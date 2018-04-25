import sys
import os
import random
import string
import json
import httplib2
from time import time
from datetime import datetime

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import exc, and_

from flask import Flask, render_template, request, redirect, url_for
from flask import flash, make_response, jsonify
from flask import session as login_session
from flask import send_from_directory

# http://flask.pocoo.org/docs/0.12/patterns/fileuploads/
from werkzeug.utils import secure_filename

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from models import Base, User, Post, Blog, Likes, Comment
from forms import NewPostForm, CommentForm, BlogForm
import requests

sys.path.append('../')
engine = create_engine('sqlite:///bloghost.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
# oauth = OAuth(app)

UPLOAD_FOLDER = 'static/photos'
ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# check the file extension preventing XSS problems
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# save the attached file in the upload folder and return the forged filename
def upload(file, prefix, suffix):
    # before storing the data, forge it to the secure name
    filename = secure_filename(file.filename)
    file_body = filename.rsplit('.', 1)[0].lower()
    file_ext = '.' + filename.rsplit('.', 1)[1].lower()
    filename = prefix + '-' + file_body + '-' + suffix + file_ext
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


# retrieve the image file from the upload_folder
@app.route('/files/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Create a state token to prevent request forgery
# Store it in the session for later validation
@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


@app.route('/')
@app.route('/main')
def main_page():
    recent = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.created).limit(5)
    tops = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.likes).limit(5)

    return render_template("main.html",
                           recent=recent,
                           tops=tops,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/JSON')
@app.route('/main/JSON')
def show_main_page_JSON():
    recent = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.created).limit(5)
    tops = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.likes).limit(5)
    return jsonify(recent=[r.serialize for r in recent],
                   tops=[t.serialize for t in tops])


@app.route('/post', methods=['GET', 'POST'])
def new_post():
    # only signed user can write a new post
    if 'username' not in login_session:
        return redirect('/login')
    form = NewPostForm()
    if form.validate_on_submit():
        post = Post(subject=form.subject.data,
                    user_id=login_session['user_id'],
                    blog_id=login_session['blog_id'],
                    content=form.content.data,
                    created=time(),
                    publish=form.publish.data)
        post.last_modified = post.created
        post.get_short_content()
        if form.image.data and allowed_file(form.image.data.filename):
            file = form.image.data
            # save the file name with prefix(blog_id) and suffix(created)
            post.attached_img = upload(file,
                                       str(login_session['blog_id']),
                                       str(int(post.created)))

        session.add(post)
        session.commit()
        return redirect('/')
    print form.errors
    return render_template('post.html', form=form, action=url_for('new_post'),
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/viewpost/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    creator = session.query(User).filter_by(id=post.user_id).one()
    blog = session.query(Blog).filter_by(user_id=creator.id).one()
    comments = session.query(Comment).filter_by(
        post_id=post_id).order_by(Comment.commented_ts).all()
    if request.method == 'POST':
        login_session.pop('_flashes', None)

        # user cannot like the same post more than one time. If one tries to,
        # it raises integrity error (unique constraint failed)
        if request.form['submit'] == "Like it":
            try:
                like = Likes(user_id=login_session['user_id'],
                             post_id=post_id)
                session.add(like)
                session.flush()
            except exc.IntegrityError:
                session.rollback()
                flash("You already liked this post")
            else:
                post.likes += 1
                session.add(post)
                session.commit()
            return redirect('/')
    else:
        # private post is only open to the creator itself
        if post.publish == 'no' and creator.id != login_session.get('user_id'):
            flash('This post is private')
            return redirect('/')
        if 'username' not in login_session:
            return render_template("view_post.html", post=post,
                                   comments=comments, blog=blog,
                                   user_id=login_session.get('user_id'),
                                   username=login_session.get('username'))
        if creator.id == login_session.get('user_id'):
            return render_template("view_post.html", post=post,
                                   comments=comments, blog=blog,
                                   user_id=login_session.get('user_id'),
                                   username=login_session.get('username'))
        else:
            form = CommentForm()
            return render_template("view_post.html", post=post, form=form,
                                   comments=comments, blog=blog,
                                   user_id=login_session.get('user_id'),
                                   username=login_session.get('username'))


@app.route('/viewpost/<int:post_id>/JSON')
def view_post_JSON(post_id):
    if 'username' not in login_session:
        redirect('/login')
    post = session.query(Post).filter_by(id=post_id).one()
    # if the post is set to private, can be only shown to the creator
    if post.publish == 'no' and login_session.get('user_id') != post.user_id:
        return "You are not authorized for this contents"
    comments = session.query(Comment).filter_by(
        post_id=post_id).order_by(Comment.commented_ts).all()
    return jsonify(post=post.serialize,
                   comments=[c.serialize for c in comments])


# handle the post request for leaving comments
@app.route('/comment/<int:post_id>', methods=['GET', 'POST'])
def comment_post(post_id):
    form = CommentForm()
    post = session.query(Post).filter_by(id=post_id).one()
    if 'username' not in login_session:
        flash('You need to login first to leave a comment')
        return redirect('/login')
    if form.validate_on_submit():
        comment = Comment(post_id=post_id,
                          commented_ts=time(),
                          commenter=login_session['username'],
                          comment_body=form.comment.data)
        comment.commented_dt = datetime.utcfromtimestamp(
            comment.commented_ts).strftime('%Y-%m-%d %H:%M:%S')
        session.add(comment)
        session.commit()
        return redirect(url_for('view_post', post_id=post_id))
    print form.errors
    return render_template('view_post.html', post=post, form=form,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/editpost/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    creator = session.query(User).filter_by(id=post.user_id).one()

    # Populate the form from the data
    form = NewPostForm(obj=post)

    # only creator of the post can edit it
    if login_session['user_id'] != creator.id:
        login_session.pop('_flashes', None)
        flash('You do not have authorization to edit this post!')
        return redirect(url_for('view_post', post_id=post_id))

    if form.validate_on_submit():
        old_img = post.attached_img
        form.populate_obj(post)
        post.get_short_content()
        post.last_modified = time()
        if form.image.data and allowed_file(form.image.data.filename):
            # if there's previoused attached image
            if old_img:
                # first delete the previous file in the upload_folder
                deleting_file = os.path.join(app.config['UPLOAD_FOLDER'],
                                             old_img)
                os.remove(deleting_file)
            # then upload the new file
            file = form.image.data
            # save file with prefix(blog_id) and suffix(last_modified time)
            post.attached_img = upload(file,
                                       str(login_session['blog_id']),
                                       str(int(post.last_modified)))
        session.add(post)
        session.commit()
        return redirect(url_for('view_post', post_id=post_id))
    print form.errors
    return render_template('post.html', form=form, post=post,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'),
                           action=url_for('edit_post', post_id=post.id))


@app.route('/deletepost/<int:post_id>', methods=['GET', 'POST'])
def delete_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    creator = session.query(User).filter_by(id=post.user_id).one()
    # only creator of the post can delete it
    if login_session['user_id'] != creator.id:
        login_session.pop('_flashes', None)
        flash('You do not have authorization to delete this post!')
        return redirect(url_for('view_post', post_id=post_id))

    if request.method == 'POST':
        # if there's any attached image, also delete it from the upload folder
        if post.attached_img:
            deleting_file = os.path.join(app.config['UPLOAD_FOLDER'],
                                         post.attached_img)
            os.remove(deleting_file)

        session.delete(post)
        session.commit()
        flash('Your post is successfully deleted.')
        return redirect('/')
    else:
        return render_template("delete_post.html", post=post,
                               user_id=login_session.get('user_id'),
                               username=login_session.get('username'))


@app.route('/blog/<int:user_id>', methods=['GET', 'POST'])
def view_blog(user_id):
    posts = session.query(Post).filter_by(user_id=user_id).all()
    creator = session.query(User).filter_by(id=user_id).one()
    blog = session.query(Blog).filter_by(user_id=user_id).one()

    return render_template("view_blog.html",
                           creator=creator, posts=posts, blog=blog,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/blog/<int:user_id>/JSON')
def view_blog_JSON(user_id):
    posts = session.query(Post).filter_by(user_id=user_id).all()
    blog = session.query(Blog).filter_by(user_id=user_id).one()

    return jsonify(blog=blog.serialize, posts=[p.serialize for p in posts])


@app.route('/editblog/<int:user_id>', methods=['GET', 'POST'])
def edit_blog(user_id):
    blog = session.query(Blog).filter_by(user_id=user_id).one()
    old_img = blog.profile_img
    form = BlogForm(obj=blog)
    if form.validate_on_submit():
        blog.last_modified = time()
        form.populate_obj(blog)
        if form.image.data and allowed_file(form.image.data.filename):
            if old_img:
                # first delete the previous file in the upload_folder
                deleting_file = os.path.join(app.config['UPLOAD_FOLDER'],
                                             old_img)
                os.remove(deleting_file)
            # then upload the new file
            file = form.image.data
            # upload the file with prefix(blog_id), suffix(last_modified)
            blog.profile_img = upload(file,
                                      str(login_session['blog_id']),
                                      str(int(blog.last_modified)))

        session.add(blog)
        session.commit()
        return redirect(url_for('view_blog', user_id=user_id))
    return render_template('blog_profile.html', form=form,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/recent')
def view_recent_posts():
    recent = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.created).all()
    return render_template("recent_posts.html",
                           recent=recent,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/recent/JSON')
def view_recent_posts_JSON():
    recent = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.created).all()
    return jsonify(recent=[r.serialize for r in recent])


@app.route('/categories')
def view_categories():
    def category_filter(cat):
        return session.query(Post).filter(
            and_(Post.publish == cat, Post.publish != 'no')).order_by(
            Post.created).all()

    cats = ['review', 'food', 'politics', 'travel', 'animal', 'life', 'etc']
    cats_title = {'review': 'Book/Movie/TV Show reviews',
                  'food': 'Food/Restaurant',
                  'politics': 'Politics',
                  'travel': 'Travel',
                  'animal': 'Cute Animals',
                  'life': 'Daily Live',
                  'etc': 'Uncategorized'}
    cats_posts = {}
    for cat in cats:
        cats_posts[cat] = category_filter(cat)

    return render_template("categories_posts.html",
                           cats_title=cats_title,
                           cats_posts=cats_posts,
                           user_id=login_session.get('user_id'),
                           username=login_session.get('username'))


@app.route('/categories/JSON')
def view_categories_JSON():
    def category_filter(cat):
        return session.query(Post).filter(
            and_(Post.publish == cat, Post.publish != 'no')).order_by(
            Post.created).all()

    cats = ['review', 'food', 'politics', 'travel', 'animal', 'life', 'etc']
    cats_posts = {}
    for cat in cats:
        cats_posts[cat] = category_filter(cat)
    return jsonify(
        posts=[[r.serialize for r in cats_posts[cat]] for cat in cats])


@app.route('/categories/<category>')
def view_single_category(category):
    posts_in_category = session.query(Post).filter(
        Post.publish != 'no', Post.publish == category).order_by(
        Post.created).all()
    return render_template("single_cateory_posts.html",
                           category=category,
                           posts=posts_in_category)


@app.route('/categories/<category>/JSON')
def view_single_category_JSON(category):
    posts_in_category = session.query(Post).filter(
        Post.publish != 'no', Post.publish == category).order_by(
        Post.created).all()
    return jsonify(posts=[p.serialize for p in posts_in_category])


@app.route('/logout')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['access_token']
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        login_session.pop('username', None)
        login_session.pop('email', None)
        login_session.pop('picture', None)
        login_session.pop('user_id', None)
        login_session.pop('provider', None)

        flash('You have successfully been logged out.')
        return redirect(url_for('main_page'))
    else:
        flash("You were not logged in")
        return redirect(url_for('main_page'))


# for google login/logout
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # confirm the token that the client sends to the server matches what
    # the server sent to the client. If these don't match, no further
    # authentication occurs on the server side.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # collect the one-time code from the server
    code = request.data
    try:
        # Upgrade(exchange) the authorization code(one-time code)into a
        # credentials object

        # oauth_flow = oauth flow obj, add client's secret key info to it
        oauth_flow = flow_from_clientsecrets(
            'google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        # inpupt = one-time code, exchanges it for a credental object
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Once we have a credintials, check if there's a vaild access token in it
    # Check that the access token is valid
    access_token = credentials.access_token
    # if we append this access_token into the google api url, it verifies
    # whether it is a vaild acess token or not
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Here we create json GET requests containing url and access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # req_json = req.decode('utf8').replace("'", '"')
    # result = json.loads(req_json)
    # If there was an error in the access_token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # If there's no error, meaning that we have a WORKING access_token.
    # But verify that the access token is used for intended user (right token)
    # ID of the token in credentials object, compare with ID returned from api
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Also verify that the access token is valid for this app
    # i.e., access token id == the id that my app is trying to use
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's"), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check to see whether user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # If none of those if statements above were true, then we have a valid
    # access token and user successfully logged into my server
    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # See if user exists. If not, make a new one.
    user_id = getUserID(email=login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px; border-radius: 150px;\
     -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" %
          login_session['username'].encode('utf-8'))
    return output


# DISCONNECT - Revoke a current user's toekn and reset their login_session.
@app.route("/gdisconnect")
def gdisconnect():
    # Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token.
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':

        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # For any reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Facebook login/logout
@app.route("/fbconnect", methods=['POST'])
def fbconnect():
    # same as gconnect, for antiforgery
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data

    # Exchange short-lived client token for long-lived server-side token
    # https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
    # send my app secrets to FB to verify server identity
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token'
    url += '?grant_type=fb_exchange_token&client_id=%s' % app_id
    url += '&client_secret=%s' % app_secret
    url += '&fb_exchange_token=%s' % access_token
    print "url sent for API access : %s" % url
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s' % token
    url += '&fields=name,id,email'

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access : %s" % url
    print "API JSON result: %s" % result
    data = json.loads(result)

    # once get user info, populate my login_session
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # To logout properly, need to save the token in the login_session
    login_session['access_token'] = token

    # To retrieve the profile picture, need to make a separate API call
    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s' % token
    url += '&redirect=0&height=100&width=100'
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    print data
    login_session['picture'] = data["data"]["url"]

    # See if user exists. If not, make a new one.
    initialize_userinfo(login_session['email'])

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px; border-radius: 150px;\
     -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash('you are now logged in as %s' %
          login_session['username'].encode('utf-8'))
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    print result
    return "You have been logged out"


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None


def get_blog_id(user_id):
    try:
        blog = session.query(Blog).filter_by(user_id=user_id).one()
        return blog.id
    except NoResultFound:
        return None


def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def create_blog(login_session):
    newBlog = Blog(user_id=login_session['user_id'],
                   public_username=login_session['username'],
                   created=time())
    session.add(newBlog)
    session.commit()
    blog = session.query(Blog).filter_by(
        user_id=login_session['user_id']).one()
    return blog.id


def initialize_userinfo(email):
    # See if user exists. If not, make a new one.
    user_id = getUserID(email=login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    blog_id = get_blog_id(user_id=login_session['user_id'])
    if not blog_id:
        blog_id = create_blog(login_session)

    login_session['blog_id'] = blog_id


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=5000)
