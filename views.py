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
from sqlalchemy import exc

from flask import Flask, render_template, request, redirect, url_for
from flask import flash, make_response, jsonify, g
from flask import session as login_session
from flask import send_from_directory

# http://flask.pocoo.org/docs/0.12/patterns/fileuploads/
from werkzeug.utils import secure_filename

from models import Base, User, Post, Likes, Comment
from forms import NewPostForm, CommentForm

sys.path.append('../')
engine = create_engine('sqlite:///bloghost.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

UPLOAD_FOLDER = 'static/photos'
ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload(file):
    # before storing the data, forge it to the secure name
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return os.path.join(app.config['UPLOAD_FOLDER'], filename)


@app.route('/files/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


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
        Post.publish != 'no').order_by(Post.created).limit(10)
    tops = session.query(Post).filter(
        Post.publish != 'no').order_by(Post.likes).limit(10)
    return render_template("main.html", recent=recent, tops=tops)


@app.route('/post', methods=['GET', 'POST'])
def new_post():
    if 'username' not in login_session:
        return redirect('/login')
    form = NewPostForm()
    if form.validate_on_submit():
        post = Post(subject=form.subject.data,
                    user_id=login_session['user_id'],
                    content=form.content.data,
                    created=time(),
                    publish=form.publish.data)
        post.last_modified = post.created
        post.get_short_content()
        if form.image.data and allowed_file(form.image.data.filename):
            file = form.image.data
            post.attached_img = upload(file)

        session.add(post)
        session.commit()
        return redirect('/')
    print form.errors
    return render_template('post.html', form=form, action=url_for('new_post'))


@app.route('/viewpost/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    creator = session.query(User).filter_by(id=post.user_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        login_session.pop('_flashes', None)

        # creator itself cannot like its own post
        if login_session['user_id'] == creator.id:
            flash('You cannot like your own post.')
            return redirect('/')

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
        if post.publish == 'no' and creator.id != login_session['user_id']:
            flash('This post is private')
            return redirect('/')
        else:
            form = CommentForm()
            comments = session.query(Comment).filter_by(
                post_id=post_id).order_by(Comment.commented_ts).all()

            return render_template("view_post.html", post=post, form=form, comments=comments)


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
        comments = session.query(
            Comment).filter_by(post_id=post_id).order_by(
            Comment.commented_ts).all()

        return redirect(url_for('view_post', post_id=post_id))

    print form.errors
    return render_template('view_post.html', post=post, form=form)


@app.route('/editpost/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    # creator = session.query(User).filter_by(id=post.user_id).all()
    # Populate the form from the data
    form = NewPostForm(obj=post)
    if form.validate_on_submit():
        form.populate_obj(post)
        post.last_modified = time()
        post.get_short_content()
        if form.image.data and allowed_file(form.image.data.filename):
            file = form.image.data
            post.attached_img = upload(file)
        session.add(post)
        session.commit()
        return redirect(url_for('view_post', post_id=post_id))
    print form.errors
    return render_template('post.html', form=form,
                           action=url_for('edit_post', post_id=post.id))


@app.route('/deletepost/<int:post_id>', methods=['GET', 'POST'])
def delete_post(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    # creator = session.query(User).filter_by(id=post.user_id).one()
    if request.method == 'POST':
        session.delete(post)
        session.commit()
        flash('Your post is successfully deleted.')
        return redirect('/')
    else:
        return render_template("delete_post.html", post=post)


@app.route('/logout')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            #  gdisconnect()
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


def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'], created=time())
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=8000)
