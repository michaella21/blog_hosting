import sys
import random
import string
import json
import httplib2
from time import time

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm.exc import NoResultFound

from flask import Flask, render_template, request, redirect, url_for
from flask import flash, make_response
from flask import session as login_session

from models import Base, User, Post

sys.path.append('../')
engine = create_engine('sqlite:///metablog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


@app.route('/')
@app.route('/main')
def showMainPage():
    recent = session.query(Post).filter_by(
        publish_consent=1).order_by(Post.created).limit(10)
    tops = session.query(Post).filter_by(
        publish_consent=1).order_by(Post.likes).limit(10)
    return render_template("main.html", recent=recent, tops=tops)


@app.route('/newpost', methods=['GET', 'POST'])
def addNewPost():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        post = Post(subject=request.form['subject'],
                    user_id=login_session['user_id'],
                    content=request.form['content'],
                    created=time(),
                    # need to force type=int to avoid default unicode type
                    publish_consent=(request.form.get('consent', type=int)))

        # by default, last_modified has the same value as the created.
        post.last_modified = post.created
        post.get_short_content()

        if post.publish_consent == 1:
            post.category = request.form['category']
            post.published = post.created

        session.add(post)
        session.commit()

        flash('New post is created!')
        return redirect('/')
    else:
        return render_template("new_post.html")


@app.route('/viewpost/<int:post_id>', methods=['GET', 'POST'])
def viewPost(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    if request.method == 'POST':
        if request.form['submit'] == "Like it":
            post.likes += 1
            session.add(post)
            session.commit()
        return redirect('/')
    else:
        return render_template("view_post.html", post=post)


@app.route('/editpost/<int:post_id>', methods=['GET', 'POST'])
def editPost(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    creator = session.query(User).filter_by(id=post.user_id).one()
    if request.method == 'POST':
        post.subject = request.form['subject']
        post.content = request.form['content']
        post.publish_consent = request.form['consent']
        post.last_modified = time()
        if post.publish_consent == True:
            published_post = Published(subject=request.form['subject'],
                                       category=request.form['category'],
                                       published=time())
            published_post.short_content = post.get_short_content()
            session.add(published_post)
        session.commit()
        return redirect(url_for('viewPost', post_id=post_id))
    else:
        return render_template("edit_post.html", post=post,
                               published_post=published_post)


@app.route('/deletepost/<int:post_id>', methods=['GET', 'POST'])
def deletePost(post_id):
    post = session.query(Post).filter_by(id=post_id).one()
    published_post = session.query(Published).filter_by(
        id=post.id).one_or_none()
    creator = session.query(User).filter_by(id=post.user_id).one()
    if request.method == 'POST':
        session.delete(post)
        if published_post is not None:
            session.delete(published_post)
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
        return redirect(url_for('showMainPage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showMainPage'))

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
