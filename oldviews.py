import sys
import random
import string
import json
import httplib2

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm.exc import NoResultFound

from flask import Flask, render_template, request, redirect, url_for
from flask import flash, make_response
from flask import session as login_session

from models import Base, Project, User

sys.path.append('../')
engine = create_engine('sqlite:///metablogs.db')
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
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    print "url sent for API access : %s" % url
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token

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
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=100&width=100' % token
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
    return "You have been logged out"


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

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash('You have successfully been logged out.')
        return redirect(url_for('showMainPage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showMainPage'))


@app.route('/')
@app.route('/top')
def showMainPage():
    blogs = session.query(Project).order_by(Project.last_modified)
    return render_template("mainPage.html", blogs=blogs)


@app.route('/catalog/new', methods=['GET', 'POST'])
def newProject():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newBlog = Project(
            title=request.form['project_name'],
            content=request.form['project_description'])
        
        session.add(newProject)
        session.commit()
        flash('New project is created!')
        return redirect('/catalog')
    else:
        return render_template("newProject.html")


@app.route('/catalog/<int:project_id>/edit', methods=['GET', 'POST'])
def editProject(project_id):
    editingProject = session.query(Project).filter_by(id=project_id).one()
    creator = getUserInfo(editingProject.user_id)
    if login_session['user_id'] != creator.id:
        flash('You do not have authorization to edit this page!')
    if request.method == 'POST':
        editingProject.name = request.form['project_name']
        editingProject.description = request.form['project_description']
        session.add(editingProject)
        session.commit()
        flash('Your project "%s" is succssfully eidited!' %
              editingProject.name)
        return redirect('/catalog')
    else:
        return render_template("editProject.html", project=editingProject)


@app.route('/catalog/<int:project_id>/delete', methods=['GET', 'POST'])
def deleteProject(project_id):
    deletingProject = session.query(Project).filter_by(id=project_id).one()
    if request.method == 'POST':
        session.delete(deletingProject)
        session.commit()
        flash('Your project is successfully deleted.')
        return redirect('/catalog')
    else:
        return render_template("deleteProject.html", project=deletingProject)


@app.route('/catalog/projects/<int:project_id>')
def showProject(project_id):
    project = session.query(Project).filter_by(id=project_id).one()
    creator = getUserInfo(project.user_id)
    if login_session['usernmae'] != creator.username:
        return render_template("projectDeatilsPublic.html",
                               project=project, creator=creator)
    else:
        return render_template("projectDetails.html",
                               project=project, creator=creator)


@app.route('/catalog/portfolio/<int:user_id>')
def showPortfolio(user_id):
    portfolio = session.query(Project).filter_by(
        user_id=user_id).order_by(Project.last_modified).all()
    return render_template("portfolio.html", portfolio=portfolio)


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
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'].one())
    return user.id


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=8000)
