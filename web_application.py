from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from fitness_database import Base, MuscleGroup, Exercise
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Fitness Catalog"

# Connect to Database
engine = create_engine('sqlite:///fitness.db')
Base.metadata.bind = engine
# Create Session
DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def showLogin():
    ''' Returns login.html
    Generates token and renders login
    '''
    state = ''
    for x in xrange(32):
        state += random.choice(string.ascii_uppercase + string.digits)
    login_session['state'] = state

    return render_template('login.html', STATE=state)

@app.route('/')
@app.route('/musclegroup/')
def showMuscleGroups():
    ''' Return: render muscleGroups.html
        Application Homepage
    '''

    #create state id on home page
    state = ''
    for x in xrange(32):
        state += random.choice(string.ascii_uppercase + string.digits)

    login_session['state'] = state
    muscleGroups = session.query(MuscleGroup).order_by(
                                            asc(MuscleGroup.muscle_group_name)
                                                      )
    return render_template('muscleGroups.html',
                           muscleGroups=muscleGroups,
                           STATE=state)


@app.route('/musclegroup/new/', methods=['GET', 'POST'])
def newMuscleGroup():
    '''
    : Create Muscle group
    :
    :return: redirects to show Muscle if method is
    : post if not then render new muscle group
    '''
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newMuscleGroup = MuscleGroup(muscle_group_name=request.form['name'])
        session.add(newMuscleGroup)
        flash('New Muscle Group %s Successfully Created'
              % newMuscleGroup.muscle_group_name)
        session.commit()
        return redirect(url_for('showMuscleGroups'))
    else:
        return render_template('newMuscleGroup.html')


@app.route('/musclegroup/<int:muscle_group_id>/exercises/')
def showExercise(muscle_group_id):
    '''
    :param muscle_group_id:  id of muscle group
    :return: renders detailed view of muscle group
    '''
    musclegroup = session.query(MuscleGroup).filter_by(id=muscle_group_id
                                                       ).one()
    items = session.query(Exercise).filter_by(
        muscle_group_id=muscle_group_id).all()
    return render_template('detailedView.html',
                           items=items,
                           musclegroup=musclegroup
                          )

@app.route('/musclegroup/<int:muscle_group_id>/edit/', methods=['GET', 'POST'])
def editMuscleGroup(muscle_group_id):
    '''
    :param muscle_group_id: muscle group id
    :return: if method post update muscle group and redirect to
    :        showMuscleGroup endpoint else load the edit muscle
    :         page for the specific ID
    '''
    if 'username' not in login_session:
        return redirect('/login')
    editedMuscleGroup = session.query(
        MuscleGroup).filter_by(id=muscle_group_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedMuscleGroup.muscle_group_name = request.form['name']
            flash('Muscle Group Successfully Edited %s'
                  % editedMuscleGroup.muscle_group_name)
            return redirect(url_for('showMuscleGroups'))
    else:
        return render_template('editMuscleGroup.html',
                               musclegroup=editedMuscleGroup)

@app.route('/musclegroup/<int:muscle_group_id>/delete/',
           methods=['GET', 'POST'])
def deleteMuscleGroup(muscle_group_id):
    '''
    :param muscle_group_id: muscle group id
    :return: if post delete muscle group and redirect to home page
    :        else render delete page
    '''
    if 'username' not in login_session:
        return redirect('/login')
    muscleGroupToDelete = session.query(
        MuscleGroup).filter_by(id=muscle_group_id).one()
    if request.method == 'POST':
        session.delete(muscleGroupToDelete)
        flash('%s Successfully Deleted'
              % muscleGroupToDelete.muscle_group_name)
        session.commit()
        return redirect(url_for('showMuscleGroups',
                                muscle_group_id=muscle_group_id)
                       )
    else:
        return render_template('deleteMuscleGroup.html',
                               musclegroup=muscleGroupToDelete
                              )

@app.route('/musclegroup/<int:muscle_group_id>/exercise/new/',
           methods=['GET', 'POST'])
def newExercise(muscle_group_id):
    '''
    Create new exercise
    :param muscle_group_id: muscle group id
    :return: if Post create new exercise and redirect to exercise page
    :        else load new exercise page.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    muscleGroup = session.query(MuscleGroup).filter_by(
                                                        id=muscle_group_id
                                                      ).one()
    if request.method == 'POST':
        newItem = Exercise(name=request.form['name'],
                           instructions=request.form['instructions'],
                           video_link=request.form['video_link'],
                           muscle_group=muscleGroup)
        session.add(newItem)
        session.commit()
        flash('New Exercise %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showExercise',
                                muscle_group_id=muscle_group_id
                               )
                       )
    else:
        return render_template('newExercise.html',
                               muscle_group_id=muscle_group_id)

# Edit an exercise
@app.route(
        '/musclegroup/<int:muscle_group_id>/exercise/<int:exercise_id>/edit',
        methods=['GET', 'POST']
          )
def editExercise(muscle_group_id, exercise_id):
    '''
    : Edit exercise page
    :param muscle_group_id:
    :param exercise_id:
    :return: if post update exercise and redirect to show exercise page
    :        else render editExcercise page.
    '''
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Exercise).filter_by(id=exercise_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['instructions']:
            editedItem.instructions = request.form['instructions']
        if request.form['video_link']:
            editedItem.video_link = request.form['video_link']
        session.add(editedItem)
        session.commit()
        flash('Exercise Successfully Edited')
        return redirect(url_for('showExercise', muscle_group_id=muscle_group_id))
    else:
        return render_template('editExercise.html',
                               muscle_group_id=muscle_group_id,
                               exercise_id=exercise_id,
                               item=editedItem)

# Delete an exercise
@app.route(
    '/musclegroup/<int:muscle_group_id>/exercise/<int:exercise_id>/delete',
     methods=['GET', 'POST'])
def deleteExercise(muscle_group_id, exercise_id):
    '''
    Delete an Exercise page
    :param muscle_group_id: muscle group id
    :param exercise_id: exercise id
    :return: if post exercise deleted and redirected to show exercise page.
    :        else render delete confirmation page
    '''
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Exercise).filter_by(id=exercise_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Exercise Successfully Deleted')
        return redirect(url_for('showExercise', muscle_group_id=muscle_group_id))
    else:
        return render_template('deleteExercise.html', item=itemToDelete)


# Fitness APIs
# Returns muscle group json object with exercises
@app.route('/api/musclegroup/<int:muscle_group_id>')
def muscleGroupAPI(muscle_group_id):
    ''' Params: muscle id
        Return: return specific muscle groups json object

        API endpoint to get all muscle groups exercises
    '''
    musclegroup = session.query(MuscleGroup).filter_by(id=muscle_group_id).one()

    jObj = musclegroup.serialize
    jObj['exercises'] = []

    exercises = session.query(Exercise).filter_by(
        muscle_group_id=muscle_group_id).all()

    for exercise in exercises:
        jObj['exercises'].append(exercise.serialize)

    return jsonify(jObj)

# Returns all muscle group json objects with exercises
@app.route('/api/musclegroup')
def muscleGroupsAPI():
    ''' Return: return specific muscle groups json object
        API endpoint to get all muscle groups  and exercises
    '''
    resultDict = []
    # all groups
    musclegroups = session.query(MuscleGroup).all()
    for group in musclegroups:
        jObj = group.serialize
        jObj['exercises'] = []
        exercises = session.query(Exercise).filter_by(
            muscle_group_id=group.id).all()
        for exercise in exercises:
            jObj['exercises'].append(exercise.serialize)

        resultDict.append(jObj)

    return jsonify(musclegroups=resultDict)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Returns: login response
    Get Oauth2 authorization token
    '''

    # if state token generated doesnt match respond with 401
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # save request data
    code = request.data

    # Try Create a credentials object
    try:
        flow = flow_from_clientsecrets('client_secrets.json', scope='')
        flow.redirect_uri = 'postmessage'
        credentials = flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # is token valid
    token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token='
           + token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if token has error return response 500
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    g_id = credentials.id_token['sub']
    if result['user_id'] != g_id:
        response = make_response(
            json.dumps("Token's does not match user user_id"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Does client id match apps id
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Client ID does not match app ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials');
    stored_gplus_id = login_session.get('gplus_id')
    # if stored_credentials and g_id matches the stored id
    # user is already connected
    if stored_credentials is not None and g_id == stored_gplus_id:
        response = make_response(
                            json.dumps(
                                        'Current user is already connected.'
                                      )
                                , 200)

        response.header['Content-Type'] = 'application/json'

    # Store the access token in the session
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = g_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # flash user for successful login
    login_session['username'] = data['name']
    flash("you are now logged in as %s" % login_session['username'])

    # Create successful response to trigger redirect
    login_response = make_response(json.dumps('Successful'), 200)
    login_response.headers['Content-Type'] = 'application/json'
    return login_response


# Revoke edit / delete access and logout user
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']

    # Check to see if a user is currently connected
    if access_token is None:
        response = make_response(json.dumps('User not connected!'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Revoke token
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Check response and del session data.
    # Redirect to home page
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        login_session.pop('_flashes', None)
        flash("You have successfully been logged out.", 'success')

        return redirect(url_for('showMuscleGroups'))

    else:
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']

        response = make_response(
                            json.dumps(
                                    'Problem encountered during disconnected.'
                                      )
                                 , 400)

        response.headers['Content-Type'] = 'application/json'
        login_session.pop('_flashes', None)
        flash("You have been logged out.", 'Error: ')

        return redirect(url_for('showMuscleGroups'))


def isAuthenticated():
    if 'username' not in login_session:
        print "logged in !"
        return True
    return False

if __name__ == '__main__':
    TEMPLATES_AUTO_RELOAD = True
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)