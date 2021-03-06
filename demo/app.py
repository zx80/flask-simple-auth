# FlaskSimpleAuth Demo

import logging
logging.basicConfig()

from FlaskSimpleAuth import Flask, jsonify as json, VERSION
app = Flask("demo")
app.config.from_envvar("APP_CONFIG")

# database initialisation
import database
database.init_app(app)
db = database.db

# authentication hooks, which use the shared db
import auth
auth.init_app(app)

# GET /version: show running FlaskSimpleAuth version
@app.get("/version", authorize="ANY")
def get_version():
    return json(VERSION), 200

# GET /now: give current time from database
@app.get("/now", authorize="ANY")
def get_now():
    return json(db.now()[0]), 200

# GET /who: given authenticated user if available
@app.get("/who", authorize="ANY")
def get_who():
    return json(app.current_user()), 200

# register 3 blueprints to app
# stuff management by users
from stuff import stuff
app.register_blueprint(stuff)

# user management by admin (add, consult, update, delete)
from users import users
app.register_blueprint(users)

# self-care for users (register, consult, get token, change password)
from scare import scare
app.register_blueprint(scare)
