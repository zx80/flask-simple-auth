# FlaskSimpleAuth Demo

import logging
logging.basicConfig()

import FlaskSimpleAuth as fsa  # type: ignore
json = fsa.jsonify
app = fsa.Flask("demo")
app.config.from_envvar("APP_CONFIG")

# database initialisation
import database
database.init_app(app)
db = database.db

# authentication hooks, which use the shared db initialized above
import auth
auth.init_app(app)

#
# first, direct routes
#


# GET /version: show running FlaskSimpleAuth version
@app.get("/version", authorize="ANY")
def get_version():
    return json(fsa.__version__), 200


# GET /now: show current time from database
@app.get("/now", authorize="ANY")
def get_now():
    return json(db.now()), 200


# GET /who: show authenticated user if available
@app.get("/who", authorize="ANY")
def get_who():
    return json(app.current_user()), 200

#
# then register 3 blueprints
#


# stuff management by users
from stuff import stuff
app.register_blueprint(stuff)

# user management by admin (add, consult, update, delete)
from users import users
app.register_blueprint(users)

# self-care for users (register, consult, get token, change password)
from scare import scare
app.register_blueprint(scare)
