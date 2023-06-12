# FlaskSimpleAuth Demo

import uuid
import logging
logging.basicConfig()

import FlaskSimpleAuth as fsa  # type: ignore
json = fsa.jsonify
app = fsa.Flask("demo")
app.config.from_envvar("APP_CONFIG")

# database initialisation before auth so that all hooks are executed after
import database
database.init_app(app)
db = database.db

# authentication hooks, which use the shared db initialized above
import auth
auth.init_app(app)

#
# first, opened direct routes
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
    return json(app.get_user(required=False)), 200


# POST /upload (file): upload a file!
@app.post("/upload", authorize="ALL")
def post_upload(file: fsa.FileStorage):
    filename = str(uuid.uuid4()) + ".tmp"
    file.save(app.config["APP_UPLOAD_DIR"] + "/" + filename)
    return f"{file.filename} ({file.mimetype}) saved as {filename}", 201


#
# then register some blueprints
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

# demonstrate parameter typing, including JsonData "magic" type
from types_path import types
app.register_blueprint(types, url_prefix="/types")

# example multi-factor authentication
if app._fsa._token == "fsa":
    from mfa import mfa
    app.register_blueprint(mfa, url_prefix="/mfa")

# demonstrate delegated authorizations through JWT tokens
if app._fsa._token == "jwt":
    from oauth import oauth
    app.register_blueprint(oauth)
