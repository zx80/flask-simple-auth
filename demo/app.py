# FlaskSimpleAuth Demo

import logging
logging.basicConfig()

from FlaskSimpleAuth import Flask
app = Flask("demo")
app.config.from_envvar("APP_CONFIG")

# database initialisation
import database
database.init_app(app)
db = database.db

# authentication hooks, which use the shared db
import auth
auth.init_app(app)

# GET /now: give current time from database
@app.get("/now", authorize="ANY")
def get_now():
    return db.now()[0], 200

# register 3 blueprints to app
# stuff management by users
from stuff import stuff
app.register_blueprint(stuff)

# user management by admin (add, consult, update, delete)
from users import users
app.register_blueprint(users)

# self-care for users (register, consult, get token, change password)
from care import care
app.register_blueprint(care)
