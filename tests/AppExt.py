#
# ANOTHER TEST APP FOR FlaskSimpleAuth
#

from Auth import user_in_group, get_user_pass

import logging
log = logging.getLogger("app-ext")

#
# APP
#
from flask import Flask
app = Flask("Test")

# note that FSA initialization is delayed…
from FlaskSimpleAuth import FlaskSimpleAuth
fsa = FlaskSimpleAuth(app)

#
# AUTH
#
app.config.update(
    FSA_AUTH = "fake",
    FSA_MODE = "always",
    FSA_TOKEN_CARRIER = "cookie",
    FSA_GET_USER_PASS = get_user_pass,
    FSA_USER_IN_GROUP = user_in_group
)

#
# ROUTES
#
@fsa.route("/stuff", methods=["GET"], authorize="ALL")
def get_stuff():
    return "stuff", 200

# bad route decorator used
@app.route("/bad", methods=["GET"])
def get_bad():
    return "bad", 200

from SubApp import subapp
fsa.register_blueprint(subapp, url_prefix="/b2")

# errors because authorize is not handled
# app.register_blueprint(subapp, url_prefix="/b3")

import Shared
from Shared import something
Shared.init_app(something="AppExt")

@fsa.route("/something", methods=["GET"], authorize="ALL")
def get_something():
    return str(something), 200
