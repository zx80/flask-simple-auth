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

# bad route decorator actually used!
@app.route("/evil", methods=["GET"])
def get_evil():
    return "evil", 200

# note that FSA initialization is delayed…
from FlaskSimpleAuth import FlaskSimpleAuth
fsa = FlaskSimpleAuth(app)

class Special(str):
    pass

#
# AUTH
#
app.config.update(
    FSA_DEBUG = True,
    FSA_AUTH = "fake",
    FSA_TOKEN_CARRIER = "cookie",
    FSA_GET_USER_PASS = get_user_pass,
    FSA_USER_IN_GROUP = user_in_group,
    FSA_CAST = { list: lambda s: s.split(" ") },
    FSA_SPECIAL_PARAMETER = { Special: lambda: "special", },
    FSA_OBJECT_PERMS = { "xyz": lambda d, i, m: False },
    FSA_TOKEN_RENEWAL = 0.25,
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
