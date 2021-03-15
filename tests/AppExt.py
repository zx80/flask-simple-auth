#
# ANOTHER TEST APP FOR FlaskSimpleAuth
#

from shared_auth import user_in_group, get_user_pass

import logging
log = logging.getLogger("app-ext")

#
# APP
#
from flask import Flask
app = Flask("Test")

# note that FSA initialization is delayed…
from FlaskSimpleAuth import FlaskSimpleAuth, ALL
fsa = FlaskSimpleAuth(app)

#
# AUTH
#
app.config.update(
    FSA_TYPE = 'fake',
    FSA_GET_USER_PASS = get_user_pass,
    FSA_USER_IN_GROUP = user_in_group
)

#
# ROUTES
#
@fsa.route("/stuff", methods=["GET"], authorize=ALL)
def get_stuff():
    return "stuff", 200

# bad route decorator used
@app.route("/bad", methods=["GET"])
def get_bad():
    return "bad", 200