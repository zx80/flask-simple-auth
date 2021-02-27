#
# TEST APP FOR FlaskSimpleAuth
#

import logging
log = logging.getLogger("app")

#
# APP
#
from flask import Flask, request, Response, jsonify
app = Flask("Test")
app.config.update(FSA_TYPE='fake')

PARAMS = None

def set_params():
    global PARAMS
    PARAMS = request.values if request.json is None else request.json

app.before_request(set_params)

#
# AUTH
#
import FlaskSimpleAuth as auth

# passwords
UHP = {}

# group management
ADMIN, WRITE, READ = 0, 1, 2
GROUPS = { 0: {"dad"}, 1: {"dad", "calvin"}, 2: {"calvin", "hobbes"} }

def is_in_group(user, group):
    return user in GROUPS.get(group, {})

log.info("initializing auth...")
auth.setConfig(app, UHP.get, is_in_group)

# finalize test passwords
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
for u in UP:
    UHP[u] = auth.hash_password(UP[u])


SET_LOGIN_ACTIVE = False
LOGIN = None

def set_login():
    if not SET_LOGIN_ACTIVE:
        log.debug("skipping set_login")
        return
    try:
        global LOGIN
        LOGIN = auth.get_user()
    except auth.AuthException as e:
        return Response(e.message, e.status)

app.before_request(set_login)

#
# ROUTES
#
@app.route("/login")
def login():
    return jsonify(auth.create_token(auth.get_user())), 200

@app.route("/admin")
@auth.authorize(ADMIN)
def admin_only():
    return "admin-only", 200

@app.route("/write")
@auth.authorize(WRITE)
def write_only():
    return "write-only", 200

@app.route("/read")
@auth.authorize(READ)
def read_only():
    return "read-only", 200

@app.route("/all")
def all():
    return "no-auth", 200

# change password in self-care with set_login
@app.route("/user/<string:user>", methods=["PATCH"])
@auth.authorize(READ)
def self_care(user):
    if LOGIN != user:
        return "self care only", 403
    if not "oldpass" in PARAMS or not "newpass" in PARAMS:
        return "missing parameters", 400  # 422?
    oldpass, newpass = PARAMS["oldpass"], PARAMS["newpass"]
    try:
        auth.check_password(LOGIN, oldpass, UHP[LOGIN])
    except auth.AuthException:
        return "bad old password", 422
    # update password
    UP[LOGIN] = newpass
    UHP[LOGIN] = auth.hash_password(newpass)
    return "", 204

# self registration
@app.route("/register", methods=["POST"])
def register():
    if not "user" in PARAMS or not "pass" in PARAMS:
        return "", 400
    user, pswd = PARAMS["user"], PARAMS["pass"]
    # add new user with read permission…
    UP[user] = pswd
    UHP[user] = auth.hash_password(pswd)
    GROUPS[READ].add(user)
    return "", 201
