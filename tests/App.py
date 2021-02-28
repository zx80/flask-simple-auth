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
import FlaskSimpleAuth as fsa

# passwords
UHP = {}

# group management
ADMIN, WRITE, READ = 0, 1, 2
GROUPS = { 0: {"dad"}, 1: {"dad", "calvin"}, 2: {"calvin", "hobbes"} }

def is_in_group(user, group):
    return user in GROUPS.get(group, {})

log.info("initializing auth...")
fsa.setConfig(app, UHP.get, is_in_group)

# finalize test passwords
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
for u in UP:
    UHP[u] = fsa.hash_password(UP[u])


SET_LOGIN_ACTIVE = False
LOGIN = None

def set_login():
    global LOGIN
    LOGIN = None
    if not SET_LOGIN_ACTIVE or request.path in ("/register", "/all"):
        log.debug("skipping set_login")
        return
    try:
        LOGIN = fsa.get_user()
    except fsa.AuthException as e:
        return Response(e.message, e.status)

app.before_request(set_login)

#
# ROUTES
#
@app.route("/login")
@fsa.authorize(ADMIN, WRITE, READ)
def login():
    return jsonify(fsa.create_token(fsa.get_user())), 200

@app.route("/admin")
@fsa.authorize(ADMIN)
def admin_only():
    return "admin-only", 200

@app.route("/write")
@fsa.authorize(WRITE)
def write_only():
    return "write-only", 200

@app.route("/read")
@fsa.authorize(READ)
def read_only():
    return "read-only", 200

@app.route("/all")
def all():
    return "no-auth", 200

# change password in self-care with set_login
@app.route("/user/<string:user>", methods=["PATCH", "PUT"])
@fsa.authorize(READ)
@fsa.parameters("oldpass", "newpass")
def patch_user_str(user, oldpass, newpass):
    if LOGIN is None:
        return "must activate set_login", 500
    if LOGIN != user:
        return "self care only", 403
    if not fsa.check_password(oldpass, UHP[LOGIN]):
        return "bad old password", 422
    # update password
    UP[LOGIN] = newpass
    UHP[LOGIN] = fsa.hash_password(newpass)
    return "", 204

# possibly suicidal self-care
@app.route("/user/<string:user>", methods=["DELETE"])
def delete_user_str(user):
    login = fsa.get_user()
    if not (login == user or is_in_group(login, ADMIN)):
        return "self care or admin only", 403
    del UP[user]
    del UHP[user]
    return "", 204

# self registration
@app.route("/register", methods=["POST"])
@fsa.parameters("user", "upass")
def register(user, upass):
    if user in UP:
        return "cannot register existing user", 403
    # add new user with read permission…
    UP[user] = upass
    UHP[user] = fsa.hash_password(upass)
    GROUPS[READ].add(user)
    return "", 201

# typed parameters
@app.route("/add/<int:i>", methods=["GET"])
@fsa.parameters(a=float, b=float)
def get_add(i, a, b):
    return str(i * (a + b)), 200

# another one
@app.route("/mul/<int:i>", methods=["GET"])
@fsa.autoparams(True)
def get_mul(i: int, j: int, k: int):
    return str(i * j * k), 200

# another one
@app.route("/div", methods=["GET"])
@fsa.autoparams(False)
def get_div(i: int, j: int):
    if i is None or j is None:
        return "0", 200
    else:
        return str(i // j), 200
