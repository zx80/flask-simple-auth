# test app setup

import logging
log = logging.getLogger("app")

from flask import Flask, request, jsonify
app = Flask("Test")
app.config.update(FSA_TYPE='fake')

# auth
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

@app.route("/register", methods=["POST"])
def register():
    params = request.values if request.json is None else request.json
    if not "user" in params or not "pass" in params:
        return "", 404
    user, pswd = params["user"], params["pass"]
    # add new user…
    UP[user] = pswd
    UHP[user] = auth.hash_password(pswd)
    GROUPS[READ].add(user)
    return "", 201
