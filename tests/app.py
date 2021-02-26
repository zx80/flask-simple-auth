# test app setup

from flask import Flask
app = Flask("Test_Application")
app.config.update(AUTH_TYPE='fake')

# auth
import FlaskSimpleAuth as auth

# passwords
UHP = {}

# group management
ADMIN, WRITE, READ = 0, 1, 2
GROUPS = { 0: {"dad"}, 1: {"dad", "calvin"}, 2: {"calvin", "hobbes"} }
def is_in_group(user, group):
    return user in GROUP.get(group, {})

auth.setConfig(app, UHP.get, is_in_group)

# finalize test passwords
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
for u in UP:
    UHP[u] = auth.hash_password(UP[u])

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
