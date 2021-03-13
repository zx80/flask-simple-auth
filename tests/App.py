#
# TEST APP FOR FlaskSimpleAuth
#

from typing import Dict

import logging
log = logging.getLogger("app")

#
# APP
#
from FlaskSimpleAuth import Flask, RealFlask, jsonify, ANY, ALL, NONE
app = Flask("Test")

#
# AUTH
#
# passwords
UHP: Dict[str,str] = {}

# group management
ADMIN, WRITE, READ = 0, 1, 2
GROUPS = { 0: {"dad"}, 1: {"dad", "calvin"}, 2: {"calvin", "hobbes"} }

def is_in_group(user, group):
    return user in GROUPS.get(group, [])

app.config.update(
    FSA_TYPE = 'fake',
    FSA_ALWAYS = True,
    FSA_SKIP_PATH = (r"/register",
                     r"/(add|div|mul|sub|type|params|all|mis[12]|nogo|one|infer|superid)"),
    FSA_GET_USER_PASS = UHP.get,
    FSA_USER_IN_GROUP = is_in_group
)

# force initialization so that hash_password is ok
app._fsa_initialize()

# finalize test passwords
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
for u in UP:
    UHP[u] = app.hash_password(UP[u])

#
# ROUTES
#
@app.route("/login", authorize=ALL)
def login():
    return jsonify(app.create_token(app.get_user())), 200

@app.route("/admin", authorize=ADMIN)
def admin_only():
    return "admin-only", 200

@app.route("/write", authorize=WRITE)
def write_only():
    return "write-only", 200

@app.route("/read", authorize=READ)
def read_only():
    return "read-only", 200

@app.route("/all", authorize=ANY)
def all():
    return "no-auth", 200

# change password in self-care with set_login
@app.route("/user/<user>", methods=["PATCH", "PUT"], authorize=[READ])
def patch_user_str(user, oldpass, newpass):
    login = app.get_user()
    if login != user:
        return "self care only", 403
    if not app.check_password(oldpass, UHP[login]):
        return "bad old password", 422
    # update password
    UP[login] = newpass
    UHP[login] = app.hash_password(newpass)
    return "", 204

# possibly suicidal self-care
@app.route("/user/<user>", methods=["DELETE"], authorize=[ALL])
def delete_user_str(user):
    login = app.get_user()
    if not (login == user or is_in_group(login, ADMIN)):
        return "self care or admin only", 403
    del UP[user]
    del UHP[user]
    GROUPS[READ].remove(user)
    return "", 204

# self registration with listed mandatory parameters
@app.route("/register", methods=["POST"], authorize=[ANY])
def register(user, upass):
    if user in UP:
        return "cannot register existing user", 403
    # add new user with read permission…
    UP[user] = upass
    UHP[user] = app.hash_password(upass)
    GROUPS[READ].add(user)
    return "", 201

# typed mandatory parameters
@app.route("/add/<i>", methods=["GET"], authorize=[ANY])
def get_add(i: int, a: float, b: float):
    return str(i * (a + b)), 200

# another one: j and k and mandatory
@app.route("/mul/<i>", methods=["GET"], authorize=[ANY])
def get_mul(i: int, j: int, k: int):
    return str(i * j * k), 200

# another one: i and j are optional
@app.route("/div", methods=["GET"], authorize=[ANY])
def get_div(i: int = None, j: int = None):
    if i is None or j is None:
        return "0", 200
    else:
        return str(i // j), 200

# another one: i is mandatory, j is optional
@app.route("/sub", methods=["GET"], authorize=[ANY])
def get_sub(i: int, j: int = 0):
    return str(i - j), 200

# type tests
@app.route("/type", methods=["GET"], authorize=[ANY])
def get_type(f: float = None, i: int = None, b: bool = None, s: str = None):
    if f is not None:
        return f"float {f}", 200
    elif i is not None:
        return f"int {i}", 200
    elif b is not None:
        return f"bool {b}", 200
    elif s is not None:
        return f"str {s}", 200
    else:
        return "", 200

# accept any parameters…
@app.route("/params", methods=["GET"], authorize=[ANY], allparams=True)
def get_params(**kwargs):
    return ' '.join(sorted(kwargs)), 200

# explicitly forbidden route
@app.route("/nogo", methods=["GET"], authorize=NONE)
def get_nogo():
    return "", 200

# missing authorization check with parameters
@RealFlask.route(app, "/mis1", methods=["GET"])
@app._fsa_parameters()
def get_mis1(i: int = 0):
    return "", 200

# missing authorization check without parameters
@RealFlask.route(app, "/mis2", methods=["GET"])
def get_mis2():
    return "", 200

# empty authorization
@app.route("/empty", methods=["GET"], authorize=[])
def get_mis3():
    return "", 200

# convenient route all-in-one decorator
@app.route("/one/<int:i>", methods=["GET"], authorize=[ANY])
def get_one(i: int, msg: str, punct: str = "!"):
    return f"{i}: {msg} {punct}", 200

# missing authorize on direct flask route call
@RealFlask.route(app, "/two", methods=["GET"])
def get_two():
    return "2", 200

# parameter type inference
@app.route("/infer/<id>", methods=["GET"], authorize=[ANY])
def get_infer(id: float, i = 2, s = "hi"):
    return f"{id} {i*len(s)}", 200

# try a date…
import datetime as dt
@app.route("/when", methods=["GET"], authorize=ALL)
def get_when(d: dt.date, t: dt.time = '23:34:45'):
    return f"in {d - dt.date.today()} {t}", 200

import uuid
@app.route("/superid/<uid>", methods=["GET"], authorize=ANY)
def get_superid_uid(uid: uuid.UUID):
    return f"uid = {uid}", 200
