#
# TEST APP FOR FlaskSimpleAuth
#

import sys
from typing import Optional, Union
from Auth import user_in_group, get_user_pass
from Auth import ADMIN, WRITE, READ, GROUPS, UP, UHP

import logging
log = logging.getLogger("app")

#
# APP
#
import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import Flask, jsonify, ANY, ALL, NONE, path, string, \
    Request, Session, Globals, Environ, CurrentUser, CurrentApp, Cookie, Header

app = Flask(
    "Test",
    debug=True,
    FSA_MODE="debug2",
    FSA_LOGGING_LEVEL=logging.DEBUG
)
app.add_group(ADMIN, WRITE, READ)

#
# AUTH
#
app.config.update(
    # FSA_AUTH = "fake",
    FSA_AUTH=["token", "fake", "basic", "param"],
    # FSA_TOKEN_CARRIER="param",
    FSA_GET_USER_PASS = get_user_pass,
    FSA_USER_IN_GROUP = user_in_group,
)


# object permissions: dad (admin) or self
def check_users_perms(login: str, val: str, mode):
    return login in (val, "dad") if val in UP else None

app.object_perms("users", check_users_perms)

from SubApp import subapp
app.register_blueprint(subapp, url_prefix="/b1")

#
# ROUTES
#
@app.route("/login", authorize=ALL)
def login():
    cur = app.current_user()
    assert cur
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

@app.route("/any", authorize=ANY)
def any(app: CurrentApp):
    assert app._fsa._get_httpd_auth() is None
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
    if not (login == user or user_in_group(login, ADMIN)):
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

# FIXME test depends on version, simpler once >= 3.10
if sys.version_info >= (3, 10):
    IntOrNone = int | None
else:
    IntOrNone = Union[int, None]

# type tests
@app.route("/type", methods=["GET"], authorize=[ANY])
def get_type(f: Optional[float] = None, i: IntOrNone = None, b: Union[bool, None] = None, s: str = None):
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
@app.route("/params", methods=["GET"], authorize=[ANY])
def get_params(**kwargs):
    return ' '.join(sorted(kwargs)), 200

# explicitly forbidden route
@app.route("/nogo", methods=["GET"], authorize=NONE)
def get_nogo():
    return "", 200

import flask

# missing authorization check with parameters
@flask.Flask.route(app, "/mis1", methods=["GET"])
@app._fsa._parameters("/mis1")
def get_mis1(i: int = 0):
    return "", 200

# missing authorization check without parameters
@flask.Flask.route(app, "/mis2", methods=["GET"])
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
@flask.Flask.route(app, "/two", methods=["GET"])
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
def get_superid_uid(uid: uuid.UUID, u: uuid.UUID = None):
    return f"uid = {uid}/{u}", 200

# complex numbers as HTTP parameters should work out of the box
@app.route("/cplx", methods=["GET"], authorize=ANY)
def get_cplx(c1: complex, c2: complex = 1+1j):
    return f"{c1+c2}", 200

# unexpected types as path parameters are recast
@app.route("/bool/<b>", methods=["GET"], authorize=ANY)
def get_bool_b(b: bool):
    return str(b), 200

# again with complex
@app.route("/cplx/<c>", methods=["GET"], authorize=ANY)
def get_cplx_c(c: complex):
    return str(c + 1j), 200

# requires Python 3.9
# import zoneinfo as zi
# @app.route("/zi/<zone>", methods=["GET"], authorize=ANY)
# def get_zi_zone(zone: zi.ZoneInfo):
#     return f"{zone}", 200

# custom class
class Mail:
    def __init__(self, address):
        assert "@" in address, "email address must contain a '@'"
        self._address = address
    def __str__(self):
        return self._address

@app.route("/mail/<ad1>", methods=["GET"], authorize=ANY)
def get_mail_address(ad1: Mail, ad2: Mail = "calvin@comics.net"):
    return f"{ad1} {ad2}", 200

# custom class with custom cast
class my_int:
    def __init__(self):
        self.val = 0
    def __str__(self):
        return f"my_int: {self.val}"
    @staticmethod
    def str_to_my_int(s):
        i = my_int()
        i.val = int(s)
        return i

app.cast(my_int, my_int.str_to_my_int)

@app.get("/myint/<i>", authorize=ANY)
def get_myint_i(i: my_int):
    return str(i), 200

# shared initialized object
import Shared
from Shared import something
Shared.init_app(something="App")

@app.route("/something", methods=["GET"], authorize=ANY)
def get_something():
    return str(something), 200

@app.route("/path/<p>", methods=["GET"], authorize=ANY)
def get_path(p: path):
    return p, 200

@app.route("/string/<s>", methods=["GET"], authorize=ANY)
def get_string(s: string):
    return s, 200

# per-route authentication scheme
@app.route("/auth/token", methods=["GET"], authorize=ALL, auth="token")
def get_auth_token():
    return f"token auth: {app.get_user()}", 200

@app.route("/auth/basic", methods=["GET"], authorize=ALL, auth="basic")
def get_auth_basic():
    return f"basic auth: {app.get_user()}", 200

@app.route("/auth/param", methods=["GET"], authorize=ALL, auth="param")
def get_auth_param():
    return f"param auth: {app.get_user()}", 200

@app.route("/auth/fake", methods=["GET"], authorize=ALL, auth="fake")
def get_auth_fake():
    return f"fake auth: {app.get_user()}", 200

@app.route("/auth/password", methods=["GET"], authorize=ALL, auth="password")
def get_auth_password():
    return f"password auth: {app.get_user()}", 200

@app.route("/auth/ftp", methods=["GET"], authorize=ALL, auth=["fake", "token", "param"])
def get_auth_ftp():
    return f"ftp auth: {app.get_user()}", 200

@app._fsa.route("/403")
def get_403():
    return "missing authorize", 200

@app.route("/required/true", authorize=ANY)
def get_required_true(s1, s2):
    return s1 + " " + s2, 200

@app.route("/required/false", authorize=ANY)
def get_required_false(s1 = "hello", s2 = "world"):
    return s1 + " " + s2, 200

# check Flask 2.0 compatibility
@app.get("/f2/get", authorize=ANY)
def get_f2():
    return "get ok", 200

@app.post("/f2/post", authorize=ANY)
def post_f2():
    return "post ok", 200

@app.put("/f2/put", authorize=ANY)
def put_f2():
    return "put ok", 200

@app.delete("/f2/delete", authorize=ANY)
def delete_f2():
    return "delete ok", 200

@app.patch("/f2/patch", authorize=ANY)
def patch_f2():
    return "patch ok", 200

class Len:
    def __init__(self, s):
        self._len = len(s)
    def __str__(self):
        return str(self._len)

# test underscore params
@app.get("/_/<_def>", authorize=ANY)
def get___def(_def: str, _int: int, _: Len, _pass: bool = True):
    return f"{_def}/{_int}/{_}/{_pass}", 200

# per-object permissions
@app.get("/my/<login>", authorize=("users", "login"))
def get_my_login(login: str):
    return f"login is {login} for {app.get_user()}", 200

# raise instead of return
@app.get("/oops", authorize=ANY)
def get_oops():
    raise fsa.ErrorResponse("Ooops!", 518)

# magic Json handling
import json as js
from FlaskSimpleAuth import JsonData
@app.get("/json", authorize=ANY)
def get_json(j: JsonData):
    return f"{type(j).__name__}: {js.dumps(j)}", 200

# magic parameters, user should be None as there is no authentication required
@app.get("/request", authorize=ANY)
def get_request(req: Request, ses: Session, glo: Globals, env: Environ, user: CurrentUser):
    return req.base_url, 200

# new magic parameters
class Foo(str):
    pass

@app.special_parameter(Foo)
def foo_parameter_value(_: str):
    return "foo"

class Bla(str):
    pass

app.special_parameter(Bla, lambda _: "BAD")
app.special_parameter(Bla, lambda _: "bla")

@app.get("/special", authorize=ANY)
def get_special(foo: Foo, bla: Bla):
    return f"{foo}-{bla}", 200

# WWW-Authenticate priority
@app.get("/perm/basic", authorize=ALL, auth="basic")
def get_perm_basic():
    return "basic", 200

@app.get("/perm/token", authorize=ALL, auth="token")
def get_perm_token():
    return "token", 200

@app.get("/perm/token-basic", authorize=ALL, auth=("token", "basic"))
def get_perm_token_basic():
    return "token-basic", 200

@app.get("/perm/basic-token", authorize=ALL, auth=("basic", "token"))
def get_perm_basic_token():
    return "basic-token", 200

@app.before_request
def early_return():
    if fsa.request.path.startswith("/early-return/"):
        code = int(fsa.request.path[14:])
        return "early return", code

@app.get("/early-return/<code>", authorize=ANY)
def get_early_return(code: int):
    return "should not get there", 500

@app.get("/shadow/<stuff>", authorize=ANY)
def get_shadow(stuff: str, lapp: CurrentApp, blup: str = "Yukon"):
    return f"{lapp.name}: {stuff} {blup}", 200

@app.get("/cookie/foo", authorize=ANY)
def get_cookie_foo(foo: Cookie):
    return f"cookie foo: {foo}", 200

@app.get("/headers", authorize=ANY)
def get_headers(user_agent: Header, hello: Header):
    return { "User-Agent": user_agent, "Hello": hello }, 200
