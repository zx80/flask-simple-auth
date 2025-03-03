#
# TEST APP FOR FlaskSimpleAuth
#

import sys
from typing import Optional, Union
from Auth import user_in_group, get_user_pass
from Auth import ADMIN, WRITE, READ, GROUPS, UP, UHP

import logging
logging.basicConfig(level=logging.DEBUG)
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
    FSA_AUTH=["token", "param", "basic", "fake", "none"],
    FSA_MODE="debug2",
    FSA_LOGGING_LEVEL=logging.DEBUG,
    FSA_ALLOW_DEPRECATION=True,
)

#
# AUTH*
#
app.config.update(
    FSA_AUTH=["token", "fake", "basic", "param", "none"],
    FSA_GET_USER_PASS=get_user_pass,
    FSA_USER_IN_GROUP=user_in_group,
)

# object permissions: dad (admin) or self
def check_users_perms(login: str, val: str, _):
    return login in (val, "dad") if val in UP else None

app.add_group(ADMIN, WRITE, READ)
app.object_perms("users", check_users_perms)

@app.object_perms("fun")
def check_fun_perms(login: str, id1: int, id2: int, _):
    return id1 == id2

# add and remove a password quality fun
@app.password_quality
def check_password_quality(_: str) -> bool:
    return True

app.password_quality(None)

# configure with a blueprint
from SubApp import subapp
app.register_blueprint(subapp, url_prefix="/b1")

#
# ROUTES
#
@app.route("/login", authz=ALL)
def login():
    cur = app.current_user()
    assert cur
    return jsonify(app.create_token(app.get_user())), 200

@app.route("/admin", authz=ADMIN)
def admin_only():
    return "admin-only", 200

@app.route("/write", authz=WRITE)
def write_only():
    return "write-only", 200

@app.route("/read", authz=READ)
def read_only():
    return "read-only", 200

@app.route("/any", authz=ANY)
def any(app: CurrentApp, req: Request):
    assert app._fsa._am._get_httpd_auth(app, req) is None
    return "no-auth", 200

# change password in self-care with set_login
@app.route("/user/<user>", methods=["PATCH", "PUT"], authz=[READ])
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
@app.route("/user/<user>", methods=["DELETE"], authz=["AUTH"])
def delete_user_str(user):
    login = app.get_user()
    if not (login == user or user_in_group(login, ADMIN)):
        return "self care or admin only", 403
    del UP[user]
    del UHP[user]
    GROUPS[READ].remove(user)
    return "", 204

# self registration with listed mandatory parameters
@app.route("/register", methods=["POST"], authz=["OPEN"])
def register(user, upass):
    if user in UP:
        return "cannot register existing user", 403
    # add new user with read permission…
    UP[user] = upass
    UHP[user] = app.hash_password(upass)
    GROUPS[READ].add(user)
    return "", 201

# typed mandatory parameters
@app.route("/add/<i>", methods=["GET"], authz=["OPEN"])
def get_add(i: int, a: float, b: float):
    return str(i * (a + b)), 200

# another one: j and k and mandatory
@app.route("/mul/<i>", methods=["GET"], authz=["OPEN"])
def get_mul(i: int, j: int, k: int):
    return str(i * j * k), 200

# another one: i and j are optional
@app.route("/div", methods=["GET"], authz=["OPEN"])
def get_div(i: int = None, j: int = None):
    if i is None or j is None:
        return "0", 200
    else:
        return str(i // j), 200

# another one: i is mandatory, j is optional
@app.route("/sub", methods=["GET"], authz=["OPEN"])
def get_sub(i: int, j: int = 0):
    return str(i - j), 200

# FIXME test depends on version, simpler once >= 3.10
if sys.version_info >= (3, 10):
    IntOrNone = int | None
else:
    IntOrNone = Union[int, None]

# type tests
@app.route("/type", methods=["GET"], authz=["OPEN"])
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
@app.route("/params", methods=["GET"], authz=["OPEN"])
def get_params(**kwargs):
    return ' '.join(sorted(kwargs)), 200

# explicitly forbidden route
@app.route("/nogo", methods=["GET"], authz=NONE)
def get_nogo():
    return "", 200

import flask

# missing authorization check with parameters
@flask.Flask.route(app, "/mis1", methods=["GET"])
@app._fsa._pm._parameters("/mis1", False)
def get_mis1(i: int = 0):
    return "", 200

# missing authorization check without parameters
@flask.Flask.route(app, "/mis2", methods=["GET"])
def get_mis2():
    return "", 200

# empty authorization
@app.route("/empty", methods=["GET"], authz=[])
def get_mis3():
    return "", 200

# convenient route all-in-one decorator
@app.route("/one/<int:i>", methods=["GET"], authz=["OPEN"])
def get_one(i: int, msg: str, punct: str = "!"):
    return f"{i}: {msg} {punct}", 200

# missing authorize on direct flask route call
@flask.Flask.route(app, "/two", methods=["GET"])
def get_two():
    return "2", 200

# parameter type inference
@app.route("/infer/<id>", methods=["GET"], authz=["OPEN"])
def get_infer(id: float, i = 2, s = "hi"):
    return f"{id} {i*len(s)}", 200

# try a date…
import datetime as dt
@app.route("/when", methods=["GET"], authz="AUTH")
def get_when(d: dt.date, t: dt.time = '23:34:45'):
    return f"in {d - dt.date.today()} {t}", 200

import uuid
@app.route("/superid/<uid>", methods=["GET"], authz="OPEN")
def get_superid_uid(uid: uuid.UUID, u: uuid.UUID = None):
    return f"uid = {uid}/{u}", 200

# complex numbers as HTTP parameters should work out of the box
@app.route("/cplx", methods=["GET"], authz="OPEN")
def get_cplx(c1: complex, c2: complex = 1+1j):
    return f"{c1+c2}", 200

# unexpected types as path parameters are recast
@app.route("/bool/<b>", methods=["GET"], authz="OPEN")
def get_bool_b(b: bool):
    return str(b), 200

# again with complex
@app.route("/cplx/<c>", methods=["GET"], authz="OPEN")
def get_cplx_c(c: complex):
    return str(c + 1j), 200

# requires Python 3.9
# import zoneinfo as zi
# @app.route("/zi/<zone>", methods=["GET"], authz="OPEN")
# def get_zi_zone(zone: zi.ZoneInfo):
#     return f"{zone}", 200

# custom class
class Mail:
    def __init__(self, address):
        assert "@" in address, "email address must contain a '@'"
        self._address = address
    def __str__(self):
        return self._address

@app.route("/mail/<ad1>", methods=["GET"], authz="OPEN")
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

@app.get("/myint/<i>", authz="OPEN")
def get_myint_i(i: my_int):
    return str(i), 200

# shared initialized object
import Shared
from Shared import something
Shared.init_app(something="App")

@app.route("/something", methods=["GET"], authz="OPEN")
def get_something():
    return str(something), 200

@app.route("/path/<p>", methods=["GET"], authz="OPEN")
def get_path(p: path):
    return p, 200

@app.route("/string/<s>", methods=["GET"], authz="OPEN")
def get_string(s: string):
    return s, 200

# per-route authentication scheme
@app.route("/auth/token", methods=["GET"], authz="AUTH", authn="token")
def get_auth_token():
    return f"token auth: {app.get_user()}", 200

@app.route("/auth/basic", methods=["GET"], authz="AUTH", authn="basic")
def get_auth_basic():
    return f"basic auth: {app.get_user()}", 200

@app.route("/auth/param", methods=["GET"], authz="AUTH", authn="param")
def get_auth_param():
    return f"param auth: {app.get_user()}", 200

@app.route("/auth/fake", methods=["GET"], authz="AUTH", authn="fake")
def get_auth_fake():
    return f"fake auth: {app.get_user()}", 200

@app.route("/auth/password", methods=["GET"], authz="AUTH", authn="password")
def get_auth_password():
    return f"password auth: {app.get_user()}", 200

@app.route("/auth/ftp", methods=["GET"], authz="AUTH", authn=["fake", "token", "param"])
def get_auth_ftp():
    return f"ftp auth: {app.get_user()}", 200

@app._fsa.route("/403")
def get_403():
    return "missing authorize", 200

@app.route("/required/true", authz="OPEN")
def get_required_true(s1, s2):
    return s1 + " " + s2, 200

@app.route("/required/false", authz="OPEN")
def get_required_false(s1 = "hello", s2 = "world"):
    return s1 + " " + s2, 200

# check Flask 2.0 compatibility
@app.get("/f2/get", authz="OPEN")
def get_f2():
    return "get ok", 200

@app.post("/f2/post", authz="OPEN")
def post_f2():
    return "post ok", 200

@app.put("/f2/put", authz="OPEN")
def put_f2():
    return "put ok", 200

@app.delete("/f2/delete", authz="OPEN")
def delete_f2():
    return "delete ok", 200

@app.patch("/f2/patch", authz="OPEN")
def patch_f2():
    return "patch ok", 200

class Len:
    def __init__(self, s):
        self._len = len(s)
    def __str__(self):
        return str(self._len)

# test underscore params
@app.get("/_/<_def>", authz="OPEN")
def get___def(_def: str, _int: int, _: Len, _pass: bool = True):
    return f"{_def}/{_int}/{_}/{_pass}", 200

# per-object permissions
@app.get("/my/<login>", authz=("users", "login"))
def get_my_login(login: str):
    return f"login is {login} for {app.get_user()}", 200

# raise instead of return
@app.get("/oops", authz="OPEN")
def get_oops():
    raise fsa.ErrorResponse("Ooops!", 518)

# magic Json handling
import json as js
from FlaskSimpleAuth import JsonData
@app.get("/json", authz="OPEN")
def get_json(j: JsonData):
    return f"{type(j).__name__}: {js.dumps(j)}", 200

# magic parameters
@app.get("/request", authz="OPEN")
def get_request(req: Request, ses: Session, glo: Globals, env: Environ):
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

@app.get("/special", authz="OPEN")
def get_special(foo: Foo, bla: Bla):
    return f"{foo}-{bla}", 200

# WWW-Authenticate priority
@app.get("/perm/basic", authz="AUTH", authn="basic")
def get_perm_basic():
    return "basic", 200

@app.get("/perm/token", authz="AUTH", authn="token")
def get_perm_token():
    return "token", 200

@app.get("/perm/token-basic", authz="AUTH", authn=["token", "basic"])
def get_perm_token_basic():
    return "token-basic", 200

@app.get("/perm/basic-token", authz="AUTH", authn=["basic", "token"])
def get_perm_basic_token():
    return "basic-token", 200

# test multiple-variable object permissions
@app.get("/perm/fun/<i>/<j>", authz=("fun", "i:j"), authn="fake")
def get_perm_fun_i_j(i: int, j: int, user: CurrentUser):
    return f"{user} i==j", 200

@app.before_request
def early_return():
    if fsa.request.path.startswith("/early-return/"):
        code = int(fsa.request.path[14:])
        return "early return", code

@app.get("/early-return/<code>", authz="OPEN")
def get_early_return(code: int):
    return "should not get there", 500

@app.get("/shadow/<stuff>", authz="OPEN")
def get_shadow(stuff: str, lapp: CurrentApp, blup: str = "Yukon"):
    return f"{lapp.name}: {stuff} {blup}", 200

@app.get("/cookie/foo", authz="OPEN")
def get_cookie_foo(foo: Cookie, bla: Cookie = None, bar: Cookie = "foobla"):
    return f"cookie foo: {foo}, bla: {bla}, bar: {bar}", 200

@app.get("/headers", authz="OPEN")
def get_headers(user_agent: Header, hello: Header):
    return { "User-Agent": user_agent, "Hello": hello }, 200
