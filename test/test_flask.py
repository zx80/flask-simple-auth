# tests with flask
#
# FIXME tests are not perfectly isolated as they should be…
#

import re
import pytest
import App
from App import app

import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import Response, ConfigError, ErrorResponse
import json

import AppExt

import logging
logging.basicConfig()
log = logging.getLogger("tests")

# app._fsa._log.setLevel(logging.DEBUG)
# app.log.setLevel(logging.DEBUG)
# log.setLevel(logging.DEBUG)
# app._fsa._initialize()

def check(code, res):
    assert res.status_code == code
    return res

def check_200(res):
    return check(200, res)

def check_403(res):
    return check(403, res)

def has_service(host="localhost", port=22):
    import socket
    try:
        tcp_ip = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_ip.settimeout(1)
        res = tcp_ip.connect_ex((host, port))
        return res == 0
    except Exception as e:
        log.info(f"connection to {(host, port)} failed: {e}")
        return False
    finally:
        tcp_ip.close()

def test_sanity():
    assert App.app is not None and fsa is not None
    assert App.app.name == "Test"
    assert app._fsa._realm == "Test"
    assert 'FSA_AUTH' in app.config
    assert "dad" in App.UHP
    assert "calvin" in App.UHP
    assert "hobbes" in App.UHP

@pytest.fixture
def client():
    with App.app.test_client() as c:
        yield c

@pytest.fixture
def client2():
    with AppExt.app.test_client() as c:
        yield c

@pytest.fixture
def client3():
    import AppFact as af
    with af.create_app(FSA_DEBUG=False, FSA_LOGGING_LEVEL=logging.DEBUG).test_client() as c:
        yield c

@pytest.fixture
def client4():
    import AppFact as af
    with af.create_app(FSA_CORS=True).test_client() as c:
        yield c

# push/pop auth
app_saved_auth = {}

def push_auth(app, auth, token = None, carrier = None, name = None):
    # assert auth in (None, "none", "fake", "basic", "param", "password", "token", "http-token")
    assert token in (None, "fsa", "jwt")
    assert carrier in (None , "bearer", "param", "cookie", "header")
    app_saved_auth.update(a = app._auth, t = app._token, c = app._carrier, n = app._name)
    app._auth = [auth] if isinstance(auth, str) else auth
    app._token, app._carrier, app._name = token, carrier, name

def pop_auth(app):
    d = app_saved_auth
    app._auth, app._token, app._carrier, app._name = d["a"], d["t"], d["c"], d["n"]
    d.clear()

def auth_header_basic(user: str):
    from requests.auth import _basic_auth_str as basic_auth
    return {"Authorization": basic_auth(user, App.UP[user])}

def auth_header_token(user: str):
    return {"Authorization": "Bearer " + app.create_token(user)}

# test all auth variants on GET
def all_auth(client, user, pswd, check, *args, **kwargs):
    # fake login
    push_auth(app._fsa, "fake", "fsa", "param", "auth")
    token_fake = json.loads(client.get("login", data={"LOGIN": user}).data)
    check(client.get(*args, **kwargs, data={"LOGIN": user}))
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "param", "auth")
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    pop_auth(app._fsa)
    # user-pass param
    push_auth(app._fsa, ["token", "param"], "fsa", "param", "auth")
    USERPASS = { "USER": user, "PASS": pswd }
    token_param = json.loads(client.get("login", data=USERPASS).data)
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    pop_auth(app._fsa)
    push_auth(app._fsa, ["token", "password"], "fsa", "param", "auth")
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    pop_auth(app._fsa)
    # user-pass basic
    push_auth(app._fsa, ["token", "basic"], "fsa", "param", "auth")
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth(user, pswd)}
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    pop_auth(app._fsa)
    push_auth(app._fsa, ["token", "password"], "fsa", "param", "auth")
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    pop_auth(app._fsa)
    # token only
    push_auth(app._fsa, "token", "fsa", "param", "auth")
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "bearer", "Bearer")
    bearer = lambda t: {"Authorization": "Bearer " + t}
    check(client.get(*args, **kwargs, headers=bearer(token_fake)))
    check(client.get(*args, **kwargs, headers=bearer(token_param)))
    check(client.get(*args, **kwargs, headers=bearer(token_basic)))
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "bearer", "Youpi")
    youpi = lambda t: {"Authorization": "Youpi " + t}
    check(client.get(*args, **kwargs, headers=youpi(token_fake)))
    check(client.get(*args, **kwargs, headers=youpi(token_param)))
    check(client.get(*args, **kwargs, headers=youpi(token_basic)))
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "cookie", "auth")
    client.set_cookie("localhost", "auth", token_fake)
    check(client.get(*args, **kwargs))
    client.cookie_jar.clear()
    client.set_cookie("localhost", "auth", token_param)
    check(client.get(*args, **kwargs))
    client.cookie_jar.clear()
    client.set_cookie("localhost", "auth", token_basic)
    check(client.get(*args, **kwargs))
    pop_auth(app._fsa)

def test_early_return(client):
    res = check(418, client.get("/early-return/418"))
    assert b"early return" in res.data
    res = check(200, client.get("/early-return/200"))
    assert b"early return" in res.data

def test_perms(client):
    check(200, client.get("/any"))  # open route
    check(401, client.get("/login"))  # login without login
    check(404, client.get("/"))  # empty path
    # admin only
    check(401, client.get("/admin"))
    log.debug(f"App.user_in_group: {App.user_in_group}")
    log.debug(f"app._fsa._user_in_group: {app._fsa._user_in_group}")
    assert App.user_in_group("dad", App.ADMIN)
    assert app._fsa._user_in_group("dad", App.ADMIN)
    all_auth(client, "dad", App.UP["dad"], check_200, "/admin")
    assert not App.user_in_group("calvin", App.ADMIN)
    all_auth(client, "calvin", App.UP["calvin"], check_403, "/admin")
    assert not App.user_in_group("hobbes", App.ADMIN)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/admin")
    assert hasattr(app._fsa._cache, "clear")
    app.clear_caches()
    # write only
    check(401, client.get("/write"))
    assert app._fsa._user_in_group("dad", App.WRITE)
    all_auth(client, "dad", App.UP["dad"], check_200, "/write")
    assert app._fsa._user_in_group("calvin", App.WRITE)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/write")
    assert not App.user_in_group("hobbes", App.WRITE)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/write")
    # read only
    check(401, client.get("/read"))
    assert not app._fsa._user_in_group("dad", App.READ)
    all_auth(client, "dad", App.UP["dad"], check_403, "/read")
    assert app._fsa._user_in_group("calvin", App.READ)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/read")
    assert App.user_in_group("hobbes", App.READ)
    all_auth(client, "hobbes", App.UP["hobbes"], check_200, "/read")

def test_whatever(client):
    check(404, client.get("/whatever"))
    check(404, client.post("/whatever"))
    check(404, client.put("/whatever"))
    check(404, client.patch("/whatever"))
    check(404, client.delete("/whatever"))
    push_auth(app._fsa, "fake")
    check(404, client.get("/whatever", data={"LOGIN": "dad"}))
    check(404, client.post("/whatever", data={"LOGIN": "dad"}))
    check(404, client.put("/whatever", data={"LOGIN": "dad"}))
    check(404, client.patch("/whatever", data={"LOGIN": "dad"}))
    check(404, client.delete("/whatever", data={"LOGIN": "dad"}))
    pop_auth(app._fsa)

def test_register(client):
    # missing params
    check(400, client.post("/register", data={"user":"calvin"}))
    check(400, client.post("/register", data={"upass":"calvin-pass"}))
    # existing user
    check(403, client.post("/register", data={"user":"calvin", "upass":"calvin-pass"}))
    # new user
    check(201, client.post("/register", data={"user":"susie", "upass":"derkins"}))
    assert App.UP["susie"] == "derkins"
    all_auth(client, "susie", App.UP["susie"], check_403, "/admin")
    all_auth(client, "susie", App.UP["susie"], check_403, "/write")
    all_auth(client, "susie", App.UP["susie"], check_200, "/read")
    # clean-up
    push_auth(app._fsa, "fake")
    check(204, client.delete("/user/susie", data={"LOGIN":"susie"}))
    assert "susie" not in App.UP and "susie" not in App.UHP
    pop_auth(app._fsa)

def test_fsa_token():
    tsave, hsave = app._fsa._token, app._fsa._algo
    app._fsa._token, app._fsa._algo = "fsa", "blake2s"
    app._fsa._issuer = "self"
    foo_token = app.create_token("foo")
    assert foo_token.startswith("Test/self:foo:")
    assert app._fsa._get_any_token_auth(foo_token) == "foo"
    app._fsa._issuer = None
    calvin_token = app.create_token("calvin")
    assert calvin_token[:12] == "Test:calvin:"
    assert app._fsa._get_any_token_auth(calvin_token) == "calvin"
    # malformed token
    try:
        user = app._fsa._get_any_token_auth("not an FSA token")
        assert False, "expecting a malformed error"
    except fsa.ErrorResponse as e:
        assert "invalid fsa token" in str(e)
    # bad timestamp format
    try:
        user = app._fsa._get_any_token_auth("R:U:demain:signature")
        assert False, "expecting a bad timestamp format"
    except fsa.ErrorResponse as e:
        assert "unexpected timestamp format" in e.message
    try:
        user = app._fsa._get_any_token_auth("Test:calvin:20201500000000:signature")
        assert False, "expecting a bad timestamp format"
    except fsa.ErrorResponse as e:
        assert "unexpected limit" in e.message
    # force expiration
    grace = app._fsa._grace
    app._fsa._grace = -1000000
    try:
        user = app._fsa._get_any_token_auth(calvin_token)
        assert False, "token must have expired"
    except fsa.ErrorResponse as e:
        assert "expired auth token" in e.message
    # again after clear cache, so the expiration is detected at fsa level
    app.clear_caches()
    try:
        user = app._fsa._get_any_token_auth(calvin_token)
        assert False, "token must have expired"
    except fsa.ErrorResponse as e:
        assert "expired fsa auth token" in e.message
    # cleanup
    app._fsa._grace = grace
    app._fsa._token, app._fsa._algo = tsave, hsave
    hobbes_token = app.create_token("hobbes")
    grace, app._fsa._grace = app._fsa._grace, -100
    try:
        user = app._fsa._get_any_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except fsa.ErrorResponse as e:
        assert e.status == 401
    app._fsa._grace = grace

RSA_TEST_PUB_KEY = """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN2AI/mvUWfUSh7KIAsLgwyqtuCTlw5D
6Be7GAeKFhmp7+Xf3LCGOPrfqzjILxXrUUn4tnpCudL0+6jQiLFZZ5ECAwEAAQ==
-----END PUBLIC KEY-----
"""

RSA_TEST_PRIV_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAN2AI/mvUWfUSh7KIAsLgwyqtuCTlw5D6Be7GAeKFhmp7+Xf3LCG
OPrfqzjILxXrUUn4tnpCudL0+6jQiLFZZ5ECAwEAAQJAGJkYZawQkEVFDfJIaLGY
lhmHQZ1iUxU7exct7fhpx+OgdojEDiIjN1S6cGBfbw0EFoN/dSPFGsnLjw37Tkch
gQIhAPQ9L+9Cpgnk3uUbXXIU52OF7WiQ51gdT8SnNLuNs+sZAiEA6CqmINKb09yr
qOGXfKeoA08jgWJ0atXVZEf5SE+rZzkCIQC35U4vRy5/ap1NQfJ1EDo83D0qK1iV
JtTFy+PPh909GQIhAMokyDzv42nWS0hiE6ofuDQZZcqz1LVotcH4wN3rMExRAiAd
4Id4VP45+rGweeuzFycgt0MjB/m82leJla77vNdV7Q==
-----END RSA PRIVATE KEY-----
"""

def test_jwt_token():
    tsave, hsave, app._fsa._token, app._fsa._algo = app._fsa._token, app._fsa._algo, "jwt", "HS256"
    Ksave, ksave = app._fsa._secret, app._fsa._sign
    # hmac signature scheme
    app._fsa._issuer = "self"
    moe_token = app.create_token("moe")
    assert "." in moe_token and len(moe_token.split(".")) == 3
    user = app._fsa._get_any_token_auth(moe_token)
    assert user == "moe"
    # again for caching test
    user = app._fsa._get_any_token_auth(moe_token)
    assert user == "moe"
    app._fsa._issuer = None
    # expired token
    delay, grace = app._fsa._delay, app._fsa._grace
    app._fsa._delay, app._fsa._grace = -1, 0
    susie_token = app.create_token("susie")
    assert len(susie_token.split(".")) == 3
    try:
        user = app._fsa._get_any_token_auth(susie_token)
        assert False, "expired token should fail"
    except fsa.ErrorResponse as e:
        assert "expired jwt auth token" in e.message
    finally:
        app._fsa._delay, app._fsa._grace = delay, grace
    # pubkey stuff
    app._fsa._algo, app._fsa._secret, app._fsa._sign = \
        "RS256", RSA_TEST_PUB_KEY, RSA_TEST_PRIV_KEY
    mum_token = app.create_token("mum")
    pieces = mum_token.split(".")
    assert len(pieces) == 3
    user = app._fsa._get_any_token_auth(mum_token)
    assert user == "mum"
    # bad pubkey token
    try:
        bad_token = f"{pieces[0]}.{pieces[2]}.{pieces[1]}"
        user = app._fsa._get_any_token_auth(bad_token)
        assert False, "bad token should fail"
    except fsa.ErrorResponse as e:
        assert "invalid jwt token" in e.message
    # cleanup
    app._fsa._token, app._fsa._algo = tsave, hsave
    app._fsa._secret, app._fsa._sign = Ksave, ksave

def test_invalid_token():
    # bad token
    susie_token = app.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = app._fsa._get_any_token_auth(susie_token)
        assert False, "token should be invalid"
    except fsa.ErrorResponse as e:
        assert e.status == 401
    # wrong token
    realm, app._fsa._realm = app._fsa._realm, "elsewhere"
    moe_token = app.create_token("moe")
    app._fsa._realm = realm
    try:
        user = app._fsa._get_any_token_auth(moe_token)
        assert False, "token should be invalid"
    except fsa.ErrorResponse as e:
        assert e.status == 401

def test_password_check(client):
    fsa = app._fsa
    # standard password
    fsa._init_password_manager()
    ref = app.hash_password("hello")
    assert app.check_password("hello", ref)
    assert not app.check_password("bad-pass", ref)
    # password alternate hook
    assert fsa._password_check is None
    def test_check_pass(user, pwd):
        if user == "calvin" and pwd == "hobbes":
            return True
        elif pwd == "magic":
            return True
        elif pwd == "none":
            return False
        elif pwd == "Error":
             raise ErrorResponse("test_check_pass error", 400)
        else:
             raise Exception("oops!")
    fsa._password_check = test_check_pass
    assert fsa._check_password("calvin", "hobbes") == "calvin"
    assert fsa._check_password("susie", "magic") == "susie"
    assert fsa._check_password("moe", "magic") == "moe"
    try:
        fsa._check_password("boo", "none")
        assert False, "should have raised an error"
    except ErrorResponse as e:
        assert True, "none password was rejected"
    try:
        fsa._check_password("dad", "Error")
        assert False, "should raise an error"
    except ErrorResponse as e:
        assert "test_check_pass error" in str(e)
    try:
        fsa._check_password("baa", "whatever")
        assert False, "should raise an Exception"
    except ErrorResponse as e:
        assert "no such user" in str(e)
    saved = fsa._get_user_pass
    fsa.get_user_pass(None)
    try:
        fsa._check_password("calvin", "Oops!")
        assert False, "should raise an error"
    except ErrorResponse as e:
        assert "invalid user/password" in str(e)
    fsa.get_user_pass(saved)
    fsa.password_check(None)
    # password, through requests
    push_auth(fsa, ["password"])
    res = check(401, client.get("/read", data={"USER": "dad", "PASS": "bad-dad-password"}))
    assert b"invalid password for" in res.data
    res = check(401, client.get("/read", data={"USER": "dad"}))
    assert b"missing password parameter" in res.data
    pop_auth(fsa)
    # basic, through requests
    push_auth(fsa, ["basic"])
    res = check(401, client.get("/read", headers={"Authorization": "Basic !!!"}))
    assert b"decoding error on authorization" in res.data
    pop_auth(fsa)
    # try plaintext
    pm = fsa._pm
    fsa._pm = None
    app.config.update(FSA_PASSWORD_SCHEME = "plaintext")
    fsa._init_password_manager()
    assert app.hash_password("hello") == "hello"
    fsa._pm = pm

def test_password_quality():
    fsa = app._fsa
    # password len
    assert fsa._password_len == 0
    assert app.hash_password("") is not None
    assert app.hash_password("c") is not None
    assert app.hash_password("cy") is not None
    fsa._password_len = 1
    try:
        app.hash_password("")
        assert False, "len must be rejected"
    except ErrorResponse as e:
        assert "too short" in str(e)
    assert app.hash_password("c") is not None
    assert app.hash_password("cy") is not None
    fsa._password_len = 2
    assert app.hash_password("cy") is not None
    # password re, eg password must contain a lc and uc letter
    assert len(fsa._password_re) == 0
    fsa._password_re = [
        re.compile(r"[a-z]").search,
        re.compile(r"[A-Z]").search,
    ]
    assert app.hash_password("Cy") is not None
    try:
        app.hash_password("CY")
        assert False, "must detect missing lc letter"
    except ErrorResponse as e:
        assert "a-z" in str(e)
    try:
        app.hash_password("cy")
        assert False, "must detect missing uc letter"
    except ErrorResponse as e:
        assert "A-Z" in str(e)
    # password quality return
    assert fsa._password_quality is None
    def password_quality_checker(pwd):
        if pwd == "G0od!":
            return True
        elif pwd == "B@d":
            return False
        else:
            raise Exception(f"password quality checker is not happy about {pwd}")
    fsa._password_quality = password_quality_checker
    assert app.hash_password("G0od!") is not None
    try:
        app.hash_password("B@d")
        assert False, "password should be rejected"
    except ErrorResponse as e:
        assert True, "password was rejected as expected"
    # password quality exception
    try:
        app.hash_password("@ny-Password!")
        assert False, "password should be rejected"
    except ErrorResponse as e:
        assert "not happy" in str(e)
    # reset password checking rules
    fsa._password_len = 0
    fsa._password_re = []
    fsa.password_quality(None)

def test_authorize():
    assert app._fsa._user_in_group("dad", App.ADMIN)
    assert not app._fsa._user_in_group("hobbes", App.ADMIN)
    @app._fsa._group_authz("stuff", App.ADMIN)
    def stuff():
        return Response("", 200)
    app._fsa._local.user = "dad"
    res = stuff()
    assert res.status_code == 200
    app._fsa._local.user = "hobbes"
    res = stuff()
    assert res.status_code == 403
    try:
        @app._fsa._group_authz("stuff", fsa.ALL, fsa.ANY)
        def foo():
            return "foo", 200
        assert False, "cannot mix ALL & ANY in authorize"
    except ConfigError as e:
        assert True, "mix is forbidden"

def test_self_care(client):
    push_auth(app._fsa, "fake")
    check(401, client.patch("/user/calvin"))
    check(403, client.patch("/user/calvin", data={"LOGIN":"dad"}))
    who, npass, opass = "calvin", "new-calvin-password", App.UP["calvin"]
    check(204, client.patch(f"/user/{who}", data={"oldpass":opass, "newpass":npass, "LOGIN":who}))
    assert App.UP[who] == npass
    check(204, client.patch(f"/user/{who}", data={"oldpass":npass, "newpass":opass, "LOGIN":who}))
    assert App.UP[who] == opass
    check(201, client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check(204, client.delete("user/rosalyn", data={"LOGIN":"rosalyn"}))  # self
    check(201, client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check(204, client.delete("user/rosalyn", data={"LOGIN":"dad"}))  # admin
    pop_auth(app._fsa)

def test_typed_params(client):
    res = check(200, client.get("/add/2", data={"a":"2.0", "b":"4.0"}))
    assert float(res.data) == 12.0
    # unused params are ignored
    app._fsa._reject_param = False
    res = check(200, client.get("/mul/2", data={"j":"3", "k":"4", "unused":"x"}))
    assert int(res.data) == 24
    res = check(200, client.get("/mul/2", json={"j":5, "k":"4", "unused":"y"}))
    assert int(res.data) == 40
    # unused params are rejected
    app._fsa._reject_param = True
    res = check(400, client.get("/mul/2", data={"j":"3", "k":"4", "unused":"x"}))
    res = check(400, client.get("/mul/2", json={"j":5, "k":"4", "unused":"y"}))
    # type errors
    check(400, client.get("/mul/1", data={"j":"3"}))
    check(400, client.get("/mul/1", data={"k":"4"}))
    check(400, client.get("/mul/2", data={"j":"three", "k":"four"}))
    check(400, client.get("/mul/2", json={"j":"three", "k":"four"}))
    # optional
    res = check(200, client.get("/div", data={"i":"10", "j":"3"}))
    assert int(res.data) == 3
    res = check(200, client.get("/div", json={"i":100, "j":"4"}))
    assert int(res.data) == 25
    res = check(200, client.get("/div", data={"i":"10"}))
    assert int(res.data) == 0
    res = check(200, client.get("/sub", data={"i":"42", "j":"20"}))
    assert int(res.data) == 22
    check(400, client.get("/sub", data={"j":"42"}))
    res = check(200, client.get("/sub", data={"i":"42"}))
    assert int(res.data) == 42
    res = check(200, client.get("/request"))
    assert res.data.endswith(b"/request")
    res = check(200, client.get("/special"))
    assert res.data == b"foo-bla"

def test_types(client):
    res = check(200, client.get("/type", data={"f": "1.0"}))
    assert res.data == b"float 1.0"
    res = check(200, client.get("/type", json={"f": "2.0"}))
    assert res.data == b"float 2.0"
    res = check(200, client.get("/type", json={"f": 2.0}))
    assert res.data == b"float 2.0"
    res = check(200, client.get("/type", data={"i": "0b11"}))
    assert res.data == b"int 3"
    res = check(200, client.get("/type", data={"i": "0x11"}))
    assert res.data == b"int 17"
    res = check(200, client.get("/type", json={"i": "0x11"}))
    assert res.data == b"int 17"
    res = check(200, client.get("/type", json={"i": 0x11}))
    assert res.data == b"int 17"
    # note: 011 is not accepted as octal
    res = check(200, client.get("/type", data={"i": "0o11"}))
    assert res.data == b"int 9"
    res = check(200, client.get("/type", data={"i": "11"}))
    assert res.data == b"int 11"
    res = check(200, client.get("/type", json={"i": "11"}))
    assert res.data == b"int 11"
    res = check(200, client.get("/type", json={"i": 11}))
    assert res.data == b"int 11"
    res = check(200, client.get("/type", data={"b": "0"}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"b": ""}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"b": "False"}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"b": "fALSE"}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"b": "F"}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"b": "1"}))
    assert res.data == b"bool True"
    res = check(200, client.get("/type", data={"b": "foofoo"}))
    assert res.data == b"bool True"
    res = check(200, client.get("/type", data={"b": "True"}))
    assert res.data == b"bool True"
    res = check(200, client.get("/type", json={"b": "True"}))
    assert res.data == b"bool True"
    res = check(200, client.get("/type", json={"b": True}))
    assert res.data == b"bool True"
    res = check(200, client.get("/type", json={"b": False}))
    assert res.data == b"bool False"
    res = check(200, client.get("/type", data={"s": "Hello World!"}))
    assert res.data == b"str Hello World!"
    res = check(200, client.get("/type", json={"s": "Hello World?"}))
    assert res.data == b"str Hello World?"

def test_params(client):
    res = check(200, client.get("/params", data={"a":1, "b":2, "c":3}))
    assert res.data == b"a b c"
    res = check(200, client.get("/required/true", data={"s1": "su", "s2": "sie"}))
    assert res.data == b"su sie"
    check(400, client.get("/required/true", data={"s2": "sie"}))
    check(400, client.get("/required/true", data={"s1": "su"}))
    res = check(200, client.get("/required/false", data={"s1": "su", "s2": "sie"}))
    assert res.data == b"su sie"
    res = check(200, client.get("/required/false"))
    assert res.data == b"hello world"
    res = check(200, client.get("/required/false", data={"s2": "sie"}))
    assert res.data == b"hello sie"
    res = check(200, client.get("/required/false", data={"s1": "su"}))
    assert res.data == b"su world"

def test_missing(client):
    check(403, client.get("/mis1"))
    check(403, client.get("/mis2"))
    check(403, client.get("/empty", data={"LOGIN": "dad"}))

def test_nogo(client):
    check(403, client.get("/nogo"))

def test_route(client):
    res = check(200, client.get("/one/42", data={"msg":"hello"}))
    assert res.data == b"42: hello !"
    res = check(200, client.get("/one/42", data={"msg":"hello", "punct":"?"}))
    assert res.data == b"42: hello ?"
    check(400, client.get("/one/42"))   # missing "msg"
    check(404, client.get("/one/bad", data={"msg":"hi"}))  # bad "i" type
    check(403, client.get("/two", data={"LOGIN":"calvin"}))
    check(518, client.get("/oops", data={"LOGIN":"calvin"}))

def test_infer(client):
    res = check(200, client.get("/infer/1.000"))
    assert res.data == b"1.0 4"
    res = check(200, client.get("/infer/2.000", data={"i":"2", "s":"hello"}))
    assert res.data == b"2.0 10"

def test_when(client):
    res = check(200, client.get("/when", data={"d": "1970-03-20", "LOGIN": "calvin"}))
    assert b"days" in res.data
    check(400, client.get("/when", data={"d": "not a date", "LOGIN": "calvin"}))
    check(400, client.get("/when", data={"d": "2005-04-21", "t": "not a time", "LOGIN": "calvin"}))

def test_uuid(client):
    u1 = "12345678-1234-1234-1234-1234567890ab"
    u2 = "23456789-1234-1234-1234-1234567890ab"
    res = check(200, client.get(f"/superid/{u1}"))
    check(404, client.get("/superid/not-a-valid-uuid"))
    res = check(200, client.get(f"/superid/{u2}", data={"u": u1}))
    check(400, client.get(f"/superid/{u1}", data={"u": "invalid uuid"}))

def test_complex(client):
    res = check(200, client.get("/cplx", data={"c1": "-1-1j"}))
    assert res.data == b"0j"
    res = check(200, client.get("/cplx/-1j"))
    assert res.data == b"0j"
    check(400, client.get("/cplx/zero"))

def test_bool(client):
    res = check(200, client.get("/bool/1"))
    assert res.data == b"True"
    res = check(200, client.get("/bool/f"))
    assert res.data == b"False"
    res = check(200, client.get("/bool/0"))
    assert res.data == b"False"
    res = check(200, client.get("/bool/hello"))
    assert res.data == b"True"
    check(404, client.get("/bool/"))

def test_custom(client):
    s, h, m = "susie@comics.net", "hobbes@comics.net", "moe@comics.net"
    res = check(200, client.get(f"/mail/{s}"))
    assert b"susie" in res.data and b"calvin" in res.data
    res = check(200, client.get(f"/mail/{h}", data={"ad2": m}))
    assert b"hobbes" in res.data and b"moe" in res.data
    check(400, client.get(f"/mail/bad-email-address"))
    check(400, client.get(f"/mail/{m}", data={"ad2": "bad-email-address"}))
    res = check(200, client.get("/myint/5432"))
    assert b"my_int: 5432" in res.data

def test_appext(client2):
    # FIXME should be 500
    check(200, client2.get("/evil"))
    check(403, client2.get("/bad"))
    check(403, client2.get("/bad", data={"LOGIN": "dad"}))
    check(401, client2.get("/stuff"))
    res = check(200, client2.get("/stuff", data={"LOGIN": "dad"}))
    assert "auth=" in res.headers["Set-Cookie"]
    # the auth cookie is kept automatically, it seems…
    check(200, client2.get("/stuff"))
    check(403, client2.get("/bad"))
    client2.cookie_jar.clear()
    check(401, client2.get("/stuff"))
    check(403, client2.get("/bad"))

def test_blueprint(client):
    check(401, client.get("/b1/words/foo"))
    res = check(200, client.get("/b1/words/foo", data={"LOGIN": "dad"}))
    assert res.data == b"foo"
    res = check(200, client.get("/b1/words/bla", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bla_bla"
    check(403, client.get("/b1/blue", data={"LOGIN": "dad"}))

def test_blueprint_2(client2):
    check(401, client2.get("/b2/words/foo"))
    res = check(200, client2.get("/b2/words/foo", data={"LOGIN": "dad"}))
    assert res.data == b"foo"
    res = check(200, client2.get("/b2/words/bla", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bla_bla"
    check(403, client2.get("/b2/blue", data={"LOGIN": "dad"}))

def test_appfact(client3):
    check(401, client3.get("/add", data={"i": "7", "j": "2"}))
    res = check(200, client3.get("/add", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"9"
    res = check(200, client3.get("/sub", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"5"
    res = check(200, client3.get("/mul", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"14"
    res = check(200, client3.get("/div", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"3"
    res = check(200, client3.get("/div", data={"i": "0xf", "j": "0b10", "LOGIN": "dad"}))
    assert res.data == b"7"
    check(400, client3.get("/add", data={"i": "sept", "j": "deux", "LOGIN": "dad"}))
    check(400, client3.get("/add", data={"i": "7", "LOGIN": "dad"}))
    # blueprint
    check(404, client3.get("/b/word/fun"))
    res = check(200, client3.get("/b/words/fun", data={"LOGIN": "dad"}))
    assert res.data == b"fun"
    res = check(200, client3.get("/b/words/bin", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bin_bin"
    check(403, client3.get("/b/blue", data={"LOGIN": "dad"}))

import Shared

def test_something_1(client):
    Shared.init_app(something="HELLO")
    res = check(200, client.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"HELLO"
    res = check(200, client.get("/b1/something", data={"LOGIN": "dad"}))
    assert res.data == b"HELLO"

def test_something_2(client2):
    Shared.init_app(something="WORLD")
    res = check(200, client2.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"WORLD"
    res = check(200, client2.get("/b2/something", data={"LOGIN": "dad"}))
    assert res.data == b"WORLD"

def test_something_3(client3):
    Shared.init_app(something="CALVIN")
    res = check(200, client3.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"CALVIN"
    res = check(200, client3.get("/b/something", data={"LOGIN": "dad"}))
    assert res.data == b"CALVIN"

def test_401_redirect():
    import AppFact as af
    app = af.create_app(FSA_401_REDIRECT="/login-page", FSA_LOCAL="process")
    with app.test_client() as client:
        res = check(307, client.get("/something"))
        assert "/login-page" in res.location
        app._fsa._url_name = "URL"
        res = check(307, client.get("/something"))
        assert "/login-page" in res.location and "URL" in res.location and "something" in res.location
        res = check(200, client.get("/something", data={"LOGIN": "dad"}))

def test_path(client):
    res = check(200, client.get("/path/foo"))
    assert res.data == b"foo"
    res = check(200, client.get("/path/foo/bla"))
    assert res.data == b"foo/bla"

def test_string(client):
    res = check(200, client.get("/string/foo"))
    assert res.data == b"foo"


def test_www_authenticate(client):
    push_auth(app._fsa, "param")
    res = check(401, client.get("/admin"))
    pop_auth(app._fsa)
    push_auth(app._fsa, "basic")
    res = check(401, client.get("/admin"))
    log.debug(f"res auth = {res.www_authenticate.keys()}")
    assert res.www_authenticate.get("__auth_type__", None) == "basic"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "password")
    res = check(401, client.get("/admin"))
    assert res.www_authenticate.get("__auth_type__", None) == "basic"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "bearer", "Hello")
    res = check(401, client.get("/admin"))
    assert res.www_authenticate.get("__auth_type__", None) == "hello"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)

import AppHttpAuth as aha

@pytest.fixture
def app_basic():
    with aha.create_app_basic().test_client() as c:
        yield c

@pytest.fixture
def app_digest():
    with aha.create_app_digest(SECRET_KEY="top secret").test_client() as c:
        yield c

def test_http_basic(app_basic):
    check(401, app_basic.get("/basic"))
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth("calvin", "hobbes")}
    res = check(200, app_basic.get("/basic", headers=BASIC))
    assert res.data == b"calvin"

def test_http_digest(app_digest):
    check(401, app_digest.get("/digest"))
    # FIXME how to generate a digest authenticated request with werkzeug is unclear
    # from requests.auth import HTTPDigestAuth as Digest
    # AUTH = Digest("calvin", "hobbes")
    # res = check(200, app_digest.get("/digest", auth=AUTH))
    # assert res.data == b"calvin"

def test_http_token():
    app = aha.create_app_token()
    with app.test_client() as client:
        # http-token default bearer configuration
        check(401, client.get("/token"))
        calvin_token = app.create_token("calvin")
        log.debug(f"token: {calvin_token}")
        TOKEN = {"Authorization": f"Bearer {calvin_token}"}
        res = check(200, client.get("/token", headers=TOKEN))
        assert res.data == b"calvin"
        # check header with http auth
        push_auth(app._fsa, "http-token", "fsa", "header", "HiHiHi")
        app._fsa._http_auth.header = "HiHiHi"
        res = check(200, client.get("/token", headers={"HiHiHi": calvin_token}))
        assert res.data == b"calvin"
        app._fsa._http_auth.header = None
        pop_auth(app._fsa)
        # check header token fallback
        push_auth(app._fsa, "token", "fsa", "header", "HoHoHo")
        res = check(200, client.get("/token", headers={"HoHoHo": calvin_token}))
        assert res.data == b"calvin"
        pop_auth(app._fsa)

def test_per_route(client):
    # data for 4 various authentication schemes
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth("calvin", App.UP["calvin"])}
    PARAM = {"USER": "calvin", "PASS": App.UP["calvin"]}
    FAKE = {"LOGIN": "calvin"}
    token = app.create_token("calvin")
    TOKEN = {"Authorization": f"Bearer {token}"}
    # basic
    log.debug("trying: basic")
    check(200, client.get("/auth/basic", headers=BASIC))
    check(401, client.get("/auth/basic", headers=TOKEN))
    check(401, client.get("/auth/basic", data=PARAM))
    check(401, client.get("/auth/basic", json=PARAM))
    check(401, client.get("/auth/basic", data=FAKE))
    check(401, client.get("/auth/basic", json=FAKE))
    # param
    check(200, client.get("/auth/param", data=PARAM))
    check(200, client.get("/auth/param", json=PARAM))
    check(401, client.get("/auth/param", headers=BASIC))
    check(401, client.get("/auth/param", headers=TOKEN))
    check(401, client.get("/auth/param", data=FAKE))
    check(401, client.get("/auth/param", json=FAKE))
    # password
    check(200, client.get("/auth/password", headers=BASIC))
    check(200, client.get("/auth/password", data=PARAM))
    check(200, client.get("/auth/password", json=PARAM))
    check(401, client.get("/auth/password", headers=TOKEN))
    check(401, client.get("/auth/password", data=FAKE))
    check(401, client.get("/auth/password", json=FAKE))
    # token
    check(200, client.get("/auth/token", headers=TOKEN))
    check(401, client.get("/auth/token", data=PARAM))
    check(401, client.get("/auth/token", json=PARAM))
    check(401, client.get("/auth/token", headers=BASIC))
    check(401, client.get("/auth/token", data=FAKE))
    check(401, client.get("/auth/token", json=FAKE))
    # fake
    check(200, client.get("/auth/fake", data=FAKE))
    check(200, client.get("/auth/fake", json=FAKE))
    check(401, client.get("/auth/fake", headers=TOKEN))
    check(401, client.get("/auth/fake", data=PARAM))
    check(401, client.get("/auth/fake", json=PARAM))
    check(401, client.get("/auth/fake", headers=BASIC))
    # fake, token, param
    check(200, client.get("/auth/ftp", data=FAKE))
    check(200, client.get("/auth/ftp", json=FAKE))
    check(200, client.get("/auth/ftp", headers=TOKEN))
    check(200, client.get("/auth/ftp", data=PARAM))
    check(200, client.get("/auth/ftp", json=PARAM))
    check(401, client.get("/auth/ftp", headers=BASIC))

def test_bad_app():
    from AppBad import create_app
    # working versions, we basically test that there is no exception
    app = create_app(FSA_AUTH="basic", FSA_LOCAL="werkzeug")
    app = create_app(FSA_AUTH=["token", "basic"])
    app = create_app(auth="fake")
    app = create_app(auth=["token", "fake"])
    # trigger default header name
    app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="header", FSA_TOKEN_SECRET="too short")
    # cover jwt initialization path
    app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt")
    app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="HS256")
    app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="none")
    app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="RSA")
    app = create_app(FSA_AUTH="http-token", FSA_TOKEN_CARRIER="header", FSA_TOKEN_NAME="Foo")
    app = None
    # bad scheme
    try:
        app = create_app(FSA_AUTH="bad")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH=["fake", "basic", "bad"])
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(auth="bad")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(auth=["basic", "token", "bad"])
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # bad token type
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="bad")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # FIXME, None is ok?
    # try:
    #     app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE=None)
    #    # assert False, "bad app creation must fail"
    # except ConfigError as e:
    #     assert True, "ok, bad app creation has failed"
    # bad token carrier
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bad")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER=None)
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "requires a carrier" in str(e), "ok, bad app creation has failed"
    # bad token name
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bearer", FSA_TOKEN_NAME=None)
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "requires a name" in str(e), "ok, bad app creation has failed"
    # bad jwt talgorithm
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="bad")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # bad local
    try:
        app = create_app(FSA_LOCAL="oops!")
        assert False, "bad app creation must fail"
    except ConfigError as e:
        assert "FSA_LOCAL" in str(e)

class PK():
    def __init__(self, kind):
        self.kind = kind

def test_typeof():
    import inspect
    P = inspect.Parameter
    assert fsa._typeof(PK(P.VAR_KEYWORD)) == dict
    assert fsa._typeof(PK(P.VAR_POSITIONAL)) == list

def test_f2(client):
    res = check(200, client.get("/f2/get"))
    assert res.data == b'get ok'
    res = check(200, client.post("/f2/post"))
    assert res.data == b'post ok'
    res = check(200, client.put("/f2/put"))
    assert res.data == b'put ok'
    res = check(200, client.delete("/f2/delete"))
    assert res.data == b'delete ok'
    res = check(200, client.patch("/f2/patch"))
    assert res.data == b'patch ok'

def test_underscore(client):
    check(400, client.get("/_/foo"))
    res = check(200, client.get("/_/foo", data={"int": 2, "_": "hello"}))
    assert res.data == b"foo/2/5/True"
    res = check(200, client.get("/_/bla", data={"int": 4, "_": "world!", "pass": False}))
    assert res.data == b"bla/4/6/False"

def test_no_cors(client3):
    check(401, client3.get("/add", data={"i": "7", "j": "2"}))
    res = check(200, client3.get("/add", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"9"
    res = check(500, client3.options("/add", data={"LOGIN": "dad"}))

def test_no_cors(client4):
    check(401, client4.get("/add", data={"i": "7", "j": "2"}))
    res = check(200, client4.get("/add", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"9"
    res = check(200, client4.options("/add", data={"LOGIN": "dad"}))

# test a bad get_user_pass implementation
@pytest.fixture
def bad2():
    import AppBad as ab
    with ab.create_badapp_2().test_client() as c:
        yield c

def test_bad_2(bad2):
    check(200, bad2.get("/any"))
    check(401, bad2.get("/all"))
    res = check(500, bad2.get("/all", data={"USER": "calvin", "PASS": "hobbes"}))
    assert b"internal error in get_user_pass" == res.data

# test a bad user_in_group implementation
@pytest.fixture
def bad3():
    import AppBad as ab
    with ab.create_badapp_3().test_client() as c:
        yield c

def test_bad_3(bad3):
    check(200, bad3.get("/any"))
    check(200, bad3.get("/all", data={"LOGIN": "calvin"}))
    res = check(500, bad3.get("/fail", data={"LOGIN": "calvin"}))
    assert b"internal error in user_in_group" == res.data

# test a bad route function
@pytest.fixture
def bad4():
    import AppBad as ab
    with ab.create_badapp_4().test_client() as c:
        yield c

def test_bad_4(bad4):
    check(200, bad4.get("/ok"))
    res = check(500, bad4.get("/any"))
    assert b"internal error caught at no authorization on /any" == res.data
    check(404, bad4.get("/no-such-route"))


def test_bads():
    import AppBad as ab
    try:
        app = ab.create_badapp_5()
        assert False, "mandatory parameter with default should fail"
    except ConfigError as e:
        assert "default" in str(e)
    try:
        app = ab.create_badapp_6()
        assert False, "missing path parameter should fail"
    except ConfigError as e:
        assert "missing" in str(e)
    try:
        app = ab.create_badapp_7()
        assert False, "inconsistent path parameter types should fail"
    except ConfigError as e:
        assert "bad" in str(e)
    try:
        app = ab.create_badapp_8()
        assert False, "unknown path parameter converter should fail"
    except ConfigError as e:
        assert "unknown" in str(e)

# per-object perms
def test_object_perms(client):
    check(401, client.get("/my/calvin", data={"LOGIN": None}))
    # dad is an admin, can access all users
    check(200, client.get("/my/calvin", data={"LOGIN": "dad"}))
    check(200, client.get("/my/hobbes", data={"LOGIN": "dad"}))
    check(200, client.get("/my/dad", data={"LOGIN": "dad"}))
    # other users can only access themselves
    check(403, client.get("/my/calvin", data={"LOGIN": "hobbes"}))
    check(403, client.get("/my/hobbes", data={"LOGIN": "calvin"}))
    check(403, client.get("/my/dad", data={"LOGIN": "calvin"}))
    check(200, client.get("/my/calvin", data={"LOGIN": "calvin"}))
    check(200, client.get("/my/hobbes", data={"LOGIN": "hobbes"}))
    # no-such-user
    check(404, client.get("/my/no-such-user", data={"LOGIN": "calvin"}))

def test_object_perms_errors():
    import AppFact as af
    app = af.create_app(FSA_AUTH="fake")
    @app.object_perms("known")
    def is_okay(u: str, v: str, m: str):
        log.debug(f"is_okay({u}, {v}, {m})")
        if v == "fsa":
            raise fsa.ErrorResponse("oops-1", 518)
        elif v == "ex":
            raise Exception("oops-2")
        elif v == "float":
            return 3.15159
        else:
            return True
    # triggers an overwrite warning
    app.object_perms("known", is_okay)
    # declaration time errors
    try:
        @app.get("/bad-perm-1", authorize=tuple())
        def get_bad_perm_1(uid: int):
            return "should not get there", 200
        assert False, "should detect too short tuple"
    except ConfigError as e:
        assert "3 data" in str(e)
    try:
        @app.get("/bad-perm-2/<uid>", authorize=("unknown",))
        def get_bad_perm_2_uid(uid: int):
            return "should not get there", 200
        assert False, "should detect unregistered permission domain"
    except ConfigError as e:
        assert "missing object permission" in str(e)
    try:
        @app.get("/bad-perm-3", authorize=("known", 3))
        def get_bad_perm_3(uid: int):
            return "should not get there", 200
        assert False, "should detect bad variable name"
    except ConfigError as e:
        assert "unexpected identifier name type" in str(e)
    try:
        @app.get("/bad-perm-4/<uid>", authorize=("known", "uid", 3.14159))
        def get_bad_perm_4_uid(uid: int):
            return "should not get there", 200
        assert False, "should detect bad mode type"
    except ConfigError as e:
        assert "unexpected mode type" in str(e)
    try:
        @app.get("/bad-perm-5", authorize=("known", "uid"))
        def get_bad_perm_3(oid: int):
            return "should not get there", 200
        assert False, "should detect missing variable"
    except ConfigError as e:
        assert "missing function parameter uid" in str(e)
    try:
        @app.get("/bad-perm-6", authorize=("known", "uid"))
        def get_bad_perm_3():
            return "should not get there", 200
        assert False, "should detect missing variable"
    except ConfigError as e:
        assert "permissions require some parameters" in str(e)
    # run time errors
    @app.get("/oops/<err>", authorize=("known", "err"))
    def get_oops_err(err: str):
        return "should not get there", 500
    c = app.test_client()
    res = c.get("/oops/fsa", data={"LOGIN": "calvin"})
    assert res.status_code == 518 and b"oops-1" in res.data
    res = c.get("/oops/ex", data={"LOGIN": "calvin"})
    assert res.status_code == 500 and b"internal error in permission check" in res.data
    res = c.get("/oops/float", data={"LOGIN": "calvin"})
    assert res.status_code == 500 and b"internal error with permission check" in res.data

def test_authorize_errors():
    import AppFact as af
    app = af.create_app()
    try:
        @app.get("/bad-authorize", authorize=[3.14159])
        def get_bad_authorize():
            return "should not get there", 200
        assert False, "should detect bad authorize type"
    except ConfigError as e:
        assert "unexpected authorization" in str(e)
    try:
        @app.get("/bad-mix-1", authorize=["ANY", "ALL"])
        def get_bad_mix_1():
            return "should not get there", 200
        assert False, "should detect ANY/ALL mix"
    except ConfigError as e:
        assert "ANY/ALL" in str(e)
    try:
        @app.get("/bad-mix-2", authorize=["ANY", "OTHER"])
        def get_bad_mix_2():
            return "should not get there", 200
        assert False, "should detect ANY/other mix"
    except ConfigError as e:
        assert "other" in str(e)
    try:
        @app.get("/bad-mix-3", authorize=["ANY", ("foo", "id")])
        def get_bad_mix_2():
            return "should not get there", 200
        assert False, "should detect ANY/other mix"
    except ConfigError as e:
        assert "object" in str(e)
    try:
        app.add_group("foo", "bla")
        @app.get("/bad-group", authorize="no-such-group")
        def get_bad_group():
            return "should not get there", 200
        assert False, "should detect unregistered group"
    except ConfigError as e:
        assert "no-such-group" in str(e)
    try:
        app.add_scope("foo", "bla")
        app._fsa._token = "jwt"
        app._fsa._issuer = "calvin"
        @app.get("/bad-scope", authorize="no-such-scope", auth="oauth")
        def get_bad_scope():
            return "should not get there", 200
        assert False, "should detect unregistered scope"
    except ConfigError as e:
        assert "no-such-scope" in str(e)

def test_group_errors():
    import AppFact as af
    def bad_uig(login, group):
       if group == "ex":
           raise fsa.ErrorResponse("exception in user_in_group", 518)
       elif group == "float":
           return 3.14159
       else:
           return True
    app = af.create_app(FSA_AUTH="fake", FSA_USER_IN_GROUP=bad_uig)
    @app.get("/ex", authorize="ex")
    def get_ex():
        return "should not get here", 200
    @app.get("/float", authorize="float")
    def get_float():
        return "should not get here", 200
    c = app.test_client()
    res = c.get("/ex", data={"LOGIN": "calvin"})
    assert res.status_code == 518 and b"exception in user_in_group" in res.data
    res = c.get("/float", data={"LOGIN": "calvin"})
    assert res.status_code == 500 and b"internal error with user_in_group" in res.data

def test_scope_errors():
    import AppFact as af
    try:
        app = af.create_app(FSA_AUTH="oauth", FSA_TOKEN_TYPE="fsa")
        assert False, "should raise an exception"
    except ConfigError as e:
        assert "oauth" in str(e) and "JWT" in str(e)
    try:
        app = af.create_app(FSA_AUTH="oauth", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ISSUER=None)
        assert False, "should raise an exception"
    except ConfigError as e:
        assert "oauth" in str(e) and "ISSUER" in str(e)
    try:
        app = af.create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="fsa", FSA_TOKEN_ISSUER="god")
        @app.get("/foo/bla", authorize=["read"], auth=["oauth"])
        def get_foo_bla():
            return "", 200
        assert False, "should be rejected"
    except ConfigError as e:
        assert "JWT" in str(e)

# run some checks on AppFact, repeat to exercise caching
def run_some_checks(c, n=10):
    assert n >= 1
    for i in range(n):
        check(401, c.get("/add"))
        check(400, c.get("/add", data={"LOGIN": "calvin"}))
        check(403, c.get("/admin", data={"LOGIN": "calvin"}))
        check(200, c.get("/admin", data={"LOGIN": "dad"}))
        res = check(200, c.get("/add", data={"LOGIN": "calvin", "i": 1234, "j": 4321}))
        assert b"5555" in res.data
        res = check(200, c.get("/add", data={"LOGIN": "dad", "i": 123, "j": 321}))
        assert b"444" in res.data
        res = check(200, c.get("/self/dad", data={"LOGIN": "dad"}))
        assert b"hello: dad" in res.data
        res = check(200, c.get("/self/calvin", data={"LOGIN": "calvin"}))
        assert b"hello: calvin" in res.data
        check(403, c.get("/self/calvin", data={"LOGIN": "dad"}))
        check(403, c.get("/self/dad", data={"LOGIN": "calvin"}))
    res = check(200, c.get("/hits", data={"LOGIN": "dad"}))
    size, hits = json.loads(res.data)
    log.info(f"cache: {size} {hits}")
    if n > 5:  # hmmm…
        assert hits > (n-4) / n

@pytest.mark.skipif(not has_service(port=11211), reason="no local memcached service available for testing")
def test_memcached_cache(client):
    import AppFact as af
    for prefix in ["mmcap.", None]:
        with af.create_app(
            FSA_CACHE="memcached", FSA_CACHE_PREFIX=prefix,
            FSA_CACHE_OPTS={"server": "localhost:11211"}).test_client() as c:
            run_some_checks(c)

@pytest.mark.skipif(not has_service(port=6379), reason="no local redis service available for testing")
def test_redis_cache():
    import AppFact as af
    for prefix in ["redap.", None]:
        with af.create_app(
            FSA_CACHE="redis", FSA_CACHE_PREFIX=prefix,
            FSA_CACHE_OPTS={"host": "localhost", "port": 6379}).test_client() as c:
            run_some_checks(c)

def test_caches():
    import AppFact as af
    for cache in ["ttl", "lru", "lfu", "mru", "fifo", "rr", "dict"]:
        for prefix in [cache + ".", None]:
            log.debug(f"testing cache type {cache}")
            with af.create_app(FSA_CACHE=cache, FSA_CACHE_PREFIX=prefix).test_client() as c:
                run_some_checks(c)

def test_no_such_cache():
    import AppFact as af
    try:
        af.create_app(FSA_CACHE="no-such-cache")
        assert False, "create app should fail"
    except ConfigError as e:
        assert "unexpected FSA_CACHE" in e.args[0]

def test_warnings_and_errors():
    def bad_gup_1(user: str):
        raise fsa.ErrorResponse("bad_gup_1", 518)
    def bad_gup_2(user: str):
        return 3.14159
    import AppFact as af
    app = af.create_app(
        FSA_SUCH_DIRECTIVE="no-such-directive",
        FSA_AUTH=["basic", "token"],
        FSA_TOKEN_TYPE="fsa",
        FSA_TOKEN_CARRIER="param",
        FSA_TOKEN_SIGN="signature-not-used-for-fsa-tokens",
        FSA_FAKE_LOGIN="not-used-if-no-fake",
        FSA_PARAM_USER="not-used-if-no-param",
        FSA_PARAM_PASS="not-used-if-no-param",
        FSA_PASSWORD_LEN=10,
        FSA_PASSWORD_RE=[r"[0-9]"],
        FSA_GET_USER_PASS=bad_gup_1,
    )
    app._fsa.initialize()
    # password exceptions
    try:
        app.hash_password("short1")
        assert False, "should be too short"
    except fsa.ErrorResponse as e:
        assert e.status == 400 and "too short" in e.message
    try:
        app.hash_password("long-enough-but-missing-a-number")
        assert False, "should not match re"
    except fsa.ErrorResponse as e:
        assert e.status == 400 and "must match" in e.message
    try:
        app._fsa._check_password("calvin", "hobbes")
        assert False, "should not get through"
    except fsa.ErrorResponse as e:
        assert e.status == 518 and "bad" in e.message
    # unused length warning
    app = af.create_app(
        FSA_TOKEN_TYPE="jwt",
        FSA_TOKEN_ISSUER="calvin",
        FSA_TOKEN_LENGTH=8,  # no used if jwt
        FSA_GET_USER_PASS=bad_gup_2,
    )
    app._fsa.initialize()
    try:
        app._fsa._check_password("calvin", "hobbes")
        assert False, "should not get through"
    except fsa.ErrorResponse as e:
        assert e.status == 500 and "internal error with get_user_pass" in e.message
    # overwrite warning
    @app.cast("foo")
    def cast_foo(s: str):
        return s
    assert app._fsa._casts["foo"] == cast_foo
    app.cast("foo", lambda x: cast_foo(x))
    assert app._fsa._casts["foo"] != cast_foo
    s = "Hello World!"
    assert app._fsa._casts["foo"](s) == cast_foo(s)
    # OAuth2 warnings
    app = af.create_app(FSA_TOKEN_SCOPE=True)
    # type errors
    try:
        app = af.create_app(FSA_CAST="not a dict")
        assert False, "should not get through"
    except ConfigError as e:
        assert "FSA_CAST must be a dict" in str(e)
    try:
        app = af.create_app(FSA_OBJECT_PERMS="should be a dict")
        assert False, "should not get through"
    except ConfigError as e:
        assert "FSA_OBJECT_PERMS must be a dict" in str(e)
    try:
        app = af.create_app(FSA_SPECIAL_PARAMETER="not a dict")
        assert False, "should not get through"
    except ConfigError as e:
        assert "FSA_SPECIAL_PARAMETER must be a dict" in str(e)

def test_jsondata(client):
    # simple types, anything but strings
    res = client.get("/json", data={"j": "null"})
    assert res.status_code == 200 and res.data == b"NoneType: null"
    res = client.get("/json", json={"j": "null"})
    assert res.status_code == 200 and res.data == b"NoneType: null"
    res = client.get("/json", json={"j": None})
    assert res.status_code == 200 and res.data == b"NoneType: null"
    res = client.get("/json", data={"j": "5432"})
    assert res.status_code == 200 and res.data == b"int: 5432"
    res = client.get("/json", json={"j": "9876"})
    assert res.status_code == 200 and res.data == b"int: 9876"
    res = client.get("/json", json={"j": 1234})
    assert res.status_code == 200 and res.data == b"int: 1234"
    res = client.get("/json", data={"j": "false"})
    assert res.status_code == 200 and res.data == b"bool: false"
    res = client.get("/json", json={"j": "true"})
    assert res.status_code == 200 and res.data == b"bool: true"
    res = client.get("/json", json={"j": True})
    assert res.status_code == 200 and res.data == b"bool: true"
    res = client.get("/json", data={"j": "54.3200"})
    assert res.status_code == 200 and res.data == b"float: 54.32"
    res = client.get("/json", json={"j": "32.10"})
    assert res.status_code == 200 and res.data == b"float: 32.1"
    res = client.get("/json", json={"j": 1.0000})
    assert res.status_code == 200 and res.data == b"float: 1.0"
    # note: complex is not json serializable
    # list
    res = client.get("/json", data={"j": "[1, 2]"})
    assert res.status_code == 200 and res.data == b"list: [1, 2]"
    res = client.get("/json", json={"j": "[3, 4]"})
    assert res.status_code == 200 and res.data == b"list: [3, 4]"
    res = client.get("/json", json={"j": [4, 5]})
    assert res.status_code == 200 and res.data == b"list: [4, 5]"
    # dict
    res = client.get("/json", data={"j": '{"n":1}'})
    assert res.status_code == 200 and res.data == b'dict: {"n": 1}'
    res = client.get("/json", json={"j": '{"m":2}'})
    assert res.status_code == 200 and res.data == b'dict: {"m": 2}'
    res = client.get("/json", json={"j": {"p": 3}})
    assert res.status_code == 200 and res.data == b'dict: {"p": 3}'
    # mixed types
    res = client.get("/json", json={"j": [False, True, [0x3, 14.000], {"q": 4}]})
    assert res.status_code == 200 and res.data == b'list: [false, true, [3, 14.0], {"q": 4}]'
    res = client.get("/json", json={"j": {"a": {"b": {"c": 3}}}})
    assert res.status_code == 200 and res.data == b'dict: {"a": {"b": {"c": 3}}}'

def test_www_authenticate_priority(client):
    # save current status
    fsa = app._fsa
    token, carrier, name = fsa._token, fsa._carrier, fsa._name
    fsa._token, fsa._carrier, fsa._name = "fsa", "bearer", "Bearer"
    BASIC = auth_header_basic("calvin")
    TOKEN = auth_header_token("calvin")
    # /perm/basic only basic
    res = check(401, client.get("/perm/basic"))
    assert "WWW-Authenticate" in res.headers
    assert "Basic" in res.headers["WWW-Authenticate"]
    res = check(200, client.get("/perm/basic", headers=BASIC))
    res = check(401, client.get("/perm/basic", headers=TOKEN))
    # /perm/token only token
    res = check(401, client.get("/perm/token"))
    assert "WWW-Authenticate" in res.headers
    assert "Bearer" in res.headers["WWW-Authenticate"]
    res = check(401, client.get("/perm/token", headers=BASIC))
    res = check(200, client.get("/perm/token", headers=TOKEN))
    # /perm/basic-token both ok
    res = check(401, client.get("/perm/basic-token"))
    assert "WWW-Authenticate" in res.headers
    assert "Basic" in res.headers["WWW-Authenticate"]
    res = check(200, client.get("/perm/basic-token", headers=BASIC))
    res = check(200, client.get("/perm/basic-token", headers=TOKEN))
    # /perm/token-basic both ok
    res = check(401, client.get("/perm/token-basic"))
    assert "WWW-Authenticate" in res.headers
    assert "Bearer" in res.headers["WWW-Authenticate"]
    res = check(200, client.get("/perm/token-basic", headers=BASIC))
    res = check(200, client.get("/perm/token-basic", headers=TOKEN))
    # test with other name
    fsa._name = "Foo"
    res = check(401, client.get("/perm/token"))
    assert "WWW-Authenticate" in res.headers
    assert "Foo" in res.headers["WWW-Authenticate"]
    res = check(401, client.get("/perm/token-basic"))
    assert "WWW-Authenticate" in res.headers
    assert "Foo" in res.headers["WWW-Authenticate"]
    # restore
    fsa._token, fsa._carrier, fsa._name = token, carrier, name


def test_jwt_authorization():
    import AppFact as af
    app = af.create_app(FSA_TOKEN_TYPE="jwt", FSA_REALM="comics", FSA_TOKEN_ISSUER="god")
    # oauth in list auth
    @app.get("/some/stuff", authorize=["read"], auth=["oauth"])
    def get_some_stuff():
        return "", 200
    # config errors
    try:
        @app.get("/some/path", authorize=["read", "write"], auth=["oauth", "basic"])
        def get_some_path():
            return "", 200
        assert False, "route should be rejected"
    except fsa.ConfigError as e:
        assert "mixed" in str(e)
    app._fsa._issuer = None
    try:
        @app.patch("/any/stuff", authorize=["write"], auth="oauth")
        def patch_any_stuff():
            return "", 204
        assert False, "route should be rejected"
    except fsa.ConfigError as e:
        assert "ISSUER" in str(e)
    app._fsa._issuer = "god"
    # usage errors
    a = app._fsa
    rosalyn_token = a._get_jwt_token(a._realm, "god", "rosalyn", 10.0, a._secret, scope=["character"])
    rosalyn_auth=("Authorization", f"Bearer {rosalyn_token}")
    moe_token = a._get_jwt_token(a._realm, "god", "moe", 10.0, a._secret, scope=["sidekick"])
    moe_auth=("Authorization", f"Bearer {moe_token}")
    client = app.test_client()
    check(401, client.get("/perm/jwt-authz"))
    check(200, client.get("/perm/jwt-authz", headers=[rosalyn_auth]))
    check(403, client.get("/perm/jwt-authz", headers=[moe_auth]))

def test_error_response():
    import AppFact as af
    app = af.create_app()
    # set error_response hook with the decorator
    @app.error_response
    def oops(m: str, c: int):
        return Response(f"OOPS: {m}", c, content_type="text/plain")
    # override with the function
    app.error_response(oops)
    @app.get("/oops", authorize="ANY")
    def get_oops():
        raise ErrorResponse("oops!", 499)
    client = app.test_client()
    res = check(499, client.get("/oops"))
    assert b"OOPS: oops!" == res.data
    # again, with FSA_ERROR_RESPONSE "plain"
    app = af.create_app(FSA_ERROR_RESPONSE="plain")
    @app.get("/aaps", authorize="ANY")
    def get_aaps():
        raise ErrorResponse("aaps!", 499)
    client = app.test_client()
    res = check(499, client.get("/aaps"))
    assert b"aaps!" == res.data
    assert res.headers["Content-Type"] == "text/plain"
    # again, with FSA_ERROR_RESPONSE "json"
    app = af.create_app(FSA_ERROR_RESPONSE="json")
    @app.get("/iips", authorize="ANY")
    def get_iips():
        raise ErrorResponse("iips!", 499)
    client = app.test_client()
    res = check(499, client.get("/iips"))
    assert res.headers["Content-Type"] == "text/json"
    assert b'"iips!"' == res.data
    # again, with FSA_ERROR_RESPONSE "json:*"
    app = af.create_app(FSA_ERROR_RESPONSE="json:BLA")
    @app.get("/uups", authorize="ANY")
    def get_uups():
        raise ErrorResponse("uups!", 499)
    client = app.test_client()
    res = check(499, client.get("/uups"))
    assert res.headers["Content-Type"] == "text/json"
    assert b'{"BLA": "uups!"}' == res.data
    # again, with FSA_ERROR_RESPONSE callable
    app = af.create_app(FSA_ERROR_RESPONSE=oops)
    @app.get("/eeps", authorize="ANY")
    def get_uups():
        raise ErrorResponse("eeps!", 499)
    client = app.test_client()
    res = check(499, client.get("/eeps"))
    assert res.headers["Content-Type"] == "text/plain"
    assert b'OOPS: eeps!' == res.data
    # again, with FSA_ERROR_RESPONSE wrong type
    try:
        app = af.create_app(FSA_ERROR_RESPONSE=True)
        app._fsa.initialize()
        assert False, "should have raised an exception"
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, with FSA_ERROR_RESPONSE None
    try:
        app = af.create_app(FSA_ERROR_RESPONSE=None)
        app._fsa.initialize()
        assert False, "should have raised an exception"
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, with FSA_ERROR_RESPONSE "bad value"
    try:
        app = af.create_app(FSA_ERROR_RESPONSE="bad value")
        app._fsa.initialize()
        assert False, "should have raised an exception"
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, to trigger a warning for coverage
    def erh(m: str, c: int):
        return Response(m, c, content_type="text/plain")
    app = fsa.Flask("trigger warning")
    app._fsa._error_response = erh
    app.config.update(FSA_ERROR_RESPONSE="json", FSA_SECURE=False)
    app._fsa.initialize()

def test_add_headers():
    import AppFact as af
    app = af.create_app(FSA_ADD_HEADERS={"Service": "FSA", "Headers": lambda r: len(r.headers)})
    @app.get("/heads", authorize="ANY")
    def get_heads():
        return "", 200
    app.add_headers(Now="Maintenant")
    client = app.test_client()
    res = check(200, client.get("heads"))
    assert "Service" in res.headers and "Headers" in res.headers and "Now" in res.headers

def test_request_hooks():
    def before_bad(req):
        return Response("Ooops!", 555)
    def after_cool(res):
        res.headers["Cool"] = "Calvin"
        return res
    import AppFact as af
    app = af.create_app(FSA_BEFORE_REQUEST=[], FSA_AFTER_REQUEST=[after_cool])
    @app.get("/cool", authorize="ANY")
    def get_cool():
        return "this is cool!", 200
    client = app.test_client()
    res = check(200, client.get("/cool"))
    assert res.data == b"this is cool!"
    assert "Cool" in res.headers and res.headers["Cool"] == "Calvin"
    # add the kill-me before request
    app._fsa._before_requests = [before_bad]
    res = check(555, client.get("/cool"))
    assert res.data == b"Ooops!"
