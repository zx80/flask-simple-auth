# tests with flask
#
# FIXME tests are not perfectly isolated as they should be…
#

import io
import re
import importlib
import typing
import datetime as dt

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
log.setLevel(logging.DEBUG)
# app._fsa._initialize()

def check(code, res):
    if res.status_code != code:
        log.debug(f"BAD res = {res.data}")
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

def has_package(pkg_name):
    try:
        importlib.import_module(pkg_name)
        return True
    except ModuleNotFoundError:
        return False

def test_sanity():
    assert App.app is not None and fsa is not None
    assert App.app.name == "Test"
    assert app._fsa._am._realm == "Test"
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
    with af.create_app(FSA_MODE="debug", FSA_LOGGING_LEVEL=logging.DEBUG).test_client() as c:
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
    app_saved_auth.update(a = app._am._auth, t = app._am._tm._token, c = app._am._tm._carrier, n = app._am._tm._name)
    app._am._auth = [auth] if isinstance(auth, str) else auth
    app._am._tm._token, app._am._tm._carrier, app._am._tm._name = token, carrier, name
    app._am._auth_params.add(name)

def pop_auth(app):
    d = app_saved_auth
    app._am._auth, app._am._tm._token, app._am._tm._carrier, app._am._tm._name = d["a"], d["t"], d["c"], d["n"]
    d.clear()

def basic_auth(login: str, password: str):
    from base64 import b64encode
    encoded = b64encode(f"{login}:{password}".encode("UTF8"))
    return {"Authorization": f"Basic {encoded.decode('ascii')}"}

def auth_header_basic(user: str):
    return basic_auth(user, App.UP[user])

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
    push_auth(app._fsa, ["token", "basic", "param"], "fsa", "param", "auth")
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    pop_auth(app._fsa)
    # user-pass basic
    push_auth(app._fsa, ["token", "basic"], "fsa", "param", "auth")
    BASIC = basic_auth(user, pswd)
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    pop_auth(app._fsa)
    push_auth(app._fsa, ["token", "basic", "param"], "fsa", "param", "auth")
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
    client.set_cookie(domain="localhost", key="auth", value=token_fake)
    check(client.get(*args, **kwargs))
    client.delete_cookie(domain="localhost", key="auth")
    client.set_cookie(domain="localhost", key="auth", value=token_param)
    check(client.get(*args, **kwargs))
    client.delete_cookie(domain="localhost", key="auth")
    client.set_cookie(domain="localhost", key="auth", value=token_basic)
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
    log.debug(f"app._fsa._zm._user_in_group: {app._fsa._zm._user_in_group}")
    assert App.user_in_group("dad", App.ADMIN)
    assert app._fsa._zm._user_in_group("dad", App.ADMIN)
    all_auth(client, "dad", App.UP["dad"], check_200, "/admin")
    assert not App.user_in_group("calvin", App.ADMIN)
    all_auth(client, "calvin", App.UP["calvin"], check_403, "/admin")
    assert not App.user_in_group("hobbes", App.ADMIN)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/admin")
    # manual cache cleaning for "dad"
    assert app.password_uncache("dad")
    assert app.group_uncache("dad", App.ADMIN)
    # full cache cleaning
    assert hasattr(app._fsa._cm._cache, "clear")
    app.clear_caches()
    # write only
    check(401, client.get("/write"))
    assert app._fsa._zm._user_in_group("dad", App.WRITE)
    all_auth(client, "dad", App.UP["dad"], check_200, "/write")
    assert app._fsa._zm._user_in_group("calvin", App.WRITE)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/write")
    assert not App.user_in_group("hobbes", App.WRITE)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/write")
    # read only
    check(401, client.get("/read"))
    assert not app._fsa._zm._user_in_group("dad", App.READ)
    all_auth(client, "dad", App.UP["dad"], check_403, "/read")
    assert app._fsa._zm._user_in_group("calvin", App.READ)
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
    # hmmm… these tests are not very clean
    tm = app._fsa._am._tm
    tsave, hsave = tm._token, tm._algo
    tm._token, tm._algo = "fsa", "blake2s"
    tm._issuer = "self"
    app._fsa._local.token_realm = app._fsa._am._realm
    foo_token = app.create_token("foo")
    assert foo_token.startswith("Test/self:foo:")
    assert tm._get_any_token_auth(foo_token) == "foo"
    tm._issuer = None
    calvin_token = app.create_token("calvin")
    assert calvin_token.startswith("Test:calvin:")
    assert tm._get_any_token_auth(calvin_token) == "calvin"
    # realm parameter
    test2_token = app.create_token("susie", realm="test2")
    assert test2_token.startswith("test2:susie:")
    test_token = app.create_token("hobbes")
    assert test_token.startswith("Test:hobbes:")
    # malformed token
    try:
        user = tm._get_any_token_auth("not an FSA token")
        pytest.fail("expecting a malformed error")
    except fsa.ErrorResponse as e:
        assert "invalid fsa token" in str(e)
    # bad timestamp format
    try:
        user = tm._get_any_token_auth("R:U:demain:signature")
        pytest.fail("expecting a bad timestamp format")
    except fsa.ErrorResponse as e:
        assert "unexpected timestamp format" in e.message
    try:
        user = tm._get_any_token_auth("Test:calvin:20201500000000:signature")
        pytest.fail("expecting a bad timestamp format")
    except fsa.ErrorResponse as e:
        assert "unexpected fsa token limit" in e.message
    # force expiration
    grace = tm._grace
    tm._grace = -1000000
    try:
        user = tm._get_any_token_auth(calvin_token)
        pytest.fail("token must have expired")
    except fsa.ErrorResponse as e:
        assert "expired auth token" in e.message
    # again after clear cache, so the expiration is detected at fsa level
    assert app.token_uncache(calvin_token, "Test")
    # app.clear_caches()
    try:
        user = tm._get_any_token_auth(calvin_token)
        pytest.fail("token must have expired")
    except fsa.ErrorResponse as e:
        assert "expired fsa auth token" in e.message
    # cleanup
    tm._grace = grace
    tm._token, tm._algo = tsave, hsave
    hobbes_token = app.create_token("hobbes")
    grace, tm._grace = tm._grace, -100
    try:
        user = tm._get_any_token_auth(hobbes_token)
        pytest.fail("token should be invalid")
    except fsa.ErrorResponse as e:
        assert e.status == 401
    tm._grace = grace


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
    tm = app._fsa._am._tm
    tsave, hsave, tm._token, tm._algo = tm._token, tm._algo, "jwt", "HS256"
    Ksave, ksave = tm._secret, tm._sign
    # hmac signature scheme
    tm._issuer = "self"
    moe_token = app.create_token("moe")
    assert "." in moe_token and len(moe_token.split(".")) == 3
    user = tm._get_any_token_auth(moe_token)
    assert user == "moe"
    # again for caching test
    user = tm._get_any_token_auth(moe_token)
    assert user == "moe"
    tm._issuer = None
    # expired token
    delay, grace = tm._delay, tm._grace
    tm._delay, tm._grace = -1, 0
    susie_token = app.create_token("susie")
    assert len(susie_token.split(".")) == 3
    try:
        user = tm._get_any_token_auth(susie_token)
        pytest.fail("expired token should fail")
    except fsa.ErrorResponse as e:
        assert "expired jwt auth token" in e.message
    finally:
        tm._delay, tm._grace = delay, grace
    # pubkey stuff
    tm._algo, tm._secret, tm._sign = "RS256", RSA_TEST_PUB_KEY, RSA_TEST_PRIV_KEY
    mum_token = app.create_token("mum")
    pieces = mum_token.split(".")
    assert len(pieces) == 3
    user = tm._get_any_token_auth(mum_token)
    assert user == "mum"
    # bad pubkey token
    try:
        bad_token = f"{pieces[0]}.{pieces[2]}.{pieces[1]}"
        user = tm._get_any_token_auth(bad_token)
        pytest.fail("bad token should fail")
    except fsa.ErrorResponse as e:
        assert "invalid jwt token" in e.message
    # cleanup
    tm._token, tm._algo = tsave, hsave
    tm._secret, tm._sign = Ksave, ksave

def test_invalid_token():
    tm = app._fsa._am._tm
    # bad token
    susie_token = app.create_token("susie", tm._realm)
    susie_token = susie_token[:-1] + "z"
    try:
        user = tm._get_any_token_auth(susie_token, tm._realm)
        pytest.fail("token should be invalid")
    except fsa.ErrorResponse as e:
        assert e.status == 401
    # wrong token
    realm, tm._realm = tm._realm, "elsewhere"
    moe_token = app.create_token("moe", tm._realm)
    tm._realm = realm
    try:
        user = tm._get_any_token_auth(moe_token, tm._realm)
        pytest.fail("token should be invalid")
    except fsa.ErrorResponse as e:
        assert e.status == 401

def test_password_lazy_init():
    app = fsa.Flask("pass-one", FSA_AUTH="basic")
    ref = app.hash_password("hello world!")
    assert isinstance(ref, str) and len(ref) >= 40
    app = fsa.Flask("pass-two", FSA_AUTH="basic")
    assert app.check_password("hello world!", ref)

def test_password_check(client):
    fsa = app._fsa
    # standard password
    fsa._initialize()
    pm = fsa._am._pm
    ref = app.hash_password("hello")
    assert app.check_password("hello", ref)
    assert not app.check_password("bad-pass", ref)
    assert not app.check_password("hello", "bad-ref")
    # password alternate hook
    assert pm._pass_check is None
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
    pm._pass_check = test_check_pass
    assert app.check_user_password("calvin", "hobbes")
    assert app.check_user_password("susie", "magic")
    assert app.check_user_password("moe", "magic")
    assert not app.check_user_password("moe", "bad-password")
    try:
        pm.check_user_password("boo", "none")
        pytest.fail("should have raised an error")
    except ErrorResponse as e:
        assert True, "none password was rejected"
    try:
        pm.check_user_password("dad", "Error")
        pytest.fail("should raise an error")
    except ErrorResponse as e:
        assert "test_check_pass error" in str(e)
    try:
        pm.check_user_password("baa", "whatever")
        pytest.fail("should raise an Exception")
    except ErrorResponse as e:
        assert "no such user" in str(e)
    saved = pm._get_user_pass
    pm.get_user_pass(None)
    try:
        pm.check_user_password("calvin", "Oops!")
        pytest.fail("should raise an error")
    except ErrorResponse as e:
        assert "invalid user/password" in str(e)
    pm.get_user_pass(saved)
    fsa.password_check(None)
    # password, through requests
    push_auth(fsa, ["basic", "param"])
    res = check(401, client.get("/read", data={"USER": "dad", "PASS": "bad-dad-password"}))
    assert b"invalid password for" in res.data
    res = check(401, client.get("/read", data={"USER": "dad"}))
    assert b"missing param password parameter" in res.data
    pop_auth(fsa)
    # basic, through requests
    push_auth(fsa, ["basic"])
    res = check(401, client.get("/read", headers={"Authorization": "Basic !!!"}))
    assert b"decoding error on authorization" in res.data
    pop_auth(fsa)

def test_no_password_manager():
    app = fsa.Flask("nopm", FSA_AUTH="none", FSA_PASSWORD_SCHEME=None)
    try:
        app.hash_password("hello")
        pytest.fail("should fail because no pm")
    except ErrorResponse as e:
        assert "disabled" in str(e)

def test_plaintext_password():
    app = fsa.Flask("plain", FSA_AUTH="password", FSA_PASSWORD_SCHEME="plaintext")
    assert app.hash_password("hello") == "hello"
    assert app.check_password("hello", "hello")

def check_various_passwords(app):
    for password in ("hello", "W0r1d!", "&éçàùµ§…"):
        assert app.check_password(password, app.hash_password(password))
        assert not app.check_password("another one", app.hash_password(password))

def test_fsa_password_simple_schemes():
    for scheme in ("plaintext", "fsa:plaintext", "fsa:b64", "fsa:a85"):
        app = fsa.Flask(scheme, FSA_AUTH="password", FSA_PASSWORD_SCHEME=scheme)
        check_various_passwords(app)

@pytest.mark.skipif(not has_package("bcrypt"), reason="bcrypt is not available")
def test_fsa_password_bcrypt_scheme():
    for scheme in ("bcrypt", "fsa:bcrypt"):
        app = fsa.Flask(scheme, FSA_AUTH="password", FSA_PASSWORD_SCHEME=scheme)
        check_various_passwords(app)

@pytest.mark.skipif(not has_package("argon2"), reason="argon2 is not available")
def test_fsa_password_argon2_scheme():
    for scheme in ("argon2", "fsa:argon2"):
        app = fsa.Flask(scheme, FSA_AUTH="password", FSA_PASSWORD_SCHEME=scheme)
        check_various_passwords(app)

@pytest.mark.skipif(not has_package("scrypt"), reason="scrypt is not available")
def test_fsa_password_scrypt_scheme():
    for scheme in ("scrypt", "fsa:scrypt"):
        app = fsa.Flask(scheme, FSA_AUTH="password", FSA_PASSWORD_SCHEME=scheme)
        check_various_passwords(app)

@pytest.mark.skipif(not has_package("passlib"), reason="passlib is not available")
def test_passlib_password_scheme():
    for scheme in ("passlib:plaintext", "passlib:bcrypt"):
        app = fsa.Flask(scheme, FSA_AUTH="password", FSA_PASSWORD_SCHEME=scheme)
        check_various_passwords(app)

@pytest.mark.skipif(not has_package("passlib"), reason="passlib is not available")
def test_passlib_password_scheme_list():
    app = fsa.Flask("passlib", FSA_AUTH="password", FSA_PASSWORD_SCHEME=["bcrypt", "plaintext"])
    # bcrypt
    ref = app.hash_password("hello")
    assert len(ref) > 10
    assert app.check_password("hello", ref)
    assert not app.check_password("world", ref)
    # plaintext
    assert app.check_password("world", "world")
    assert not app.check_password("hello", "world")

def test_password_quality():
    mode = app._fsa._mode
    app._fsa._mode = fsa._Mode.DEBUG3
    pm = app._fsa._am._pm
    # password len
    assert pm._pass_len == 0
    assert app.hash_password("") is not None
    assert app.hash_password("c") is not None
    assert app.hash_password("cy") is not None
    pm._pass_len = 1
    try:
        app.hash_password("")
        pytest.fail("len must be rejected")
    except ErrorResponse as e:
        assert "too short" in str(e)
    assert app.hash_password("c") is not None
    assert app.hash_password("cy") is not None
    pm._pass_len = 2
    assert app.hash_password("cy") is not None
    # password re, eg password must contain a lc and uc letter
    assert len(pm._pass_re) == 0
    pm._pass_re = [
        re.compile(r"[a-z]").search,
        re.compile(r"[A-Z]").search,
    ]
    assert app.hash_password("Cy") is not None
    try:
        app.hash_password("CY")
        pytest.fail("must detect missing lc letter")
    except ErrorResponse as e:
        assert "a-z" in str(e)
    try:
        app.hash_password("cy")
        pytest.fail("must detect missing uc letter")
    except ErrorResponse as e:
        assert "A-Z" in str(e)
    # password quality return
    assert pm._pass_quality is None
    def password_quality_checker(pwd):
        if pwd == "G0od!":
            return True
        elif pwd == "B@d":
            return False
        else:
            raise Exception(f"password quality checker is not happy about {pwd}")
    pm._pass_quality = password_quality_checker
    assert app.hash_password("G0od!") is not None
    try:
        app.hash_password("B@d")
        pytest.fail("password should be rejected")
    except ErrorResponse as e:
        assert True, "password was rejected as expected"
    # password quality exception
    try:
        app.hash_password("@ny-Password!")
        pytest.fail("password should be rejected")
    except ErrorResponse as e:
        assert "not happy" in str(e)
    # reset password checking rules
    app._fsa._mode = mode
    pm._pass_len = 0
    pm._pass_re = []
    pm._pass_quality = None

def test_authorize():
    assert app._fsa._zm._user_in_group("dad", App.ADMIN)
    assert not app._fsa._zm._user_in_group("hobbes", App.ADMIN)
    @app._fsa._zm._group_authz("stuff", App.ADMIN)
    def stuff():
        return Response("", 200)
    app._fsa._local.user = "dad"
    res = stuff()
    assert res.status_code == 200
    app._fsa._local.user = "hobbes"
    res = stuff()
    assert res.status_code == 403
    try:
        @app._fsa._zm._group_authz("stuff", "AUTH", "OPEN")
        def foo():
            return "foo", 200
        pytest.fail("cannot mix AUTH & OPEN in authorize")
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
    app._fsa._pm._reject_param = False
    res = check(200, client.get("/mul/2", data={"j":"3", "k":"4", "unused":"x"}))
    assert int(res.data) == 24
    res = check(200, client.get("/mul/2", json={"j":5, "k":"4", "unused":"y"}))
    assert int(res.data) == 40
    # unused params are rejected
    app._fsa._pm._reject_param = True
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
    client2.delete_cookie(key="auth")
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
    # log.debug(f"res auth = {res.www_authenticate.keys()}")
    assert "Basic" in str(res.www_authenticate)
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, ["basic", "param"])
    res = check(401, client.get("/admin"))
    assert "Basic" in str(res.www_authenticate)
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "bearer", "Hello")
    res = check(401, client.get("/admin"))
    assert "Hello" in str(res.www_authenticate)
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
    BASIC = basic_auth("calvin", "hobbes")
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
        app._fsa._am._http_auth.header = "HiHiHi"
        res = check(200, client.get("/token", headers={"HiHiHi": calvin_token}))
        assert res.data == b"calvin"
        app._fsa._am._http_auth.header = None
        pop_auth(app._fsa)
        # check header token fallback
        push_auth(app._fsa, "token", "fsa", "header", "HoHoHo")
        res = check(200, client.get("/token", headers={"HoHoHo": calvin_token}))
        assert res.data == b"calvin"
        pop_auth(app._fsa)

def test_per_route(client):
    # data for 4 various authentication schemes
    BASIC = basic_auth("calvin", App.UP["calvin"])
    PARAM = {"USER": "calvin", "PASS": App.UP["calvin"]}
    FAKE = {"LOGIN": "calvin"}
    token = app.create_token("calvin")
    log.debug(f"calvin token: {token}")
    TOKEN = {"Authorization": f"Bearer {token}"}
    # basic
    log.debug("trying: basic")
    res = check(200, client.get("/auth/basic", headers=BASIC))
    assert "basic auth: calvin" in res.text
    assert "calvin (basic)" in res.headers["FSA-User"]
    check(401, client.get("/auth/basic", headers=TOKEN))
    check(401, client.get("/auth/basic", data=PARAM))
    check(401, client.get("/auth/basic", json=PARAM))
    check(401, client.get("/auth/basic", data=FAKE))
    check(401, client.get("/auth/basic", json=FAKE))
    # param
    res = check(200, client.get("/auth/param", data=PARAM))
    assert "param auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/param", json=PARAM))
    assert "param auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    check(401, client.get("/auth/param", headers=BASIC))
    check(401, client.get("/auth/param", headers=TOKEN))
    check(401, client.get("/auth/param", data=FAKE))
    check(401, client.get("/auth/param", json=FAKE))
    # password
    res = check(200, client.get("/auth/password", headers=BASIC))
    assert "password auth: calvin" in res.text
    assert "calvin (basic)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/password", data=PARAM))
    assert "password auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/password", json=PARAM))
    assert "password auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    check(401, client.get("/auth/password", headers=TOKEN))
    check(401, client.get("/auth/password", data=FAKE))
    check(401, client.get("/auth/password", json=FAKE))
    # token
    res = check(200, client.get("/auth/token", headers=TOKEN))
    assert "token auth: calvin" in res.text
    assert "calvin (token)" in res.headers["FSA-User"]
    check(401, client.get("/auth/token", data=PARAM))
    check(401, client.get("/auth/token", json=PARAM))
    check(401, client.get("/auth/token", headers=BASIC))
    check(401, client.get("/auth/token", data=FAKE))
    check(401, client.get("/auth/token", json=FAKE))
    # fake
    res = check(200, client.get("/auth/fake", data=FAKE))
    assert "fake auth: calvin" in res.text
    assert "calvin (fake)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/fake", json=FAKE))
    assert "fake auth: calvin" in res.text
    assert "calvin (fake)" in res.headers["FSA-User"]
    check(401, client.get("/auth/fake", headers=TOKEN))
    check(401, client.get("/auth/fake", data=PARAM))
    check(401, client.get("/auth/fake", json=PARAM))
    check(401, client.get("/auth/fake", headers=BASIC))
    # fake, token, param
    res = check(200, client.get("/auth/ftp", data=FAKE))
    assert "ftp auth: calvin" in res.text
    assert "calvin (fake)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/ftp", json=FAKE))
    assert "ftp auth: calvin" in res.text
    assert "calvin (fake)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/ftp", headers=TOKEN))
    assert "ftp auth: calvin" in res.text
    assert "calvin (token)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/ftp", data=PARAM))
    assert "ftp auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    res = check(200, client.get("/auth/ftp", json=PARAM))
    assert "ftp auth: calvin" in res.text
    assert "calvin (param)" in res.headers["FSA-User"]
    check(401, client.get("/auth/ftp", headers=BASIC))

def test_default_auth():
    # bad cases
    try:
        app = fsa.Flask("bad", FSA_AUTH=["token", "param"], FSA_AUTH_DEFAULT="basic")
        # trigger init
        app.hash_password("hello")
        pytest.fail("default auth is not allowed")
    except ConfigError as e:
        assert "not enabled" in str(e)
    try:
        app = fsa.Flask("bad", FSA_AUTH="password", FSA_AUTH_DEFAULT=42)
        app.hash_password("hello")
        pytest.fail("default auth type")
    except ConfigError as e:
        assert "int" in str(e)
    # working case
    app = fsa.Flask("no-auth", FSA_AUTH=["token", "fake"], FSA_AUTH_DEFAULT="token")
    @app.get("/login", authz="AUTH", authn="fake")
    def get_login(user: fsa.CurrentUser):
        return {"token": app.create_token(user)}
    @app.get("/hello", authz="AUTH")  # MUST be token!
    def get_hello(user: fsa.CurrentUser):
        return {"msg": f"hello {user}"}
    with app.test_client() as api:
        res = api.get("/login", data={"LOGIN": "calvin"})
        assert res.status_code == 200 and res.is_json
        calvin_token = res.json["token"]
        # fake must be blocked
        res = api.get("/hello", data={"LOGIN": "hobbes"})
        assert res.status_code == 401
        # token must be ok
        res = api.get("/hello", headers={"Authorization": f"Bearer {calvin_token}"})
        assert res.status_code == 200 and res.is_json and res.json["msg"] == "hello calvin"

def test_bad_app():
    from AppBad import create_app
    # working versions, we basically test that there is no exception
    app = create_app(FSA_AUTH="basic", FSA_LOCAL="werkzeug")
    app = create_app(FSA_AUTH=["token", "basic"])
    app = create_app(FSA_AUTH="fake", auth="fake")
    app = create_app(FSA_AUTH=["token", "fake"], auth=["token", "fake"])
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
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH=1)
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "unexpected FSA_AUTH type" in str(e)
    try:
        app = create_app(FSA_AUTH=[1])
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "unexpected authentication id" in str(e)
    try:
        app = create_app(FSA_AUTH=["fake", "basic", "bad"])
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(auth="bad")
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH="password", auth=["basic", "token", "bad"])
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # bad token type
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="bad")
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # FIXME, None is ok?
    # try:
    #     app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE=None)
    #    # pytest.fail("bad app creation must fail")
    # except ConfigError as e:
    #     assert True, "ok, bad app creation has failed"
    # bad token carrier
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bad")
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER=None)
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "unexpected FSA_TOKEN_CARRIER" in str(e), "ok, bad app creation has failed"
    # bad token name
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bearer", FSA_TOKEN_NAME=None)
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "requires a name" in str(e), "ok, bad app creation has failed"
    # bad jwt talgorithm
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="bad")
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "bad" in str(e), "ok, bad app creation has failed"
    # bad local
    try:
        app = create_app(FSA_LOCAL="oops!")
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "FSA_LOCAL" in str(e)
    # bad route auth
    try:
        app = create_app("token")
        @app.get("/bad-auth-type", authz="AUTH", authn=1)
        def get_bad_auth_type():
            return None
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "unexpected authn type" in str(e)
    app = create_app("basic", FSA_ALLOW_DEPRECATION=True)
    # incompatible route parameters
    try:
        @app.get("/bad-param-1", authorize="AUTH", authz="OPEN")
        def get_bad_param_1():
            return None
        pytest.fail("creation must fail")
    except ConfigError as e:
        assert "cannot use both" in str(e)
    try:
        @app.get("/bad-param-2", auth="basic", authn="param")
        def get_bad_param_2():
            return None
        pytest.fail("creation must fail")
    except ConfigError as e:
        assert "cannot use both" in str(e)
    try:
        @app.get("/bad-param-3", authorize="AUTH", authz="CLOSE")
        def get_bad_param_1():
            return None
        pytest.fail("creation must fail")
    except ConfigError as e:
        assert "cannot use both" in str(e)
    # bad add various checks
    try:
        app.add_group(["hello", "world"])
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "invalid group type" in str(e)
    try:
        app.add_scope(["hello", "world"])
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "invalid scope type" in str(e)
    try:
        app.add_headers(one=1)
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "header value" in str(e)
    try:
        @app.get("/bad-param-col", authz="OPEN")
        def get_bad_param_col(_x: int, x: int):
            return _x + x, 200
        pytest.fail("bad app creation must fail")
    except ConfigError as e:
        assert "collision" in str(e)
    try:
        @app.get("/bad-param-pos", authz="OPEN")
        def get_bad_param_pos(*args):
            return len(args)
    except ConfigError as e:
        assert "position" in str(e)


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
    assert b"internal error while checking group" in res.data

# test a bad route function
@pytest.fixture
def bad4():
    import AppBad as ab
    with ab.create_badapp_4().test_client() as c:
        yield c

def test_bad_4(bad4):
    check(200, bad4.get("/ok"))
    res = check(500, bad4.get("/any"))
    assert b"internal error caught at no params on /any" == res.data
    check(404, bad4.get("/no-such-route"))


def test_bads():
    import AppBad as ab
    try:
        app = ab.create_badapp_5()
        pytest.fail("mandatory parameter with default should fail")
    except ConfigError as e:
        assert "default" in str(e)
    try:
        app = ab.create_badapp_6()
        pytest.fail("missing path parameter should fail")
    except ConfigError as e:
        assert "missing" in str(e)
    try:
        app = ab.create_badapp_7()
        pytest.fail("inconsistent path parameter types should fail")
    except ConfigError as e:
        assert "bad" in str(e)
    try:
        app = ab.create_badapp_8()
        pytest.fail("unknown path parameter converter should fail")
    except ConfigError as e:
        assert "unknown" in str(e)
    # unexpected parameter
    app = fsa.Flask("unexpected param", FSA_AUTH="none", FSA_MODE="debug2")
    @app.get("/youpi", authz="OPEN")
    def get_youpi(i: int):
        return str(i), 200
    client = app.test_client()
    check(200, client.get("/youpi", data={"i": 5432}))
    check(200, client.get("/youpi", json={"i": 5432}))
    res = check(400, client.get("/youpi", data={"i": 5432, "j": "oops!"}))
    assert b"unexpected http parameter \"j\"" in res.data
    res = check(400, client.get("/youpi", json={"i": 5432, "h": "oops!"}))
    assert b"unexpected json parameter \"h\"" in res.data

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
    assert app.object_perms_uncache("users", "calvin", "calvin", None)
    check(200, client.get("/my/calvin", data={"LOGIN": "calvin"}))
    check(200, client.get("/my/hobbes", data={"LOGIN": "hobbes"}))
    # no-such-user
    check(404, client.get("/my/no-such-user", data={"LOGIN": "calvin"}))
    # multi-parameter object perms
    res = check(200, client.get("/perm/fun/4/4", data={"LOGIN": "calvin"}))
    assert "calvin i==j" in res.text
    check(403, client.get("/perm/fun/3/4", data={"LOGIN": "calvin"}))

def test_object_perms_errors():
    import AppFact as af
    app = af.create_app()
    @app.object_perms("known")
    def is_okay(u: str, v: str, m: str):
        log.debug(f"is_okay({u}, {v}, {m})")
        if v == "fsa":
            fsa.err("oops-1", 518)
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
        @app.get("/bad-perm-1", authz=tuple())
        def get_bad_perm_1(uid: int):
            ...
        pytest.fail("should detect too short tuple")
    except ConfigError as e:
        assert "3 data" in str(e)
    try:
        @app.get("/bad-perm-2/<uid>", authz=("unknown",))
        def get_bad_perm_2_uid(uid: int):
            ...
        pytest.fail("should detect unregistered permission domain")
    except ConfigError as e:
        assert "missing object permission" in str(e)
    try:
        @app.get("/bad-perm-3", authz=("known", 3))
        def get_bad_perm_3(uid: int):
            ...
        pytest.fail("should detect bad variable name")
    except ConfigError as e:
        assert "unexpected identifier name type" in str(e)
    try:
        @app.get("/bad-perm-4/<uid>", authz=("known", "uid", 3.14159))
        def get_bad_perm_4_uid(uid: int):
            ...
        pytest.fail("should detect bad mode type")
    except ConfigError as e:
        assert "unexpected mode type" in str(e)
    try:
        @app.get("/bad-perm-5", authz=("known", "uid"))
        def get_bad_perm_5(oid: int):
            ...
        pytest.fail("should detect missing variable")
    except ConfigError as e:
        assert "missing function parameter uid" in str(e)
    try:
        @app.get("/bad-perm-6", authz=("known", "uid"))
        def get_bad_perm_6():
            ...
        pytest.fail("should detect missing variable")
    except ConfigError as e:
        assert "permissions require some parameters" in str(e)
    try:
        @app.get("/bad-perm-7/<à>", authz=("known", "à"))
        def get_bad_perm_7(à: int):
            ...
        pytest.fail("should reject non-ASCII variable name")
    except ConfigError as e:
        assert "à" in str(e)
    try:
        @app.get("/bad-perm-8/<a>/<ê>", authz=("known", "a:ê"))
        def get_bad_perm_7(a: int, ê: int):
            ...
        pytest.fail("should reject non-ASCII variable name")
    except ConfigError as e:
        assert "ê" in str(e)
    # run time errors
    @app.get("/oops/<err>", authz=("known", "err"))
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
        @app.get("/bad-authorize", authz=[3.14159])
        def get_bad_authorize():
            ...
        pytest.fail("should detect bad authorize type")
    except ConfigError as e:
        assert "unexpected authorization" in str(e)
    try:
        @app.get("/bad-mix-1", authz=["OPEN", "AUTH"])
        def get_bad_mix_1():
            ...
        pytest.fail("should detect OPEN/AUTH mix")
    except ConfigError as e:
        assert "OPEN/AUTH" in str(e)
    try:
        @app.get("/bad-mix-2", authz=["OPEN", "OTHER"])
        def get_bad_mix_2():
            ...
        pytest.fail("should detect OPEN/other mix")
    except ConfigError as e:
        assert "other" in str(e)
    try:
        @app.get("/bad-mix-3", authz=["OPEN", ("foo", "id")])
        def get_bad_mix_2():
            ...
        pytest.fail("should detect OPEN/other mix")
    except ConfigError as e:
        assert "object" in str(e)
    try:
        app.add_group("foo", "bla")
        @app.get("/bad-group", authz="no-such-group")
        def get_bad_group():
            ...
        pytest.fail("should detect unregistered group")
    except ConfigError as e:
        assert "no-such-group" in str(e)
    try:
        app.add_scope("foo", "bla")
        app._fsa._am._tm._token = "jwt"
        app._fsa._am._tm._issuer = "calvin"
        @app.get("/bad-scope", authz="no-such-scope", authn="oauth")
        def get_bad_scope():
            ...
        pytest.fail("should detect unregistered scope")
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
    app = af.create_app(FSA_AUTH=["fake", "oauth"], FSA_USER_IN_GROUP=bad_uig)
    @app.get("/ex", authz="ex")
    def get_ex():
        ...
    @app.get("/float", authz="float")
    def get_float():
        ...
    c = app.test_client()
    res = c.get("/ex", data={"LOGIN": "calvin"})
    assert res.status_code == 518 and b"exception in user_in_group" in res.data
    res = c.get("/float", data={"LOGIN": "calvin"})
    assert res.status_code == 500 and b"internal error in group check" in res.data

def test_scope_errors():
    import AppFact as af
    try:
        app = af.create_app(FSA_AUTH="oauth", FSA_TOKEN_TYPE="fsa")
        pytest.fail("should raise an exception")
    except ConfigError as e:
        assert "oauth" in str(e) and "JWT" in str(e)
    try:
        app = af.create_app(FSA_AUTH="oauth", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ISSUER=None)
        pytest.fail("should raise an exception")
    except ConfigError as e:
        assert "oauth" in str(e) and "ISSUER" in str(e)
    try:
        app = af.create_app(FSA_AUTH="oauth", FSA_TOKEN_TYPE="fsa", FSA_TOKEN_ISSUER="god")
        @app.get("/foo/bla", authz=["read"], authn=["oauth"])
        def get_foo_bla():
            ...
        pytest.fail("should be rejected: oauth requires jwt, not fsa")
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
    if size > 0 and n > 5:  # hmmm…
        assert hits > (n-4) / n

@pytest.mark.skipif(not has_service(port=11211) or not has_package("pymemcache"),
                    reason="memcached service module are required")
def test_memcached_cache(client):
    import AppFact as af
    for prefix in ["mmcap.", None]:
        with af.create_app(
            FSA_CACHE="memcached", FSA_CACHE_PREFIX=prefix,
            FSA_CACHE_OPTS={"server": "localhost:11211"}).test_client() as c:
            run_some_checks(c)

@pytest.mark.skipif(not has_service(port=6379) or not has_package("redis"),
                    reason="redis service and module are required")
def test_redis_cache():
    import AppFact as af
    for prefix in ["redap.", None]:
        with af.create_app(
            FSA_CACHE="redis", FSA_CACHE_PREFIX=prefix,
            FSA_CACHE_OPTS={"host": "localhost", "port": 6379}).test_client() as c:
            run_some_checks(c)

def test_caches():
    import AppFact as af
    import CacheToolsUtils as ctu
    # mru: deprecated
    for cache in ["ttl", "lru", "lfu", "fifo", "rr", "dict", "none"]:
        for prefix in [cache + ".", None]:
            log.debug(f"testing cache type {cache}")
            with af.create_app(FSA_CACHE=cache, FSA_CACHE_PREFIX=prefix).test_client() as c:
                run_some_checks(c)
    for prefix in ["tlru.", None]:
        log.debug(f"testing cache type tlru and custom")
        with af.create_app(FSA_CACHE="tlru",
                           FSA_CACHE_PREFIX=prefix,
                           FSA_CACHE_OPTS={"ttu": lambda _k, _v, now: now+10}).test_client() as c:
            run_some_checks(c)
        with af.create_app(FSA_CACHE=ctu.DictCache(),
                           FSA_CACHE_PREFIX=prefix).test_client() as c:
            run_some_checks(c)

def test_no_such_cache():
    import AppFact as af
    try:
        af.create_app(FSA_CACHE="no-such-cache")
        pytest.fail("create app should fail")
    except ConfigError as e:
        assert "unexpected FSA_CACHE" in e.args[0]

def test_warnings_and_errors():
    def bad_gup_1(user: str):
        raise fsa.ErrorResponse("bad_gup_1", 518)
    def bad_gup_2(user: str):
        return 3.14159
    import AppFact as af
    app = af.create_app(
        FSA_AUTH=["basic", "token"],
        FSA_TOKEN_TYPE="fsa",
        FSA_TOKEN_CARRIER="param",
        FSA_TOKEN_SIGN="signature-not-used-for-fsa-tokens",
        FSA_FAKE_LOGIN="not-used-if-no-fake",
        FSA_PARAM_USER="not-used-if-no-param",
        FSA_PARAM_PASS="not-used-if-no-param",
        FSA_PASSWORD_LENGTH=10,
        FSA_PASSWORD_RE=[r"[0-9]"],
        FSA_GET_USER_PASS=bad_gup_1,
    )
    app._fsa._initialize()
    # password exceptions
    try:
        app.hash_password("short1")
        pytest.fail("should be too short")
    except fsa.ErrorResponse as e:
        assert e.status == 400 and "too short" in e.message
    try:
        app.hash_password("long-enough-but-missing-a-number")
        pytest.fail("should not match re")
    except fsa.ErrorResponse as e:
        assert e.status == 400 and "must match" in e.message
    try:
        app._fsa._am._pm.check_user_password("calvin", "hobbes")
        pytest.fail("should not get through")
    except fsa.ErrorResponse as e:
        assert e.status == 518 and "bad" in e.message
    # unused length warning
    app = af.create_app(
        FSA_AUTH=["password", "oauth"],
        FSA_TOKEN_TYPE="jwt",
        FSA_TOKEN_ISSUER="calvin",
        FSA_TOKEN_LENGTH=8,  # no used if jwt
        FSA_GET_USER_PASS=bad_gup_2,
    )
    app._fsa._initialize()
    try:
        app._fsa._am._pm.check_user_password("calvin", "hobbes")
        pytest.fail("should not get through")
    except fsa.ErrorResponse as e:
        assert e.status == 500 and "internal error with get_user_pass" in e.message
    # overwrite warning
    @app.cast("foo")
    def cast_foo(s: str):
        return s
    assert app._fsa._pm._casts["foo"] == cast_foo
    app.cast("foo", lambda x: cast_foo(x))
    assert app._fsa._pm._casts["foo"] != cast_foo
    s = "Hello World!"
    assert app._fsa._pm._casts["foo"](s) == cast_foo(s)
    # OAuth2 warnings
    app = af.create_app()
    # type errors
    try:
        app = af.create_app(FSA_CAST="not a dict")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "FSA_CAST must be a dict" in str(e)
    try:
        app = af.create_app(FSA_OBJECT_PERMS="should be a dict")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "FSA_OBJECT_PERMS must be a dict" in str(e)
    try:
        app = af.create_app(FSA_SPECIAL_PARAMETER="not a dict")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "FSA_SPECIAL_PARAMETER must be a dict" in str(e)
    try:
        app = af.create_app(FSA_NO_SUCH_DIRECTIVE="no-such-directive")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "FSA_NO_SUCH_DIRECTIVE" in str(e)
    try:
        app = af.create_app(FSA_PASSWORD_SCHEME="foo:bcrypt")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "provider" in str(e)
    try:
        app = af.create_app(FSA_PASSWORD_SCHEME="fsa:bad-scheme")
        pytest.fail("should not get through")
    except ConfigError as e:
        assert "bad-scheme" in str(e)
    if has_package("passlib"):
        try:
            app = af.create_app(FSA_PASSWORD_SCHEME="passlib:bad_scheme")
            pytest.fail("should not get through")
        except ConfigError as e:
            assert "bad_scheme" in str(e)
    try:
        app = fsa.Flask("empty", FSA_AUTH=[])
        app._fsa._initialize()
        pytest.fail("FSA_AUTH must not be empty")
    except ConfigError as e:
        assert "empty auth" in str(e)


def test_jsondata(client):
    # simple types, anything but strings
    res = client.get("/json", data={"j": "null"})
    assert res.status_code == 200 and res.data == b"NoneType: null"
    res = client.get("/json", json={"j": None})
    assert res.status_code == 200 and res.data == b"NoneType: null"
    res = client.get("/json", data={"j": "5432"})
    assert res.status_code == 200 and res.data == b"int: 5432"
    res = client.get("/json", json={"j": 1234})
    assert res.status_code == 200 and res.data == b"int: 1234"
    res = client.get("/json", data={"j": "false"})
    assert res.status_code == 200 and res.data == b"bool: false"
    res = client.get("/json", json={"j": True})
    assert res.status_code == 200 and res.data == b"bool: true"
    res = client.get("/json", data={"j": "54.3200"})
    assert res.status_code == 200 and res.data == b"float: 54.32"
    res = client.get("/json", json={"j": 1.0000})
    assert res.status_code == 200 and res.data == b"float: 1.0"
    # note: complex is not json serializable
    # list
    res = client.get("/json", data={"j": "[1, 2]"})
    assert res.status_code == 200 and res.data == b"list: [1, 2]"
    res = client.get("/json", json={"j": [4, 5]})
    assert res.status_code == 200 and res.data == b"list: [4, 5]"
    # dict
    res = client.get("/json", data={"j": '{"n":1}'})
    assert res.status_code == 200 and res.data == b'dict: {"n": 1}'
    res = client.get("/json", json={"j": {"p": 3}})
    assert res.status_code == 200 and res.data == b'dict: {"p": 3}'
    # mixed types
    res = client.get("/json", json={"j": [False, True, [0x3, 14.000], {"q": 4}]})
    assert res.status_code == 200 and res.data == b'list: [false, true, [3, 14.0], {"q": 4}]'
    res = client.get("/json", json={"j": {"a": {"b": {"c": 3}}}})
    assert res.status_code == 200 and res.data == b'dict: {"a": {"b": {"c": 3}}}'
    # strings looking like special values
    res = client.get("/json", json={"j": "null"})
    assert res.status_code == 200 and res.data == b"str: \"null\""
    res = client.get("/json", json={"j": "true"})
    assert res.status_code == 200 and res.data == b"str: \"true\""
    res = client.get("/json", json={"j": "9876"})
    assert res.status_code == 200 and res.data == b"str: \"9876\""
    res = client.get("/json", json={"j": "32.10"})
    assert res.status_code == 200 and res.data == b"str: \"32.10\""
    res = client.get("/json", json={"j": "[3, 4]"})
    assert res.status_code == 200 and res.data == b"str: \"[3, 4]\""
    res = client.get("/json", json={"j": '{"m": 2}'})
    assert res.status_code == 200 and res.data == b'str: \"{\\"m\\": 2}\"'

def test_www_authenticate_priority(client):
    # save current status
    tm = app._fsa._am._tm
    token, carrier, name = tm._token, tm._carrier, tm._name
    tm._token, tm._carrier, tm._name = "fsa", "bearer", "Bearer"
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
    tm._name = "Foo"
    res = check(401, client.get("/perm/token"))
    assert "WWW-Authenticate" in res.headers
    assert "Foo" in res.headers["WWW-Authenticate"]
    res = check(401, client.get("/perm/token-basic"))
    assert "WWW-Authenticate" in res.headers
    assert "Foo" in res.headers["WWW-Authenticate"]
    # restore
    tm._token, tm._carrier, tm._name = token, carrier, name


def test_jwt_authorization():
    import AppFact as af
    app = af.create_app(
        FSA_AUTH=["oauth", "basic"],
        FSA_TOKEN_TYPE="jwt",
        FSA_REALM="comics",
        FSA_TOKEN_ISSUER="god")
    # oauth in list auth
    @app.get("/some/stuff", authz=["read"], authn=["oauth"])
    def get_some_stuff():
        return "", 200
    # config errors
    try:
        @app.get("/some/path", authz=["read", "write"], authn=["oauth", "basic"])
        def get_some_path():
            ...
        pytest.fail("route should be rejected")
    except fsa.ConfigError as e:
        assert "mixed" in str(e)
    app._fsa._am._tm._issuer = None
    try:
        @app.patch("/any/stuff", authz=["write"], authn="oauth")
        def patch_any_stuff():
            ...
        pytest.fail("route should be rejected")
    except fsa.ConfigError as e:
        assert "ISSUER" in str(e)
    app._fsa._am._tm._issuer = "god"
    # usage errors
    a = app._fsa._am._tm
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
    def oops(m: str, c: int, _h = None, _m = None):
        return Response(f"OOPS: {m}", c, content_type="text/plain")
    # override with the function
    app.error_response(oops)
    @app.get("/oops", authz="OPEN")
    def get_oops():
        raise ErrorResponse("oops!", 499)
    client = app.test_client()
    res = check(499, client.get("/oops"))
    assert b"OOPS: oops!" == res.data
    # again, with FSA_ERROR_RESPONSE "plain"
    app = af.create_app(FSA_ERROR_RESPONSE="plain")
    @app.get("/aaps", authz="OPEN")
    def get_aaps():
        raise ErrorResponse("aaps!", 499)
    client = app.test_client()
    res = check(499, client.get("/aaps"))
    assert b"aaps!" == res.data
    assert res.headers["Content-Type"] == "text/plain"
    # again, with FSA_ERROR_RESPONSE "json"
    app = af.create_app(FSA_ERROR_RESPONSE="json")
    @app.get("/iips", authz="OPEN")
    def get_iips():
        raise ErrorResponse("iips!", 499)
    client = app.test_client()
    res = check(499, client.get("/iips"))
    assert res.headers["Content-Type"] == "application/json"
    assert b'"iips!"' == res.data
    # again, with FSA_ERROR_RESPONSE "json:*"
    app = af.create_app(FSA_ERROR_RESPONSE="json:BLA")
    @app.get("/uups", authz="OPEN")
    def get_uups():
        raise ErrorResponse("uups!", 499)
    client = app.test_client()
    res = check(499, client.get("/uups"))
    assert res.headers["Content-Type"] == "application/json"
    assert b'{"BLA": "uups!"}' == res.data
    # again, with FSA_ERROR_RESPONSE callable
    app = af.create_app(FSA_ERROR_RESPONSE=oops)
    @app.get("/eeps", authz="OPEN")
    def get_uups():
        raise ErrorResponse("eeps!", 499)
    client = app.test_client()
    res = check(499, client.get("/eeps"))
    assert res.headers["Content-Type"] == "text/plain"
    assert b'OOPS: eeps!' == res.data
    # again, with FSA_ERROR_RESPONSE wrong type
    try:
        app = af.create_app(FSA_ERROR_RESPONSE=True)
        app._fsa._initialize()
        pytest.fail("should have raised an exception")
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, with FSA_ERROR_RESPONSE None
    try:
        app = af.create_app(FSA_ERROR_RESPONSE=None)
        app._fsa._initialize()
        pytest.fail("should have raised an exception")
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, with FSA_ERROR_RESPONSE "bad value"
    try:
        app = af.create_app(FSA_ERROR_RESPONSE="bad value")
        app._fsa._initialize()
        pytest.fail("should have raised an exception")
    except ConfigError as e:
        assert "unexpected FSA_ERROR_RESPONSE" in str(e)
    # again, to trigger a warning for coverage
    def erh(m: str, c: int):
        return Response(m, c, content_type="text/plain")
    app = fsa.Flask("trigger warning", FSA_AUTH="none")
    app._fsa._error_response = erh
    app.config.update(FSA_ERROR_RESPONSE="json", FSA_SECURE=False)
    app._fsa._initialize()
    # check that we take control of flask errors
    app = fsa.Flask("not-implemented",
                    FSA_AUTH="none",
                    FSA_LOGGING_LEVEL=logging.INFO,
                    FSA_ERROR_RESPONSE="json:bad")
    @app.get("/implemented", authz="OPEN")
    def get_implemented():
        raise ErrorResponse("oops", 418)
    with app.test_client() as client:
        res = check(418, client.get("/implemented"))
        assert res.content_type == "application/json"
        assert b'"bad":' in res.data
        res = check(405, client.post("/implemented"))
        assert res.content_type == "application/json"
        assert b'"bad":' in res.data
        res = check(404, client.get("/not-implemented"))
        assert res.content_type == "application/json"
        assert b'"bad":' in res.data

def test_add_headers():
    import AppFact as af
    app = af.create_app(FSA_MODE="debug",
                        FSA_ADD_HEADERS={"Service": "FSA", "Headers": lambda r, _: len(r.headers)})
    @app.get("/heads", authz="OPEN")
    def get_heads():
        return "", 200
    app.add_headers(Now="Maintenant")
    client = app.test_client()
    res = check(200, client.get("/heads"))
    assert "Service" in res.headers and "Headers" in res.headers and "Now" in res.headers
    assert "FSA-Delay" in res.headers and re.match(r"\d+\.\d{6}$", res.headers["FSA-Delay"])

def test_request_hooks():
    def before_bad(req):
        return Response("Ooops!", 555)
    def after_cool(res):
        res.headers["Cool"] = "Calvin"
        return res
    import AppFact as af
    app = af.create_app(FSA_BEFORE_REQUEST=[], FSA_AFTER_REQUEST=[after_cool])
    @app.get("/cool", authz="OPEN")
    def get_cool():
        return "this is cool!", 200
    client = app.test_client()
    res = check(200, client.get("/cool"))
    assert res.data == b"this is cool!"
    assert "Cool" in res.headers and res.headers["Cool"] == "Calvin"
    # add the kill-me before request
    app._fsa._qm._before_requests = [before_bad]
    res = check(555, client.get("/cool"))
    assert res.data == b"Ooops!"

def hello(app: fsa.Flask):
    @app.get("/hello", authz="OPEN")
    def get_hello(name: str):
        return f"Hello {name}!", 200
    with app.test_client() as c:
        res = check(200, c.get("/hello", data={"name": "Calvin"}))
        assert res.data == b"Hello Calvin!"
        check(400, c.get("/hello", data={"nom": "Calvin"}))
        check(400, c.get("/hello", data={"name": "Calvin", "nom": "Hobbes"}))
        res = check(200, c.get("/hello", json={"name": "Hobbes"}))
        assert res.data == b"Hello Hobbes!"
        check(400, c.get("/hello", json={"nom": "Hobbes"}))
        check(400, c.get("/hello", json={"nom": "Calvin", "name": "Hobbes"}))

def test_mode():
    # combine all debug/modes
    for debug in (True, False):
        for mode in ("debug4", "debug3", "debug2", "debug1", "debug", "dev", "prod"):
            hello(fsa.Flask("mode", debug=debug, FSA_AUTH="none", FSA_MODE=mode))
    try:
        app = fsa.Flask("mode", FSA_AUTH="none", FSA_MODE="unexpected")
        app._fsa._initialize()
        pytest.fail("should raise an exception")
    except ConfigError as e:
        assert "FSA_MODE" in str(e)

def test_shadowing(client):
    res = check(200, client.get("/shadow/foo"))
    assert res.data == b"Test: foo Yukon"
    res = check(400, client.get("/shadow/foo", json={"stuff": "bla"}))
    assert b'"stuff"' in res.data
    res = check(400, client.get("/shadow/bla", data={"stuff": "foo"}))
    assert b'"stuff"' in res.data
    res = check(400, client.get("/shadow/foo", json={"lapp": "bla"}))
    assert b'"lapp"' in res.data
    res = check(400, client.get("/shadow/bla", data={"lapp": "foo"}))
    assert b'"lapp"' in res.data
    res = check(200, client.get("/shadow/foo", json={"blup": "Manitoba"}))
    assert res.data == b"Test: foo Manitoba"
    res = check(200, client.get("/shadow/bla", data={"blup": "Quebec"}))
    assert res.data == b"Test: bla Quebec"
    # repeated parameter handling is unclear because of internal dicts
    res = check(200, client.get("/shadow/bla?blup=Manitoba", data={"blup": "Quebec"}))
    assert res.data == b"Test: bla Manitoba"
    res = check(200, client.get("/shadow/bla?blup=Manitoba&blup=Quebec"))
    assert res.data == b"Test: bla Manitoba"

def test_cookie(client):
    client.set_cookie("foo", "bla")
    res = check(200, client.get("/cookie/foo"))
    assert res.data == b"cookie foo: bla, bla: None, bar: foobla"
    client.set_cookie("bla", "foo")
    res = check(200, client.get("/cookie/foo"))
    assert res.data == b"cookie foo: bla, bla: foo, bar: foobla"
    client.set_cookie("bar", "42")
    res = check(200, client.get("/cookie/foo"))
    assert res.data == b"cookie foo: bla, bla: foo, bar: 42"

def test_headers(client):
    res = check(200, client.get("/headers", headers={"HELLO": "World!"}))
    assert res.json["Hello"] == "World!"
    assert "User-Agent" in res.json

def test_user_errors():
    # check that user errors are raised again under FSA_KEEP_USER_ERRORS
    class Oops(Exception):
        pass
    app = fsa.Flask("user-errors", FSA_AUTH="none", FSA_KEEP_USER_ERRORS=True)
    @app.get("/oops", authz="OPEN")
    def get_oops():
        raise Oops("internal error in get_oops!")
    client = app.test_client()
    res = check(500, client.get("/oops"))
    # lengthy flask-generated message
    assert b"The server encountered an internal error" in res.data
    # without rethrow
    app._fsa._keep_user_errors = False
    res = check(500, client.get("/oops"))
    # to-the-point fsa-generated message
    assert b"internal error caught at" in res.data

def test_param_params():
    app = fsa.Flask("pp",
        FSA_MODE="debug4",
        FSA_LOGGING_LEVEL=logging.DEBUG,
        FSA_AUTH="param",
        FSA_PARAM_USER="login",
        FSA_PARAM_PASS="password"
    )

    CALVIN = {"login": "calvin", "password": "hobbes"}

    USERS = {
        "calvin": app.hash_password("hobbes"),
        "hobbes": app.hash_password("calvin"),
    }

    @app.get_user_pass
    def get_user_pass(login: str):
        return USERS[login] if login in USERS else None

    # note: "login" and "password" parameters must be ignored
    @app.post("/log0", authz="AUTH")
    def post_log0():
        return f"current user is {app.get_user()}", 200

    # note: "login" and "password" parameters must be ignored
    @app.post("/log1", authz="AUTH")
    def post_log1(hello: str):
        return f"current user is {app.get_user()}", 200

    @app.post("/log2", authz="AUTH")
    def post_log2(login: fsa.CurrentUser, password: str = "world!"):
        return f"login={login} hello={password}", 200

    @app.post("/log3", authz="AUTH")
    def post_log5(login: str, password: str):
        return f"login={login} password={password}", 200

    client = app.test_client()

    # missing auth parameters
    res = check(401, client.post("/log0", data={}))
    res = check(401, client.post("/log0", data={"login": "calvin"}))
    res = check(401, client.post("/log0", json={"login": "calvin"}))
    res = check(401, client.post("/log0", data={"password": "hobbes"}))
    res = check(401, client.post("/log0", json={"password": "hobbes"}))
    # unexpected "foo" parameter
    res = check(400, client.post("/log0", data={"login": "calvin", "password": "hobbes", "foo": "bla"}))
    res = check(400, client.post("/log0", json={"login": "calvin", "password": "hobbes", "foo": "bla"}))

    # OK
    res = check(200, client.post("/log0", data=CALVIN))
    assert b"current user is calvin" == res.data

def test_file_storage():

    app = fsa.Flask("file-storage", FSA_AUTH="none", FSA_MODE="debug4")

    @app.post("/upload", authz="OPEN")
    def post_upload(file: fsa.FileStorage):
        assert isinstance(file, fsa.FileStorage)
        return f"file={file.filename}", 201

    @app.post("/uploads", authz="OPEN")
    def post_uploads(**kwargs):
        return " ".join(sorted(kwargs.keys())), 201

    @app.post("/mix", authz="OPEN")
    def post_mix(data: int, file: fsa.FileStorage):
        return f"data={data} file={file.filename}", 201

    @app.post("/empty", authz="OPEN")
    def post_empty():
        return "nothing", 200

    @app.post("/optional", authz="OPEN")
    def post_optional(file: fsa.FileStorage|None = None):
        return file.filename if file else "no file"

    client = app.test_client()

    def bfile(contents: bytes, name: str = "foo.txt", ct: str = "text/plain"):
        return (io.BytesIO(contents), name, ct)

    # /upload
    res = check(201, client.post("/upload", data={"file": bfile(b"hello file!\n")}))
    assert b"file=foo.txt" in res.data
    res = check(400, client.post("/upload", data={"stuff": bfile(b"hello stuff!\n")}))
    assert b"parameter \"file\" is missing" in res.data
    res = check(400, client.post("/upload", data={"file": bfile(b"hello file!\n"), "stuff": bfile(b"hello stuff!\n")}))
    assert b"unexpected http parameter \"stuff\"" in res.data
    res = check(400, client.post("/upload", data={"file": "bla.txt"}))
    assert b"parameter \"file\" type error" in res.data

    # /uploads
    res = check(201, client.post("/uploads", data={"foo": bfile(b"hello foo!\n"), "bla": bfile(b"hello bla!\n")}))
    assert b"bla foo" in res.data

    # /mix
    res = check(201, client.post("/mix", data={"data": 42, "file": bfile(b"hello file!\n")}))
    assert b"data=42 file=foo.txt" in res.data
    res = check(400, client.post("/mix", data={"data": bfile(b"hello data!\n"), "file": bfile(b"hello file!\n")}))
    assert b"cannot cast to int" in res.data

    # /empty
    res = check(200, client.post("/empty"))
    assert b"nothing" in res.data
    res = check(400, client.post("/empty", data={"foo": bfile(b"hello foo!\n"), "bla": bfile(b"hello bla!\n")}))
    assert b"unexpected http parameters: bla foo" in res.data

    # /optional
    res = check(200, client.post("/optional", data={"file": bfile(b"hello opt!\n")}))
    assert res.data == b"foo.txt"
    res = check(200, client.post("/optional", data={}))
    assert res.data == b"no file"


def test_param_types():
    app = fsa.Flask("param-types", FSA_AUTH="none", FSA_MODE="debug")

    try:
        @app.post("/list-str", authz="OPEN")
        def post_list_str(ls: typing.List[str]):
            return json(len(ls)), 201
        pytest.fail("should raise a config error")
    except ConfigError as e:
        assert "not callable" in str(e)

    try:
        @app.post("/list", authz="OPEN")
        def post_list(l: typing.List):
            return json(len(l)), 201
        pytest.fail("should raise a config error")
    except ConfigError as e:
        assert "is not callable" in str(e)

    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(i: int = "one"):
            return "no"
        pytest.fail("should raise a config error")
    except ConfigError as e:
        assert "cannot cast" in str(e)

    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(b=False):
            return "no"
        pytest.fail("should raise a config error")
    except ConfigError as e:
        assert "bad type" in str(e)

def test_jsonify_with_generators():
    def gen(i: int):
        for i in range(i):
            yield i
    app = fsa.Flask("json-gen", FSA_AUTH="none")
    @app.get("/json", authz="OPEN")
    def get_json(what: str):
        l = [0, 1, 2]
        res = (l if what == "list" else
               map(lambda i: i+1, l) if what == "map" else
               filter(lambda i: i>0, l) if what == "filter" else
               range(2, 3) if what == "range" else
               gen(2) if what == "gen" else
               None)
        return fsa.jsonify(res), 200
    with app.test_client() as c:
        res = check(200, c.get("/json", data={"what": "list"}))
        assert res.data == b"[0,1,2]\n"
        res = check(200, c.get("/json", data={"what": "map"}))
        assert res.data == b"[1,2,3]\n"
        res = check(200, c.get("/json", data={"what": "filter"}))
        assert res.data == b"[1,2]\n"
        res = check(200, c.get("/json", data={"what": "range"}))
        assert res.data == b"[2]\n"
        res = check(200, c.get("/json", data={"what": "gen"}))
        assert res.data == b"[0,1]\n"


def test_jsonify_with_types():

    class Pair:
        def __init__(self, i, j):
            self._i, self._j = i, j

    class Triplet:
        def __init__(self, i, j, k):
            self._i, self._j, self._k = i, j, k
        def __str__(self):
            return f"/{self._i}-{self._j}-{self._k}/"

    app = fsa.Flask("json",
        FSA_JSON_ALLSTR=True,
        FSA_JSON_CONVERTER={
            complex: lambda c: [c.real, c.imag],
            Pair: lambda p: [p._i, p._j],
        },
        FSA_AUTH="none",
    )

    @app.get("/pair", authz="OPEN")
    def get_pair(i: int, j: int):
        return fsa.jsonify(Pair(i, j))

    @app.get("/triplet", authz="OPEN")
    def get_triplet(i: int, j: int, k: int):
        return fsa.jsonify(Triplet(i, j, k))

    @app.get("/delay", authz="OPEN")
    def get_delay(d: dt.date):
        return fsa.jsonify(d - dt.date.fromisoformat("2020-07-29"))

    @app.get("/rotate", authz="OPEN")
    def get_rotate(c: complex):
        return fsa.jsonify(c * 1j)

    @app.get("/raw", authz="OPEN")
    def get_raw(r: float):
        return fsa.jsonify(r)

    # should just skip
    @app.get("/skip", authz="OPEN")
    def get_skip():
        return fsa.jsonify(Response('["hello", "world!"]', 200, mimetype="application/json"))

    with app.test_client() as c:
        res = check(200, c.get("/pair", json={"i": 18, "j": 42}))
        assert res.json == [18, 42]
        res = check(200, c.get("/triplet", json={"i": 1, "j": 2, "k": 3}))
        assert res.json == "/1-2-3/"
        res = check(200, c.get("/delay", data={"d": "2024-12-15"}))
        assert res.json.startswith("1600 days")
        res = check(200, c.get("/rotate", json={"c": "1+1j"}))
        assert res.json == [-1, 1]
        res = check(200, c.get("/raw", data={"r": 3.14}))
        assert res.json == 3.14
        res = check(200, c.get("/skip"))
        assert res.json == ["hello", "world!"]

def test_pydantic_models():
    import pydantic
    app = fsa.Flask("pyda-1", FSA_AUTH="none")
    # pydantic class
    # FIXME List -> list?
    class Foo(pydantic.BaseModel):
        f0: str
        f1: typing.List[int]
        f2: typing.Tuple[str, float]
    # JSON-like values
    FOO_OK = {"f0": "ok", "f1": [1, 2], "f2": ["hello", 1.0]}
    FOO_KO = {"f0": "ok", "f1": [1, 2]}  # missing f2
    # foo test route
    @app.post("/foo", authz="OPEN")
    def post_foo(f: Foo):
         return {"f": str(f)}, 201
    @app.get("/foo", authz="OPEN")
    def get_foo():
        return fsa.jsonify(Foo(**FOO_OK)), 200
    # pydantic dataclass
    @pydantic.dataclasses.dataclass
    class Bla:
        b0: typing.List[str]
        b1: int
    BLA_OK = {"b0": ["hello", "world"], "b1": 5432}
    BLA_KO = {"b0": [], "b1": "forty-two"}  # bad b1
    # bla test route
    @app.post("/bla", authz="OPEN")
    def post_bla(b: Bla):
        return fsa.jsonify(b), 201
    # standard dataclass
    # NOTE validation is very weak
    import dataclasses
    @dataclasses.dataclass
    class Dim:
        d0: typing.Tuple[str, int]
        d1: int
    # dim values, with a tuple and dict
    DIM_OK = {"d0": ["Calvin", 6], "d1": 5432}
    DIM_OK2 = {"d0": ("Calvin", 6), "d1": 5432}
    DIM_KO = {"d0": {"Calvin": 6}, "d1": 1234}  # bad d0, not detected
    # dim test route
    @app.post("/dim", authz="OPEN")
    def post_dim(d: Dim):
        return fsa.jsonify(d), 201
    # pydantic special parameter
    class Doom(pydantic.BaseModel):
        i: int = 0
        f: float = 0.0
    DOOM = {"i": 1, "f": 1.0}
    app.special_parameter(Doom, lambda _: Doom(**DOOM))
    @app.get("/doom", authz="OPEN")
    def get_doom(d: Doom):
        return fsa.jsonify(d), 200
    # tests
    with app.test_client() as c:
        # Foo
        r = check(201, c.post("/foo", json={"f": FOO_OK}))
        r = check(400, c.post("/foo", json={"f": FOO_KO}))
        assert b"cast error" in r.data
        r = check(400, c.post("/foo", json={"f": 5432}))
        assert b"unexpected value 5432 for dict" in r.data
        r = check(201, c.post("/foo", data={"f": json.dumps(FOO_OK)}))
        r = check(400, c.post("/foo", data={"f": json.dumps(FOO_KO)}))
        assert b"cast error" in r.data
        r = check(400, c.post("/foo", data={"f": 1234}))
        assert b"cast error on 1234" in r.data
        r = check(200, c.get("/foo"))
        assert r.json == FOO_OK
        # Bla
        r = check(201, c.post("/bla", json={"b": BLA_OK}))
        assert r.json == BLA_OK
        r = check(400, c.post("/bla", json={"b": BLA_KO}))
        assert b"cast error on " in r.data
        r = check(400, c.post("/bla", json={"b": True}))
        assert b"unexpected value True for dict" in r.data
        r = check(201, c.post("/bla", data={"b": json.dumps(BLA_OK)}))
        r = check(400, c.post("/bla", data={"b": json.dumps(BLA_KO)}))
        r = check(400, c.post("/bla", json={"b": False}))
        assert b"unexpected value False for dict" in r.data
        # Dim
        r = check(201, c.post("/dim", json={"d": DIM_OK2}))
        assert r.json == DIM_OK
        # r = check(400, c.post("/dim", json={"d": DIM_KO}))
        # assert b"type error on json parameter" in r.data
        r = check(400, c.post("/dim", json={"d": 3.14159}))
        # assert b" for dict" in r.data
        r = check(201, c.post("/dim", data={"d": json.dumps(DIM_OK)}))
        # r = check(400, c.post("/dim", data={"d": json.dumps(DIM_KO)}))
        r = check(400, c.post("/dim", json={"d": 2.78}))
        # assert b" for dict" in r.data
        # Doom
        r = check(200, c.get("/doom"))
        assert r.json == DOOM

def test_special_parameters():
    app = fsa.Flask("specials", FSA_AUTH="none")

    # trigger configuration errors
    try:
        # p must be str
        @app.special_parameter("foo")
        def foo(p: int):
            ...
        pytest.fail("must raise exception")
    except ConfigError as c:
        assert "str" in str(c)

    try:
        # first parameter must be a scalar
        @app.special_parameter("kind")
        def kind(*args):
            ...
        pytest.fail("must raise exception")
    except ConfigError as c:
        assert "kind" in str(c)

    try:
        # there must be a first parameter
        app.special_parameter("bla", lambda: None)
        pytest.fail("must raise exception")
    except ConfigError as c:
        assert "first" in str(c)

    try:
        # second parameter must be special
        @app.special_parameter("fun")
        def fun(p: str, x: str):
            ...
        pytest.fail("must raise exception")
    except ConfigError as c:
        assert "special parameter" in str(c)

    try:
        # not default values on specials
        @app.special_parameter("oops")
        def oops(p: str, user: fsa.CurrentUser = "calvin"):
            ...
        pytest.fail("must raise exception")
    except ConfigError as c:
        assert "default value" in str(c)

    # working cases
    class Foo:
        pass

    @app.special_parameter(Foo)
    def foo(p: str, a: fsa.CurrentApp):
        return isinstance(a, fsa.Flask) and a.name == "specials"

    @app.get("/foo", authz="OPEN")
    def get_foo(f: Foo):
        return fsa.jsonify(f)

    @app.get("/bla", authz="OPEN")
    def get_bla(f: Foo, s: str):
        return {"f": f, "s": s}

    with app.test_client() as c:
        res = check(200, c.get("/foo"))
        assert res.is_json and res.json == True
        res = check(200, c.get("/bla", data={"s": "susie"}))
        assert res.is_json and res.json == {"f": True, "s": "susie"}

def test_multi_400():
    app = fsa.Flask("400", FSA_AUTH="none")

    # special parameter errors
    def throwAny():
        raise Exception("some internal error")
    def throw400():
        raise fsa.ErrorResponse("oops!", 400)
    class ParamAny:
        pass
    class Param400:
        pass
    app.special_parameter(ParamAny, lambda _: throwAny())
    app.special_parameter(Param400, lambda _: throw400())
    # missing stuff
    @app.get("/400", authz="OPEN")
    def get_400(i: int, j: int, f: fsa.FileStorage, p: Param400):
        return "oops 400", 200
    @app.get("/oops", authz="OPEN")
    def get_oops(q: ParamAny):
        return "oops any", 200

    with app.test_client() as c:
        res = check(400, c.get("/400", json={"i": "one", "k": 42}))
        # bad i, missing j and f, unexpected k, bad p
        assert b'"i"' in res.data
        assert b'"j"' in res.data
        assert b'"k"' in res.data
        assert b'"f"' in res.data
        assert b'"p"' in res.data
        # q will fail
        res = check(500, c.get("/oops"))
        assert b'"q"' in res.data

def test_before_exec():
    app = fsa.Flask("after-auth", FSA_MODE="debug2", FSA_AUTH="fake")
    @app.before_exec
    def before_exec(req, login, auth):
        if login == "error":
            raise Exception("we have an error!")
        if login == "susie":
            return Response("susie triggers a teapot", 418)
        log.debug(f"before_exec: {login} by {auth}")
        return
    @app.get("/be", authz="AUTH")
    def get_be():
        return f"get_be for {app.get_user()}", 200
    with app.test_client() as c:
        res = check(200, c.get("/be", data={"LOGIN": "calvin"}))
        assert b"calvin" in res.data
        res = check(500, c.get("/be", data={"LOGIN": "error"}))
        assert b"internal error" in res.data
        res = check(418, c.get("/be", data={"LOGIN": "susie"}))
        assert b"teapot" in res.data

def test_custom_authentication():
    app = fsa.Flask("code-auth", FSA_ERROR_RESPONSE="json:oops", FSA_AUTH=["code"])
    # powerful new authentication scheme
    @app.authentication("code")
    def code_authentication(app, req):
        if "Code" not in req.headers:
            raise fsa.ErrorResponse("Missing Code authentication header", 401, headers={"Oops": "missing Code"})
        return req.headers["Code"]
    @app.get("/hello", authz="AUTH")
    def get_hello(user: fsa.CurrentUser):
        return fsa.jsonify(user), 200
    # tests
    with app.test_client() as c:
        res = check(401, c.get("/hello"))
        assert res.json["oops"] == "Missing Code authentication header"
        assert res.headers["Oops"] == "missing Code"
        res = check(200, c.get("/hello", headers={"Code": "hobbes"}))
        assert res.json == "hobbes"

def test_default_type():
    app = fsa.Flask("default-type",
                    FSA_AUTH="none",
                    FSA_DEFAULT_CONTENT_TYPE="application/xml")
    @app.get("/hello", authz="OPEN")
    def get_hello():
        return fsa.jsonify("hello"), 200
    @app.get("/bonjour", authz="OPEN")
    def get_bonjour():
        return "<x>bonjour</x>", 200
    @app.get("/guttentag", authz="OPEN")
    def get_guttentag():
        return "<X>Gutten Tag</X>"
    @app.get("/ola", authz="OPEN")
    def get_ola():
        return None
    @app.get("/ciao", authz="OPEN")
    def get_ciao():
        return (None, 204)
    with app.test_client() as c:
        res = check(200, c.get("/hello"))
        assert res.json == "hello"
        res = check(200, c.get("/bonjour"))
        assert res.data == b"<x>bonjour</x>"
        assert res.headers["Content-Type"] == "application/xml"
        res = check(200, c.get("/guttentag"))
        assert res.data == b"<X>Gutten Tag</X>"
        assert res.headers["Content-Type"] == "application/xml"
        res = check(200, c.get("/ola"))
        assert res.data == b""
        assert res.headers["Content-Type"] == "text/plain"
        res = check(204, c.get("/ciao"))
        assert res.data == b""
        assert res.headers["Content-Type"] == "text/plain"

def test_group_check():
    app = fsa.Flask("group-check", FSA_AUTH="fake", FSA_GROUP_CHECK={"foo": lambda u: u == "calvin"})
    @app.group_check("bla")
    def group_bla_check(login):
        return login in ("calvin", "hobbes")
    @app.get("/foo", authz="foo")
    def get_foo():
        return "", 200
    @app.get("/bla", authz="bla")
    def get_bla():
        return "", 200
    with app.test_client() as c:
        check(200, c.get("/foo", json={"LOGIN": "calvin"}))
        check(200, c.get("/bla", data={"LOGIN": "calvin"}))
        check(403, c.get("/foo", data={"LOGIN": "hobbes"}))
        check(200, c.get("/bla", json={"LOGIN": "hobbes"}))
    # no way to check for group membership
    app = fsa.Flask("gc2", FSA_AUTH="fake", FSA_AUTHZ_GROUPS=["foo"])
    try:
        @app.get("/foo", authz="foo")
        def get_foo():
            return "should not get there", 200
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "cannot check group foo authz" in str(e)

def test_generics():

    class Stuff(str):
        pass

    app = fsa.Flask("generics", FSA_AUTH="none")

    # simple generics
    @app.get("/l", authz="OPEN")
    def get_l(l: list):
        return f"len: {len(l)}", 200
    @app.get("/ls", authz="OPEN")
    def get_ls(l: list[str]):
        return f"len: {len(l)}", 200
    @app.get("/li", authz="OPEN")
    def get_li(l: list[int]):
        return f"len: {len(l)}", 200
    @app.get("/lf", authz="OPEN")
    def get_lf(l: list[float]):
        return f"len: {len(l)}", 200
    @app.get("/ln", authz="OPEN")
    def get_none(l: list[None]):
        return f"len: {len(l)}", 200
    @app.get("/lS", authz="OPEN")
    def get_lS(l: list[Stuff]):
        assert isinstance(l, list) and all(isinstance(i, Stuff) for i in l)
        return f"len: {len(l)}", 200

    # optionals
    @app.get("/l0s", authz="OPEN")
    def get_l0s(l: list[str]|None = None):
        return "none" if l is None else "list"
    @app.get("/l0s2", authz="OPEN")
    def get_l0s2(l: typing.Optional[list[str]] = None):
        return "none" if l is None else "list"
    @app.get("/l0s3", authz="OPEN")
    def get_l0s3(l: typing.Union[list[str], None] = None):
        return "none" if l is None else "list"

    # dicts
    @app.get("/dsi", authz="OPEN")
    def get_dsi(d: dict[str, int]):
        return f"len: {len(d)}", 200
    @app.get("/dsl", authz="OPEN")
    def get_dsl(d: dict[str, list[int]]):
        return f"len: {len(d)}", 200

    # union
    @app.get("/lsi", authz="OPEN")
    def get_lsi(l: list[str]|list[int]):
        return f"len: {len(l)}", 200

    import datetime as dt
    @app.get("/lD", authz="OPEN")
    def get_lD(l: list[dt.date]):
        return f"len: {len(l)}", 200

    with app.test_client() as c:
        # list[str]
        check(200, c.get("/l", json={"l": ["hello", "world"]}))
        check(200, c.get("/l", json={"l": []}))
        check(200, c.get("/ls", json={"l": ["hello", "world"]}))
        check(200, c.get("/ls", json={"l": []}))
        # NOTE integer 2 is cast to str
        check(200, c.get("/ls", json={"l": ["hello", 2]}))
        check(400, c.get("/ls", json={}))
        check(400, c.get("/ls", json={"l": "a list of strings"}))
        # list[int]
        check(200, c.get("/li", json={"l": [1, 2]}))
        res = check(200, c.get("/li", json={"l": []}))
        assert b"len: 0" in res.data
        check(400, c.get("/li", json={}))
        check(400, c.get("/li", json={"l": [True, 2]}))
        check(400, c.get("/li", json={"l": "a list of ints"}))
        # list[float]
        res = check(200, c.get("/lf", json={"l": [0.0, 1.0, 2.0]}))
        assert b"len: 3" in res.data
        # repeated parameters
        res = check(200, c.get("/ls?l=hello&l=world"))
        assert b"len: 2" in res.data
        res = check(200, c.get("/li?l=1&l=2&l=3"))
        assert b"len: 3" in res.data
        # what about repeated parameters?
        # list[str]|None and variants
        check(200, c.get("/l0s", json={"l": ["hello", "world"]}))
        check(200, c.get("/l0s", json={"l": []}))
        check(200, c.get("/l0s", json={}))
        # feature: 2 -> "2"
        check(200, c.get("/l0s", json={"l": ["hello", 2]}))
        check(400, c.get("/l0s", json={"l": "a list of strings"}))
        check(200, c.get("/l0s2", json={"l": ["hello", "world"]}))
        check(200, c.get("/l0s2", json={"l": []}))
        check(200, c.get("/l0s2", json={}))
        check(200, c.get("/l0s2", json={"l": ["hello", 2]}))
        check(400, c.get("/l0s2", json={"l": "a list of strings"}))
        check(200, c.get("/l0s3", json={"l": ["hello", "world"]}))
        check(200, c.get("/l0s3", json={"l": []}))
        check(200, c.get("/l0s3", json={}))
        check(200, c.get("/l0s3", json={"l": ["hello", 2]}))
        check(400, c.get("/l0s3", json={"l": "a list of strings"}))
        # dict[str, int]
        check(200, c.get("/dsi", json={"d": {"a": 1, "b": 2}}))
        check(200, c.get("/dsi", json={"d": {}}))
        check(400, c.get("/dsi", json={}))
        check(400, c.get("/dsi", json={"d": {"a": 1, "b": 3.14159}}))
        check(400, c.get("/dsi", json={"d": {"a": False, "b": 3}}))
        check(400, c.get("/dsi", json={"d": []}))
        check(400, c.get("/dsi", json={"d": "dict of str to int"}))
        check(400, c.get("/dsi", json={"d": 3.1415927}))
        # dict[str, list[int]]
        check(200, c.get("/dsl", json={"d": {"a": [], "b": [1, 2]}}))
        check(200, c.get("/dsl", json={"d": {}}))
        check(400, c.get("/dsl", json={"d": None}))
        check(400, c.get("/dsl", json={"d": "hello world"}))
        check(400, c.get("/dsl", json={"d": ["hello", "world"]}))
        check(400, c.get("/dsl", json={"d": {"a": [], "b": 1}}))
        check(400, c.get("/dsl", json={"d": {"a": [True], "b": [1, 2]}}))
        check(400, c.get("/dsl", json={"d": {"a": [], "b": [1.5, 2]}}))
        # list[str]|list[int]
        check(200, c.get("/lsi", json={"l": [1, 2, 3]}))
        check(200, c.get("/lsi", json={"l": ["one", "two"]}))
        check(200, c.get("/lsi", json={"l": []}))
        check(400, c.get("/lsi", json={"l": None}))
        check(400, c.get("/lsi", json={"l": True}))
        check(400, c.get("/lsi", json={"l": [1, "two"]}))
        check(400, c.get("/lsi", json={"l": [True, 2.5]}))
        # list[None]
        check(200, c.get("/ln", json={"l": []}))
        check(200, c.get("/ln", json={"l": [None]}))
        check(200, c.get("/ln", json={"l": [None, None, None]}))
        check(400, c.get("/ln", json={"l": "list of nones"}))
        check(400, c.get("/ln", json={"l": [0]}))
        check(400, c.get("/ln", json={"l": ["nope"]}))
        # list[Stuff]
        check(200, c.get("/lS?l=hello&l=world"))
        check(200, c.get("/lS", json={"l": ["hello", "world!"]}))
        # list[Date]
        check(200, c.get("/lD?l=1970-10-14&l=1970-03-20"))
        check(200, c.get("/lD", json={"l": []}))
        check(200, c.get("/lD", json={"l": ["2020-07-29"]}))
        check(400, c.get("/lD", json={"l": ["not-a-valid-date"]}))
    # failures
    app = fsa.Flask("generics", FSA_AUTH="none")
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(l: tuple[str, int]):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "unsupported generic type" in str(e)
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(l: dict[int, int]):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "unsupported generic type" in str(e)
    # TODO should be made to work?
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(l: dict[str, Stuff]):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "unsupported generic type" in str(e)
    # bad default
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(l: list[str] = {}):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "bad check" in str(e)
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(l: list[int] = ["one", "two"]):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "bad check" in str(e)
    # open/current user
    try:
        @app.get("/nope", authz="OPEN")
        def get_nope(user: fsa.CurrentUser):
            ...
        pytest.fail("should not get there")
    except ConfigError as e:
        assert "open" in str(e)


def test_streaming():

    for streaming in (True, False):

        app = fsa.Flask("stream", FSA_AUTH="none", FSA_JSON_STREAMING=streaming)

        @app.get("/stream", authz="OPEN")
        def get_stream(n: int = 3):
            return fsa.jsonify(range(n))

        with app.test_client() as c:
            res = c.get("/stream")
            assert res.status_code == 200
            assert res.json == [0, 1, 2]
            res = c.get("/stream", json={"n": 0})
            assert res.status_code == 200
            assert res.json == []
            res = c.get("/stream", data={"n": 1})
            assert res.status_code == 200
            assert res.json == [0]

def test_mixing():
    # test *non* mixing of http & json

    app = fsa.Flask("mixing", FSA_AUTH="none")
    @app.get("/mixing", authz="OPEN")
    def get_mixing(a: int, b: int):
        return fsa.jsonify(a + b)

    with app.test_client() as c:
        # ok
        res = c.get("/mixing?a=40&b=2")
        assert res.status_code == 200
        assert res.json == 42
        res = c.get("/mixing", data={"a": 39, "b": 3})
        assert res.status_code == 200
        assert res.json == 42
        res = c.get("/mixing", json={"a": 37, "b": 5})
        assert res.status_code == 200
        assert res.json == 42
        # mixing, why not?
        res = c.get("/mixing?a=35", json={"b": 7})
        assert res.status_code == 200
        assert res.json == 42

def run_authorize(predefs, code):

    for a in predefs:

        app = fsa.Flask("auth", FSA_AUTH=["token", "basic", "none"], FSA_ALLOW_DEPRECATION=True)

        @app.get("/route", authz=a)
        def get_route():
            return "", 200

        with app.test_client() as c:
            res = c.get("/route")
            assert res.status_code == code

def test_open():
    run_authorize(fsa._OPEN, 200)

def test_close():
    run_authorize(fsa._CLOSE, 403)

def test_auth():
    run_authorize(fsa._AUTH, 401)

def test_open_auth():
    # OPEN -> AUTH if none is not allowed, for coverage
    # auth list
    app = fsa.Flask("open", FSA_AUTH=["token", "basic"])
    @app.get("/open", authz="OPEN")
    def get_open():
        return {"msg": "open!"}
    # implicit and explicit auth
    app = fsa.Flask("open",
                    FSA_AUTH=["token", "basic", "none"],
                    FSA_AUTH_DEFAULT=["token", "basic"])
    @app.get("/open-1", authz="OPEN")
    def get_open_1():
        return {"msg": "open 1!"}
    @app.get("/open-2", authz="OPEN", authn=["token", "basic"])
    def get_open_2():
        return {"msg": "open 2!"}

def test_auth_close():
    # AUTH -> CLOSE if only none is allowed, for coverage
    app = fsa.Flask("auth", FSA_AUTH="none")
    @app.get("/auth", authz="AUTH")
    def get_auth():
        return {"msg": "auth!"}

def test_optional_params():
    app = fsa.Flask("opt", FSA_AUTH="none", FSA_MODE="debug4")
    # optional simple parameters
    @app.get("/i0", authz="OPEN")
    def get_i0(i: int|None):
        return { "i": i }
    @app.get("/i1", authz="OPEN")
    def get_i1(i: None|int):
        return { "i": i }
    @app.get("/i2", authz="OPEN")
    def get_i2(i: typing.Optional[int]):
        return { "i": i }
    @app.get("/i3", authz="OPEN")
    def get_i3(i: typing.Union[int, None]):
        return { "i": i }
    @app.get("/i4", authz="OPEN")
    def get_i4(i: typing.Union[None, int]):
        return { "i": i }
    def int_eq(i, j):
        return (i is None and j is None) or (isinstance(i, int) and isinstance(j, int) and i == j)
    with app.test_client() as api:
        cnt = 0
        for path in ["/i0", "/i1", "/i2", "/i3", "/i4"]:
            for val in [42, 0, 1, None]:
                for par in ["json", "data"]:
                    if par == "data" and val is None:
                        # there is no representation of None as a raw string.
                        continue
                    cnt += 1
                    param = {par: {"i": val}}
                    log.debug(f"param = {param}")
                    res = api.get(path, **param)
                    assert res.status_code == 200 and res.is_json and "i" in res.json
                    assert int_eq(val, res.json["i"])
        assert cnt == 35

#
# NOTE ldap tests only focus on initializations, we do not have a server for testing
#

LDAP_URL = "ldaps://foo:bla@ldap.server:389/search?login?sub?(objectClass=*)"

def ldap_tests(scheme: str, url: str):
    app = fsa.Flask(
        "ldap client",
         FSA_AUTH="password",
         FSA_PASSWORD_SCHEME=scheme,
         FSA_PASSWORD_OPTS = {"url": url},
    )
    app._fsa._initialize()
    assert app._fsa._am._pm._ldap_auth.url() == LDAP_URL

@pytest.mark.skipif(not has_package("ldap"), reason="ldap is not available")
def test_ldap():
    ldap_tests("ldap", LDAP_URL)

@pytest.mark.skipif(not has_package("ldap3"), reason="ldap3 is not available")
def test_ldap3():
    ldap_tests("ldap3", LDAP_URL)

def test_deprecation():
    # allowed
    app = fsa.Flask("deprecation", FSA_AUTH="password", FSA_ALLOW_DEPRECATION=True)
    @app.get("/all", authorize="ALL")
    def get_all():
        ...
    @app.get("/none", authorize="NONE")
    def get_none():
        ...
    @app.get("/any", authorize="ANY", auth="none")
    def get_any():
        ...
    # blocked
    app = fsa.Flask("deprecation", FSA_AUTH="password", FSA_ALLOW_DEPRECATION=False)
    try:
        @app.get("/authorize", authorize="OPEN", authn="none")
        def get_authorize():
            ...
        pytest.fail("config error must be raised")
    except ConfigError as ce:
        assert "deprecated" in str(ce)
    try:
        @app.get("/auth", authz="OPEN", auth="none")
        def get_auth():
            ...
        pytest.fail("config error must be raised")
    except ConfigError as ce:
        assert "deprecated" in str(ce)
    try:
        @app.get("/all", authz="ALL", auth="none")
        def get_all():
            ...
        pytest.fail("config error must be raised")
    except ConfigError as ce:
        assert "deprecated" in str(ce)
    try:
        @app.get("/any", authz="ANY")
        def get_any():
            ...
        pytest.fail("config error must be raised")
    except ConfigError as ce:
        assert "deprecated" in str(ce)
    try:
        @app.get("/none", authz="NONE")
        def get_none():
            ...
        pytest.fail("config error must be raised")
    except ConfigError as ce:
        assert "deprecated" in str(ce)

@pytest.mark.skipif(not has_package("pyotp"), reason="pyotp is not available")
def test_otp():

    import pyotp

    OTP_SECRETS: dict[str, str] = {
        "susie": "XXFMZAQR5IFQLAWW3O2NY5EXI3GEYKOR",
        "calvin": "6BJ6OS5EMTPEKJ4QBMLIWIGNUNRNNS55",
        "hobbes": "UG76RUVSRZ4SP6JKSYWPJDVPJPD6RLFS",
    }

    app = fsa.Flask("otp",
        FSA_AUTH="password",
        FSA_PASSWORD_SCHEME="fsa:otp",
        FSA_GET_USER_PASS=OTP_SECRETS.get,
    )

    @app.get("/otp", authz="AUTH")
    def get_otp(user: fsa.CurrentUser):
        return {"login": user}

    # no hashing for OTP
    assert app.hash_password("foo") == "foo"

    with app.test_client() as c:
        for u, s in OTP_SECRETS.items():
            check(401, c.get("/otp", headers=basic_auth(u, "badpass")))
            totp = pyotp.TOTP(s)
            res = check(200, c.get("/otp", headers=basic_auth(u, totp.now())))
            assert res.is_json and res.json["login"] == u


def test_path_check():
    app = fsa.Flask("path-check", FSA_AUTH="none", FSA_PATH_CHECK=fsa.checkPath)

    @app.path_check
    def my_path_check(m, p):
        return fsa.checkPath(m, p)

    @app.get("/ok", authz="OPEN")
    def get_ok():
        return "", 200

    try:
        @app.get("/BAD", authz="OPEN")
        def get_BAD():
            ...
        pytest.fail("must reject uppercase path")
    except ConfigError as e:
        assert "path" in str(e)

    try:
        @app.get("/get-something", authz="OPEN")
        def get_get():
            ...
        pytest.fail("must reject method in path")
    except ConfigError as e:
        assert "method" in str(e)
