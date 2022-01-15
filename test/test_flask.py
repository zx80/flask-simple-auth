# tests with flask
#
# FIXME tests are not perfectly isolated as they should be…
#

import pytest
import App
from App import app

import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import Response
import json

import AppExt

import logging
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
    with af.create_app().test_client() as c:
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

def test_perms(client):
    check(200, client.get("/any"))  # open route
    check(401, client.get("/login"))  # login without login
    check(401, client.get("/"))  # empty path
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
    assert hasattr(app._fsa._get_jwt_token_auth, "cache_clear")
    assert hasattr(app._fsa._get_fsa_token_auth, "cache_clear")
    assert hasattr(app._fsa._user_in_group, "cache_clear")
    assert hasattr(app._fsa._get_user_pass, "cache_clear")
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
    check(401, client.get("/whatever"))
    check(401, client.post("/whatever"))
    check(401, client.put("/whatever"))
    check(401, client.patch("/whatever"))
    check(401, client.delete("/whatever"))
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
    calvin_token = app.create_token("calvin")
    assert calvin_token[:12] == "Test:calvin:"
    assert app._fsa._get_any_token_auth(calvin_token) == "calvin"
    # bad timestamp format
    try:
        user = app._fsa._get_any_token_auth("R:U:demain:signature")
        assert False, "expecting a bad timestamp format"
    except Exception as e:
        assert "unexpected timestamp format" in str(e)
    # force expiration
    grace = app._fsa._grace
    app._fsa._grace = -1000000
    try:
        user = app._fsa._get_any_token_auth(calvin_token)
        assert False, "token must have expired"
    except fsa.FSAException as e:
        assert "expired auth token" in e.message
    # again after clear cache, so the expiration is detected at fsa level
    app.clear_caches()
    try:
        user = app._fsa._get_any_token_auth(calvin_token)
        assert False, "token must have expired"
    except fsa.FSAException as e:
        assert "expired fsa auth token" in e.message
    # cleanup
    app._fsa._grace = grace
    app._fsa._token, app._fsa._algo = tsave, hsave
    hobbes_token = app.create_token("hobbes")
    grace, app._fsa._grace = app._fsa._grace, -100
    try:
        user = app._fsa._get_any_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except fsa.FSAException as e:
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
    moe_token = app.create_token("moe")
    assert "." in moe_token and len(moe_token.split(".")) == 3
    user = app._fsa._get_any_token_auth(moe_token)
    assert user == "moe"
    # again for caching
    user = app._fsa._get_any_token_auth(moe_token)
    assert user == "moe"
    # expired token
    delay, grace = app._fsa._delay, app._fsa._grace
    app._fsa._delay, app._fsa._grace = -1, 0
    susie_token = app.create_token("susie")
    assert len(susie_token.split(".")) == 3
    try:
        user = app._fsa._get_any_token_auth(susie_token)
        assert False, "expired token should fail"
    except fsa.FSAException as e:
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
    except fsa.FSAException as e:
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
    except fsa.FSAException as e:
        assert e.status == 401
    # wrong token
    realm, app._fsa._realm = app._fsa._realm, "elsewhere"
    moe_token = app.create_token("moe")
    app._fsa._realm = realm
    try:
        user = app._fsa._get_any_token_auth(moe_token)
        assert False, "token should be invalid"
    except fsa.FSAException as e:
        assert e.status == 401

def test_password_check(client):
    app._fsa._init_password_manager()
    ref = app.hash_password("hello")
    assert app.check_password("hello", ref)
    assert not app.check_password("bad-pass", ref)
    push_auth(app._fsa, ["password"])
    res = check(401, client.get("/read", data={"USER": "dad", "PASS": "bad-dad-password"}))
    assert b"invalid password for" in res.data
    res = check(401, client.get("/read", data={"USER": "dad"}))
    assert b"missing password parameter" in res.data
    pop_auth(app._fsa)
    push_auth(app._fsa, ["basic"])
    res = check(401, client.get("/read", headers={"Authorization": "Basic !!!"}))
    assert b"decoding error on authorization" in res.data
    pop_auth(app._fsa)
    pm = app._fsa._pm
    app._fsa._pm = None
    app.config.update(FSA_PASSWORD_SCHEME = "plaintext")
    app._fsa._init_password_manager()
    assert app.hash_password("hello") == "hello"
    app._fsa._pm = pm

def test_authorize():
    assert app._fsa._user_in_group("dad", App.ADMIN)
    assert not app._fsa._user_in_group("hobbes", App.ADMIN)
    @app._fsa._authorize(App.ADMIN)
    def stuff():
        return Response("", 200)
    app._fsa._user = "dad"
    res = stuff()
    assert res.status_code == 200
    app._fsa._user = "hobbes"
    res = stuff()
    assert res.status_code == 403
    mode, app._fsa._mode = app._fsa._mode, "always"
    app._fsa._user = None
    res = stuff()
    assert res.status_code == 401
    app._fsa._mode = mode
    try:
        @app._fsa._authorize(fsa.ALL, fsa.ANY)
        def foo():
            return "foo", 200
        assert False, "cannot mix ALL & ANY in authorize"
    except Exception as e:
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
    res = check(200, client.get("/mul/2", data={"j":"3", "k":"4"}))
    assert int(res.data) == 24
    res = check(200, client.get("/mul/2", json={"j":"5", "k":"4"}))
    assert int(res.data) == 40
    check(400, client.get("/mul/1", data={"j":"3"}))
    check(400, client.get("/mul/1", data={"k":"4"}))
    check(400, client.get("/mul/2", data={"j":"three", "k":"four"}))
    check(400, client.get("/mul/2", json={"j":"three", "k":"four"}))
    # optional
    res = check(200, client.get("/div", data={"i":"10", "j":"3"}))
    assert int(res.data) == 3
    res = check(200, client.get("/div", json={"i":"100", "j":"4"}))
    assert int(res.data) == 25
    res = check(200, client.get("/div", data={"i":"10"}))
    assert int(res.data) == 0
    res = check(200, client.get("/sub", data={"i":"42", "j":"20"}))
    assert int(res.data) == 22
    check(400, client.get("/sub", data={"j":"42"}))
    res = check(200, client.get("/sub", data={"i":"42"}))
    assert int(res.data) == 42

def test_types(client):
    res = check(200, client.get("/type", data={"f": "1.0"}))
    assert res.data == b"float 1.0"
    res = check(200, client.get("/type", data={"i": "0b11"}))
    assert res.data == b"int 3"
    res = check(200, client.get("/type", data={"i": "0x11"}))
    assert res.data == b"int 17"
    res = check(200, client.get("/type", json={"i": "0x11"}))
    assert res.data == b"int 17"
    # note: 011 is not accepted as octal
    res = check(200, client.get("/type", data={"i": "0o11"}))
    assert res.data == b"int 9"
    res = check(200, client.get("/type", data={"i": "11"}))
    assert res.data == b"int 11"
    res = check(200, client.get("/type", json={"i": "11"}))
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
    saved, app._fsa._check = app._fsa._check, True
    check(403, client.get("/mis1"))
    check(403, client.get("/mis2"))
    check(403, client.get("/empty", data={"LOGIN": "dad"}))
    app._fsa._check = False
    # check(200, client.get("/mis1"))
    # check(200, client.get("/mis2"))
    check(403, client.get("/empty", data={"LOGIN": "dad"}))
    app._fsa._check = saved

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
    check(404, client.get("/cplx/zero"))

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
    check(404, client.get(f"/mail/bad-email-address"))
    check(400, client.get(f"/mail/{m}", data={"ad2": "bad-email-address"}))
    res = check(200, client.get("/myint/5432"))
    assert b"my_int: 5432" in res.data

def test_appext(client2):
    check(401, client2.get("/bad"))
    check(500, client2.get("/bad", data={"LOGIN": "dad"}))
    check(401, client2.get("/stuff"))
    res = check(200, client2.get("/stuff", data={"LOGIN": "dad"}))
    assert "auth=" in res.headers["Set-Cookie"]
    # the auth cookie is kept automatically, it seems…
    check(200, client2.get("/stuff"))
    check(500, client2.get("/bad"))
    client2.cookie_jar.clear()
    check(401, client2.get("/stuff"))
    check(401, client2.get("/bad"))

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
    check(401, client3.get("/b/word/fun"))
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

def test_401_redirect(client):
    app._fsa._401_redirect = "/login-page"
    res = check(307, client.get("/auth/fake"))
    assert "/login-page" in res.location
    app._fsa._url_name = "URL"
    res = check(307, client.get("/auth/fake"))
    assert "/login-page" in res.location and "URL" in res.location and "fake" in res.location
    app._fsa._401_redirect = None
    app._fsa._url_name = None

def test_path(client):
    res = check(200, client.get("/path/foo"))
    assert res.data == b"foo"
    res = check(200, client.get("/path/foo/bla"))
    assert res.data == b"foo/bla"

def test_string(client):
    res = check(200, client.get("/string/foo"))
    assert res.data == b"foo"

def test_reference():
    v1, v2 = "hello!", "world!"
    r1 = fsa.Reference()
    r1.set(v1)
    assert r1 == v1
    r2 = fsa.Reference(set_name="set_object")
    r2.set_object(v2)
    assert r2 == v2
    r3 = fsa.Reference("1")
    assert r3 == "1" and r3 != "one"
    assert "0" < r3 and "1" <= r3 and "2" > r3 and "1" >= r3
    assert "1".__hash__() == r3.__hash__()
    assert repr("1") == repr(r3)

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
    mode, app._fsa._mode = app._fsa._mode, "all"
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
    # cleanup
    app._fsa._mode = mode

def test_bad_app():
    from AppBad import create_app
    # working versions, we basically test that there is no exception
    app = create_app(FSA_AUTH="basic")
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
    except Exception:
        assert True, "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH=["fake", "basic", "bad"])
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    try:
        app = create_app(auth="bad")
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    try:
        app = create_app(auth=["basic", "token", "bad"])
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    # bad token type
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="bad")
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE=None)
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    # bad token carrier
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bad")
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER=None)
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    # bad token name
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_CARRIER="bearer", FSA_TOKEN_NAME=None)
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"
    # bad jwt talgorithm
    try:
        app = create_app(FSA_AUTH="token", FSA_TOKEN_TYPE="jwt", FSA_TOKEN_ALGO="bad")
        assert False, "bad app creation must fail"
    except Exception:
        assert True, "ok, bad app creation has failed"

class PK():
    def __init__(self, kind):
        self.kind = kind

def test_typeof():
    import inspect
    P = inspect.Parameter
    assert fsa.typeof(PK(P.VAR_KEYWORD)) == dict
    assert fsa.typeof(PK(P.VAR_POSITIONAL)) == list

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
    assert b"internal error on GET /any" == res.data
    check(404, bad4.get("/no-such-route"))
