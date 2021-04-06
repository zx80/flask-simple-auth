# tests with flask

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

def check_200(res):  # ok
    assert res.status_code == 200
    return res

def check_201(res):  # created
    assert res.status_code == 201
    return res

def check_204(res):  # no content
    assert res.status_code == 204
    return res

def check_400(res):  # client error
    assert res.status_code == 400
    return res

def check_401(res):  # authentication required
    assert res.status_code == 401
    return res

def check_403(res):  # forbidden
    assert res.status_code == 403
    return res

def check_404(res):  # not found
    assert res.status_code == 404
    return res

def check_500(res):  # bad
    assert res.status_code == 500
    return res

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

# push/pop auth
app_saved_auth = {}

def push_auth(app, auth, token = None, carrier = None, name = None):
    assert auth in (None, "none", "fake", "basic", "param", "password", "token", "http-token")
    assert token in (None, "fsa", "jwt")
    assert carrier in (None , "bearer", "param", "cookie", "header")
    app_saved_auth.update(a = app._auth, t = app._token, c = app._carrier, n = app._name)
    app._auth, app._token, app._carrier, app._name = auth, token, carrier, name

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
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    pop_auth(app._fsa)
    # user-pass param
    push_auth(app._fsa, "param", "fsa", "param", "auth")
    USERPASS = { "USER": user, "PASS": pswd }
    token_param = json.loads(client.get("login", data=USERPASS).data)
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    pop_auth(app._fsa)
    push_auth(app._fsa, "password", "fsa", "param", "auth")
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    pop_auth(app._fsa)
    # user-pass basic
    push_auth(app._fsa, "basic", "fsa", "param", "auth")
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth(user, pswd)}
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    pop_auth(app._fsa)
    push_auth(app._fsa, "password", "fsa", "param", "auth")
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
    check_200(client.get("/any"))  # open route
    check_401(client.get("/login"))  # login without login
    check_401(client.get("/"))  # empty path
    # admin only
    check_401(client.get("/admin"))
    log.debug(f"App.user_in_group: {App.user_in_group}")
    log.debug(f"app._fsa._user_in_group: {app._fsa._user_in_group}")
    assert App.user_in_group("dad", App.ADMIN)
    assert app._fsa._user_in_group("dad", App.ADMIN)
    all_auth(client, "dad", App.UP["dad"], check_200, "/admin")
    assert not App.user_in_group("calvin", App.ADMIN)
    all_auth(client, "calvin", App.UP["calvin"], check_403, "/admin")
    assert not App.user_in_group("hobbes", App.ADMIN)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/admin")
    assert hasattr(app._fsa._get_jwt_token_auth_real, "cache_clear")
    assert hasattr(app._fsa._user_in_group, "cache_clear")
    assert hasattr(app._fsa._get_user_pass, "cache_clear")
    app.clear_caches()
    # write only
    check_401(client.get("/write"))
    assert app._fsa._user_in_group("dad", App.WRITE)
    all_auth(client, "dad", App.UP["dad"], check_200, "/write")
    assert app._fsa._user_in_group("calvin", App.WRITE)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/write")
    assert not App.user_in_group("hobbes", App.WRITE)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/write")
    # read only
    check_401(client.get("/read"))
    assert not app._fsa._user_in_group("dad", App.READ)
    all_auth(client, "dad", App.UP["dad"], check_403, "/read")
    assert app._fsa._user_in_group("calvin", App.READ)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/read")
    assert App.user_in_group("hobbes", App.READ)
    all_auth(client, "hobbes", App.UP["hobbes"], check_200, "/read")

def test_whatever(client):
    check_401(client.get("/whatever"))
    check_401(client.post("/whatever"))
    check_401(client.put("/whatever"))
    check_401(client.patch("/whatever"))
    check_401(client.delete("/whatever"))
    push_auth(app._fsa, "fake")
    check_404(client.get("/whatever", data={"LOGIN": "dad"}))
    check_404(client.post("/whatever", data={"LOGIN": "dad"}))
    check_404(client.put("/whatever", data={"LOGIN": "dad"}))
    check_404(client.patch("/whatever", data={"LOGIN": "dad"}))
    check_404(client.delete("/whatever", data={"LOGIN": "dad"}))
    pop_auth(app._fsa)

def test_register(client):
    # missing params
    check_400(client.post("/register", data={"user":"calvin"}))
    check_400(client.post("/register", data={"upass":"calvin-pass"}))
    # existing user
    check_403(client.post("/register", data={"user":"calvin", "upass":"calvin-pass"}))
    # new user
    check_201(client.post("/register", data={"user":"susie", "upass":"derkins"}))
    assert App.UP["susie"] == "derkins"
    all_auth(client, "susie", App.UP["susie"], check_403, "/admin")
    all_auth(client, "susie", App.UP["susie"], check_403, "/write")
    all_auth(client, "susie", App.UP["susie"], check_200, "/read")
    # clean-up
    push_auth(app._fsa, "fake")
    check_204(client.delete("/user/susie", data={"LOGIN":"susie"}))
    assert "susie" not in App.UP and "susie" not in App.UHP
    pop_auth(app._fsa)

def test_fsa_token():
    tsave, hsave, app._fsa._token, app._fsa._algo = app._fsa._token, app._fsa._algo, "fsa", "blake2s"
    calvin_token = app.create_token("calvin")
    assert calvin_token[:12] == "Test:calvin:"
    assert app._fsa._get_token_auth(calvin_token) == "calvin"
    app._fsa._token, app._fsa._algo = tsave, hsave

def test_expired_token():
    hobbes_token = app.create_token("hobbes")
    grace, app._fsa._grace = app._fsa._grace, -100
    try:
        user = app._fsa._get_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
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
    user = app._fsa._get_token_auth(moe_token)
    assert user == "moe"
    # pubkey signature scheme
    app._fsa._algo, app._fsa._secret, app._fsa._sign = \
        "RS256", RSA_TEST_PUB_KEY, RSA_TEST_PRIV_KEY
    mum_token = app.create_token("mum")
    assert "." in mum_token and len(mum_token.split(".")) == 3
    user = app._fsa._get_token_auth(mum_token)
    assert user == "mum"
    # cleanup
    app._fsa._token, app._fsa._algo = tsave, hsave
    app._fsa._secret, app._fsa._sign = Ksave, ksave

def test_invalid_token():
    susie_token = app.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = app._fsa._get_token_auth(susie_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_wrong_token():
    realm, app._fsa._realm = app._fsa._realm, "elsewhere"
    moe_token = app.create_token("moe")
    app._fsa._realm = realm
    try:
        user = app._fsa._get_token_auth(moe_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_password_check():
    ref = app.hash_password("hello")
    assert app.check_password("hello", ref)
    assert not app.check_password("bad-pass", ref)

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

def test_self_care(client):
    push_auth(app._fsa, "fake")
    check_401(client.patch("/user/calvin"))
    check_403(client.patch("/user/calvin", data={"LOGIN":"dad"}))
    who, npass, opass = "calvin", "new-calvin-password", App.UP["calvin"]
    check_204(client.patch(f"/user/{who}", data={"oldpass":opass, "newpass":npass, "LOGIN":who}))
    assert App.UP[who] == npass
    check_204(client.patch(f"/user/{who}", data={"oldpass":npass, "newpass":opass, "LOGIN":who}))
    assert App.UP[who] == opass
    check_201(client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"rosalyn"}))  # self
    check_201(client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"dad"}))  # admin
    pop_auth(app._fsa)

def test_typed_params(client):
    res = check_200(client.get("/add/2", data={"a":"2.0", "b":"4.0"}))
    assert float(res.data) == 12.0
    res = check_200(client.get("/mul/2", data={"j":"3", "k":"4"}))
    assert int(res.data) == 24
    check_400(client.get("/mul/1", data={"j":"3"}))
    check_400(client.get("/mul/1", data={"k":"4"}))
    check_400(client.get("/mul/2", data={"j":"three", "k":"four"}))
    # optional
    res = check_200(client.get("/div", data={"i":"10", "j":"3"}))
    assert int(res.data) == 3
    res = check_200(client.get("/div", data={"i":"10"}))
    assert int(res.data) == 0
    res = check_200(client.get("/sub", data={"i":"42", "j":"20"}))
    assert int(res.data) == 22
    check_400(client.get("/sub", data={"j":"42"}))
    res = check_200(client.get("/sub", data={"i":"42"}))
    assert int(res.data) == 42

def test_types(client):
    res = check_200(client.get("/type", data={"f": "1.0"}))
    assert res.data == b"float 1.0"
    res = check_200(client.get("/type", data={"i": "0b11"}))
    assert res.data == b"int 3"
    res = check_200(client.get("/type", data={"i": "0x11"}))
    assert res.data == b"int 17"
    # note: 011 is not accepted as octal
    res = check_200(client.get("/type", data={"i": "0o11"}))
    assert res.data == b"int 9"
    res = check_200(client.get("/type", data={"i": "11"}))
    assert res.data == b"int 11"
    res = check_200(client.get("/type", data={"b": "0"}))
    assert res.data == b"bool False"
    res = check_200(client.get("/type", data={"b": ""}))
    assert res.data == b"bool False"
    res = check_200(client.get("/type", data={"b": "False"}))
    assert res.data == b"bool False"
    res = check_200(client.get("/type", data={"b": "fALSE"}))
    assert res.data == b"bool False"
    res = check_200(client.get("/type", data={"b": "F"}))
    assert res.data == b"bool False"
    res = check_200(client.get("/type", data={"b": "1"}))
    assert res.data == b"bool True"
    res = check_200(client.get("/type", data={"b": "foofoo"}))
    assert res.data == b"bool True"
    res = check_200(client.get("/type", data={"b": "True"}))
    assert res.data == b"bool True"
    res = check_200(client.get("/type", data={"s": "Hello World!"}))
    assert res.data == b"str Hello World!"

def test_params(client):
    res = check_200(client.get("/params", data={"a":1, "b":2, "c":3}))
    assert res.data == b"a b c"

def test_missing(client):
    saved, app._fsa._check = app._fsa._check, True
    check_403(client.get("/mis1"))
    check_403(client.get("/mis2"))
    check_403(client.get("/empty", data={"LOGIN": "dad"}))
    app._fsa._check = False
    # check_200(client.get("/mis1"))
    # check_200(client.get("/mis2"))
    check_403(client.get("/empty", data={"LOGIN": "dad"}))
    app._fsa._check = saved

def test_nogo(client):
    check_403(client.get("/nogo"))

def test_route(client):
    res = check_200(client.get("/one/42", data={"msg":"hello"}))
    assert res.data == b"42: hello !"
    res = check_200(client.get("/one/42", data={"msg":"hello", "punct":"?"}))
    assert res.data == b"42: hello ?"
    check_400(client.get("/one/42"))   # missing "msg"
    check_404(client.get("/one/bad", data={"msg":"hi"}))  # bad "i" type
    check_403(client.get("/two", data={"LOGIN":"calvin"}))

def test_infer(client):
    res = check_200(client.get("/infer/1.000"))
    assert res.data == b"1.0 4"
    res = check_200(client.get("/infer/2.000", data={"i":"2", "s":"hello"}))
    assert res.data == b"2.0 10"

def test_when(client):
    res = check_200(client.get("/when", data={"d": "1970-03-20", "LOGIN": "calvin"}))
    assert b"days" in res.data
    check_400(client.get("/when", data={"d": "not a date", "LOGIN": "calvin"}))
    check_400(client.get("/when", data={"d": "2005-04-21", "t": "not a time", "LOGIN": "calvin"}))

def test_uuid(client):
    u1 = "12345678-1234-1234-1234-1234567890ab"
    u2 = "23456789-1234-1234-1234-1234567890ab"
    res = check_200(client.get(f"/superid/{u1}"))
    check_404(client.get("/superid/not-a-valid-uuid"))
    res = check_200(client.get(f"/superid/{u2}", data={"u": u1}))
    check_400(client.get(f"/superid/{u1}", data={"u": "invalid uuid"}))

def test_complex(client):
    res = check_200(client.get("/cplx", data={"c1": "-1-1j"}))
    assert res.data == b"0j"
    res = check_200(client.get("/cplx/-1j"))
    assert res.data == b"0j"
    check_404(client.get("/cplx/zero"))

def test_bool(client):
    res = check_200(client.get("/bool/1"))
    assert res.data == b"True"
    res = check_200(client.get("/bool/f"))
    assert res.data == b"False"
    res = check_200(client.get("/bool/0"))
    assert res.data == b"False"
    res = check_200(client.get("/bool/hello"))
    assert res.data == b"True"
    check_404(client.get("/bool/"))

def test_mail(client):
    s, h, m = "susie@comics.net", "hobbes@comics.net", "moe@comics.net"
    res = check_200(client.get(f"/mail/{s}"))
    assert b"susie" in res.data and b"calvin" in res.data
    res = check_200(client.get(f"/mail/{h}", data={"ad2": m}))
    assert b"hobbes" in res.data and b"moe" in res.data
    check_404(client.get(f"/mail/bad-email-address"))
    check_400(client.get(f"/mail/{m}", data={"ad2": "bad-email-address"}))

def test_appext(client2):
    check_401(client2.get("/bad"))
    check_500(client2.get("/bad", data={"LOGIN": "dad"}))
    check_401(client2.get("/stuff"))
    res = check_200(client2.get("/stuff", data={"LOGIN": "dad"}))
    assert "auth=" in res.headers["Set-Cookie"]
    # the auth cookie is kept automatically, it seems…
    check_200(client2.get("/stuff"))
    check_500(client2.get("/bad"))
    client2.cookie_jar.clear()
    check_401(client2.get("/stuff"))
    check_401(client2.get("/bad"))

def test_blueprint(client):
    check_401(client.get("/b1/words/foo"))
    res = check_200(client.get("/b1/words/foo", data={"LOGIN": "dad"}))
    assert res.data == b"foo"
    res = check_200(client.get("/b1/words/bla", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bla_bla"
    check_403(client.get("/b1/blue", data={"LOGIN": "dad"}))

def test_blueprint_2(client2):
    check_401(client2.get("/b2/words/foo"))
    res = check_200(client2.get("/b2/words/foo", data={"LOGIN": "dad"}))
    assert res.data == b"foo"
    res = check_200(client2.get("/b2/words/bla", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bla_bla"
    check_403(client2.get("/b2/blue", data={"LOGIN": "dad"}))

def test_appfact(client3):
    check_401(client3.get("/add", data={"i": "7", "j": "2"}))
    res = check_200(client3.get("/add", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"9"
    res = check_200(client3.get("/sub", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"5"
    res = check_200(client3.get("/mul", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"14"
    res = check_200(client3.get("/div", data={"i": "7", "j": "2", "LOGIN": "dad"}))
    assert res.data == b"3"
    res = check_200(client3.get("/div", data={"i": "0xf", "j": "0b10", "LOGIN": "dad"}))
    assert res.data == b"7"
    check_400(client3.get("/add", data={"i": "sept", "j": "deux", "LOGIN": "dad"}))
    check_400(client3.get("/add", data={"i": "7", "LOGIN": "dad"}))
    # blueprint
    check_401(client3.get("/b/word/fun"))
    res = check_200(client3.get("/b/words/fun", data={"LOGIN": "dad"}))
    assert res.data == b"fun"
    res = check_200(client3.get("/b/words/bin", data={"LOGIN": "dad", "n": "2"}))
    assert res.data == b"bin_bin"
    check_403(client3.get("/b/blue", data={"LOGIN": "dad"}))

import Shared

def test_something_1(client):
    Shared.init_app(something="HELLO")
    res = check_200(client.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"HELLO"
    res = check_200(client.get("/b1/something", data={"LOGIN": "dad"}))
    assert res.data == b"HELLO"

def test_something_2(client2):
    Shared.init_app(something="WORLD")
    res = check_200(client2.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"WORLD"
    res = check_200(client2.get("/b2/something", data={"LOGIN": "dad"}))
    assert res.data == b"WORLD"

def test_something_3(client3):
    Shared.init_app(something="CALVIN")
    res = check_200(client3.get("/something", data={"LOGIN": "dad"}))
    assert res.data == b"CALVIN"
    res = check_200(client3.get("/b/something", data={"LOGIN": "dad"}))
    assert res.data == b"CALVIN"

def test_cacheok():
    @fsa.CacheOK
    def randBool(p: str):
        import random
        return random.choice([False, True])
    for c in "abcdefghijklmnopqrstivwxyz":
        v = randBool(c)
        if v:
            for i in range(10):
                assert v == randBool(c)

def test_path(client):
    res = check_200(client.get("/path/foo"))
    assert res.data == b"foo"
    res = check_200(client.get("/path/foo/bla"))
    assert res.data == b"foo/bla"

def test_string(client):
    res = check_200(client.get("/string/foo"))
    assert res.data == b"foo"

def test_reference():
    v1, v2 = "hello!", "world!"
    r1 = fsa.Reference()
    r1.set(v1)
    assert r1 == v1
    r2 = fsa.Reference(set_name="set_object")
    r2.set_object(v2)
    assert r2 == v2

def test_www_authenticate(client):
    push_auth(app._fsa, "param")
    res = check_401(client.get("/admin"))
    assert res.www_authenticate.get("__auth_type__", None) == "param"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "basic")
    res = check_401(client.get("/admin"))
    assert res.www_authenticate.get("__auth_type__", None) == "basic"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "password")
    res = check_401(client.get("/admin"))
    assert res.www_authenticate.get("__auth_type__", None) == "basic"
    assert "realm" in res.www_authenticate
    pop_auth(app._fsa)
    push_auth(app._fsa, "token", "fsa", "bearer", "Hello")
    res = check_401(client.get("/admin"))
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
    check_401(app_basic.get("/basic"))
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth("calvin", "hobbes")}
    res = check_200(app_basic.get("/basic", headers=BASIC))
    assert res.data == b"calvin"

def test_http_digest(app_digest):
    check_401(app_digest.get("/digest"))
    # FIXME how to generate a digest authenticated request with werkzeug is unclear
    # from requests.auth import HTTPDigestAuth as Digest
    # AUTH = Digest("calvin", "hobbes")
    # res = check_200(app_digest.get("/digest", auth=AUTH))
    # assert res.data == b"calvin"

def test_http_token():
    app = aha.create_app_token()
    with app.test_client() as client:
        # http-token default bearer configuration
        check_401(client.get("/token"))
        calvin_token = app.create_token("calvin")
        log.debug(f"token: {calvin_token}")
        TOKEN = {"Authorization": f"Bearer {calvin_token}"}
        res = check_200(client.get("/token", headers=TOKEN))
        assert res.data == b"calvin"
        # check header with http auth
        push_auth(app._fsa, "http-token", "fsa", "header", "HiHiHi")
        app._fsa._http_auth.header = "HiHiHi"
        res = check_200(client.get("/token", headers={"HiHiHi": calvin_token}))
        assert res.data == b"calvin"
        app._fsa._http_auth.header = None
        pop_auth(app._fsa)
        # check header token fallback
        push_auth(app._fsa, "fake", "fsa", "header", "HoHoHo")
        res = check_200(client.get("/token", headers={"HoHoHo": calvin_token}))
        assert res.data == b"calvin"
        pop_auth(app._fsa)
