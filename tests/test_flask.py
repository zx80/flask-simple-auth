# tests with flask

import pytest
import App
from App import app
import FlaskSimpleAuth as fsa
import json

import logging
log = logging.getLogger("tests")

# app._fsa_log.setLevel(logging.DEBUG)
# app.log.setLevel(logging.DEBUG)
# log.setLevel(logging.DEBUG)
# app._fsa_initialize()

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
    assert app._fsa_realm == "test"
    assert 'FSA_TYPE' in app.config
    assert "dad" in App.UHP
    assert "calvin" in App.UHP
    assert "hobbes" in App.UHP

@pytest.fixture
def client():
    with App.app.test_client() as c:
        yield c

# test all auth variants on GET
def all_auth(client, user, pswd, check, *args, **kwargs):
    asave, nsave = app._fsa_auth, app._fsa_name
    # fake login
    app._fsa_auth, app._fsa_name = 'fake', 'auth'
    token_fake = json.loads(client.get("login", data={"LOGIN": user}).data)
    check(client.get(*args, **kwargs, data={"LOGIN": user}))
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    # user-pass param
    USERPASS = { "USER": user, "PASS": pswd }
    app._fsa_auth = 'param'
    token_param = json.loads(client.get("login", data=USERPASS).data)
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    app._fsa_auth = 'password'
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    # user-pass basic
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = {"Authorization": basic_auth(user, pswd)}
    app._fsa_auth = 'basic'
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    app._fsa_auth = 'password'
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    # token only
    app._fsa_auth = "token"
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    app._fsa_name = None
    bearer = lambda t: {"Authorization": "Bearer " + t}
    log.debug(f"token_fake = {token_fake}")
    check(client.get(*args, **kwargs, headers=bearer(token_fake)))
    check(client.get(*args, **kwargs, headers=bearer(token_param)))
    check(client.get(*args, **kwargs, headers=bearer(token_basic)))
    app._fsa_auth, app._fsa_name = asave, nsave

def test_perms(client):
    check_200(client.get("/all"))  # open route
    check_401(client.get("/login"))  # login without login
    check_401(client.get("/"))  # empty path
    # admin only
    check_401(client.get("/admin"))
    log.debug(f"App.is_in_group: {App.is_in_group}")
    log.debug(f"app._fsa_user_in_group: {app._fsa_user_in_group}")
    assert App.is_in_group("dad", App.ADMIN)
    assert app._fsa_user_in_group("dad", App.ADMIN)
    all_auth(client, "dad", App.UP["dad"], check_200, "/admin")
    assert not App.is_in_group("calvin", App.ADMIN)
    all_auth(client, "calvin", App.UP["calvin"], check_403, "/admin")
    assert not App.is_in_group("hobbes", App.ADMIN)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/admin")
    # write only
    check_401(client.get("/write"))
    assert app._fsa_user_in_group("dad", App.WRITE)
    all_auth(client, "dad", App.UP["dad"], check_200, "/write")
    assert app._fsa_user_in_group("calvin", App.WRITE)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/write")
    assert not App.is_in_group("hobbes", App.WRITE)
    all_auth(client, "hobbes", App.UP["hobbes"], check_403, "/write")
    # read only
    check_401(client.get("/read"))
    assert not app._fsa_user_in_group("dad", App.READ)
    all_auth(client, "dad", App.UP["dad"], check_403, "/read")
    assert app._fsa_user_in_group("calvin", App.READ)
    all_auth(client, "calvin", App.UP["calvin"], check_200, "/read")
    assert App.is_in_group("hobbes", App.READ)
    all_auth(client, "hobbes", App.UP["hobbes"], check_200, "/read")

def test_whatever(client):
    check_401(client.get("/whatever"))
    check_401(client.post("/whatever"))
    check_401(client.put("/whatever"))
    check_401(client.patch("/whatever"))
    check_401(client.delete("/whatever"))
    saved, app._fsa_auth = app._fsa_auth, 'fake'
    check_404(client.get("/whatever", data={"LOGIN": "dad"}))
    check_404(client.post("/whatever", data={"LOGIN": "dad"}))
    check_404(client.put("/whatever", data={"LOGIN": "dad"}))
    check_404(client.patch("/whatever", data={"LOGIN": "dad"}))
    check_404(client.delete("/whatever", data={"LOGIN": "dad"}))
    app._fsa_auth = saved

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
    sauth, app._fsa_auth = app._fsa_auth, "fake"
    check_204(client.delete("/user/susie", data={"LOGIN":"susie"}))
    assert "susie" not in App.UP and "susie" not in App.UHP
    app._fsa_auth = sauth

def test_fsa_token():
    tsave, hsave, app._fsa_type, app._fsa_hash = app._fsa_type, app._fsa_hash, "fsa", "blake2s"
    calvin_token = app.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
    assert app._fsa_get_token_auth(calvin_token) == "calvin"
    app._fsa_type, app._fsa_hash = tsave, hsave

def test_expired_token():
    hobbes_token = app.create_token("hobbes")
    grace, app._fsa_grace = app._fsa_grace, -100
    try:
        user = app._fsa_get_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401
    app._fsa_grace = grace

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
    tsave, hsave, app._fsa_type, app._fsa_hash = app._fsa_type, app._fsa_hash, "jwt", "HS256"
    Ksave, ksave = app._fsa_secret, app._fsa_sign
    # hmac signature scheme
    moe_token = app.create_token("moe")
    assert "." in moe_token and len(moe_token.split(".")) == 3
    user = app._fsa_get_token_auth(moe_token)
    assert user == "moe"
    # pubkey signature scheme
    app._fsa_hash = "RS256"
    app._fsa_secret = RSA_TEST_PUB_KEY
    app._fsa_sign = RSA_TEST_PRIV_KEY
    mum_token = app.create_token("mum")
    assert "." in mum_token and len(mum_token.split(".")) == 3
    user = app._fsa_get_token_auth(mum_token)
    assert user == "mum"
    # cleanup
    app._fsa_type, app._fsa_hash = tsave, hsave
    app._fsa_secret, app._fsa_sign = Ksave, ksave

def test_invalid_token():
    susie_token = app.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = app._fsa_get_token_auth(susie_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_wrong_token():
    realm, app._fsa_realm = app._fsa_realm, "elsewhere"
    moe_token = app.create_token("moe")
    app._fsa_realm = realm
    try:
        user = app._fsa_get_token_auth(moe_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_password_check():
    ref = app.hash_password("hello")
    assert app.check_password("hello", ref)
    assert not app.check_password("bad-pass", ref)

def test_authorize():
    assert app._fsa_user_in_group("dad", App.ADMIN)
    assert not app._fsa_user_in_group("hobbes", App.ADMIN)
    @app._fsa_authorize(App.ADMIN)
    def stuff():
        return "", 200
    app._fsa_user = "dad"
    _, status = stuff()
    assert status == 200
    app._fsa_user = "hobbes"
    _, status = stuff()
    assert status == 403
    lazy, app._fsa_lazy = app._fsa_lazy, False
    app._fsa_user = None
    _, status = stuff()
    assert status == 401
    app._fsa_lazy = lazy

def test_self_care(client):
    saved, app._fsa_auth = app._fsa_auth, 'fake'
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
    app._fsa_auth = saved

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
    saved, app._fsa_check = app._fsa_check, True
    check_500(client.get("/mis1"))
    check_500(client.get("/mis2"))
    app._fsa_check = False
    check_200(client.get("/mis1"))
    check_200(client.get("/mis2"))
    app._fsa_check = saved

def test_nogo(client):
    check_403(client.get("/nogo"))

def test_route(client):
    res = check_200(client.get("/one/42", data={"msg":"hello"}))
    assert res.data == b"42: hello !"
    res = check_200(client.get("/one/42", data={"msg":"hello", "punct":"?"}))
    assert res.data == b"42: hello ?"
    check_400(client.get("/one/42"))   # missing "msg"
    check_404(client.get("/one/bad", data={"msg":"hi"}))  # bad "i" type
    check_500(client.get("/two", data={"LOGIN":"calvin"}))

def test_infer(client):
    res = check_200(client.get("/infer/1.000"))
    assert res.data == b"1.0 4"
    res = check_200(client.get("/infer/2.000", data={"i":"2", "s":"hello"}))
    assert res.data == b"2.0 10"
