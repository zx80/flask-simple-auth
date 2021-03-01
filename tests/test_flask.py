# tests with flask

import pytest
import App as app
from App import fsa
import json

import logging
log = logging.getLogger("tests")

# fsa.log.setLevel(logging.DEBUG)
# app.log.setLevel(logging.DEBUG)
# log.setLevel(logging.DEBUG)

def check_200(res):  # ok
    assert res.status_code == 200

def check_201(res):  # created
    assert res.status_code == 201

def check_204(res):  # no content
    assert res.status_code == 204

def check_400(res):  # client error
    assert res.status_code == 400

def check_401(res):  # authentication required
    assert res.status_code == 401

def check_403(res):  # forbidden
    assert res.status_code == 403

def check_404(res):  # not found
    assert res.status_code == 404

def test_sanity():
    assert app.app is not None and fsa is not None
    assert app.app.name == "Test"
    assert fsa.REALM == "test"
    assert 'FSA_TYPE' in fsa.CONF
    assert "dad" in app.UHP
    assert "calvin" in app.UHP
    assert "hobbes" in app.UHP

@pytest.fixture
def client():
    with app.app.test_client() as c:
        yield c

# test all auth variants on GET
def all_auth(client, user, pswd, check, *args, **kwargs):
    saved = fsa.AUTH
    # fake login
    fsa.AUTH = 'fake'
    token_fake = json.loads(client.get("login", data={"LOGIN": user}).data)
    check(client.get(*args, **kwargs, data={"LOGIN": user}))
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    # user-pass param
    USERPASS = { "USER": user, "PASS": pswd }
    fsa.AUTH = 'param'
    token_param = json.loads(client.get("login", data=USERPASS).data)
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    fsa.AUTH = 'password'
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    # user-pass basic
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = { "Authorization": basic_auth(user, pswd)}
    fsa.AUTH = 'basic'
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    fsa.AUTH = 'password'
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    # token only
    fsa.AUTH = "token"
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    fsa.AUTH = saved

def test_perms(client):
    check_200(client.get("/all"))  # open route
    check_401(client.get("/login"))  # login without login
    check_401(client.get("/"))  # empty path
    # admin only
    check_401(client.get("/admin"))
    log.debug(f"app.is_in_group: {app.is_in_group}")
    log.debug(f"fsa.user_in_group: {fsa.user_in_group}")
    assert app.is_in_group("dad", app.ADMIN)
    assert fsa.user_in_group("dad", app.ADMIN)
    all_auth(client, "dad", app.UP["dad"], check_200, "/admin")
    assert not app.is_in_group("calvin", app.ADMIN)
    all_auth(client, "calvin", app.UP["calvin"], check_403, "/admin")
    assert not app.is_in_group("hobbes", app.ADMIN)
    all_auth(client, "hobbes", app.UP["hobbes"], check_403, "/admin")
    # write only
    check_401(client.get("/write"))
    assert fsa.user_in_group("dad", app.WRITE)
    all_auth(client, "dad", app.UP["dad"], check_200, "/write")
    assert fsa.user_in_group("calvin", app.WRITE)
    all_auth(client, "calvin", app.UP["calvin"], check_200, "/write")
    assert not app.is_in_group("hobbes", app.WRITE)
    all_auth(client, "hobbes", app.UP["hobbes"], check_403, "/write")
    # read only
    check_401(client.get("/read"))
    assert not fsa.user_in_group("dad", app.READ)
    all_auth(client, "dad", app.UP["dad"], check_403, "/read")
    assert fsa.user_in_group("calvin", app.READ)
    all_auth(client, "calvin", app.UP["calvin"], check_200, "/read")
    assert app.is_in_group("hobbes", app.READ)
    all_auth(client, "hobbes", app.UP["hobbes"], check_200, "/read")

def test_whatever(client):
    check_401(client.get("/whatever"))
    check_401(client.post("/whatever"))
    check_401(client.put("/whatever"))
    check_401(client.patch("/whatever"))
    check_401(client.delete("/whatever"))
    saved, fsa.AUTH = fsa.AUTH, 'fake'
    check_404(client.get("/whatever", data={"LOGIN": "dad"}))
    check_404(client.post("/whatever", data={"LOGIN": "dad"}))
    check_404(client.put("/whatever", data={"LOGIN": "dad"}))
    check_404(client.patch("/whatever", data={"LOGIN": "dad"}))
    check_404(client.delete("/whatever", data={"LOGIN": "dad"}))
    fsa.AUTH = saved

def test_register(client):
    # missing params
    check_400(client.post("/register", data={"user":"calvin"}))
    check_400(client.post("/register", data={"upass":"calvin-pass"}))
    # existing user
    check_403(client.post("/register", data={"user":"calvin", "upass":"calvin-pass"}))
    # new user
    check_201(client.post("/register", data={"user":"susie", "upass":"derkins"}))
    assert app.UP["susie"] == "derkins"
    all_auth(client, "susie", app.UP["susie"], check_403, "/admin")
    all_auth(client, "susie", app.UP["susie"], check_403, "/write")
    all_auth(client, "susie", app.UP["susie"], check_200, "/read")
    # clean-up
    sauth, fsa.AUTH = fsa.AUTH, "fake"
    check_204(client.delete("/user/susie", data={"LOGIN":"susie"}))
    assert "susie" not in app.UP and "susie" not in app.UHP
    fsa.AUTH = sauth

def test_token():
    calvin_token = fsa.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
    assert fsa.get_token_auth(calvin_token) == "calvin"

def test_expired_token():
    hobbes_token = fsa.create_token("hobbes")
    grace, fsa.GRACE = fsa.GRACE, -100
    try:
        user = fsa.get_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401
    fsa.GRACE = grace

def test_invalid_token():
    susie_token = fsa.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = fsa.get_token_auth(susie_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_wrong_token():
    realm, fsa.REALM = fsa.REALM, "elsewhere"
    moe_token = fsa.create_token("moe")
    fsa.REALM = realm
    try:
        user = fsa.get_token_auth(moe_token)
        assert False, "token should be invalid"
    except fsa.AuthException as e:
        assert e.status == 401

def test_password_check():
    ref = fsa.hash_password("hello")
    assert fsa.check_password("hello", ref)
    assert not fsa.check_password("bad-pass", ref)

def test_authorize():
    assert fsa.user_in_group("dad", app.ADMIN)
    assert not fsa.user_in_group("hobbes", app.ADMIN)
    @fsa.authorize(app.ADMIN)
    def stuff():
        return "", 200
    fsa.USER = "dad"
    _, status = stuff()
    assert status == 200
    fsa.USER = "hobbes"
    _, status = stuff()
    assert status == 403
    lazy, fsa.LAZY = fsa.LAZY, False
    fsa.USER = None
    _, status = stuff()
    assert status == 401
    fsa.LAZY = lazy

def test_self_care(client):
    saved, fsa.AUTH = fsa.AUTH, 'fake'
    check_401(client.patch("/user/calvin"))
    check_403(client.patch("/user/calvin", data={"LOGIN":"dad"}))
    who, npass, opass = "calvin", "new-calvin-password", app.UP["calvin"]
    check_204(client.patch(f"/user/{who}", data={"oldpass":opass, "newpass":npass, "LOGIN":who}))
    assert app.UP[who] == npass
    check_204(client.patch(f"/user/{who}", data={"oldpass":npass, "newpass":opass, "LOGIN":who}))
    assert app.UP[who] == opass
    check_201(client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"rosalyn"}))  # self
    check_201(client.post("/register", data={"user":"rosalyn", "upass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"dad"}))  # admin
    fsa.AUTH = saved

def test_typed_params(client):
    res = client.get("/add/2", data={"a":"2.0", "b":"4.0"})
    check_200(res)
    assert float(res.data) == 12.0
    res = client.get("/mul/2", data={"j":"3", "k":"4"})
    check_200(res)
    assert int(res.data) == 24
    check_400(client.get("/mul/1", data={"j":"3"}))
    check_400(client.get("/mul/1", data={"k":"4"}))
    check_400(client.get("/mul/2", data={"j":"three", "k":"four"}))
    # optional
    res = client.get("/div", data={"i":"10", "j":"3"})
    check_200(res)
    assert int(res.data) == 3
    res = client.get("/div", data={"i":"10"})
    check_200(res)
    assert int(res.data) == 0
