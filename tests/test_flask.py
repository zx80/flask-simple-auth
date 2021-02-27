# tests with flask

import pytest
import App as app
from App import auth
import json

import logging
log = logging.getLogger("tests")

# auth.log.setLevel(logging.DEBUG)
# app.log.setLevel(logging.DEBUG)
# log.setLevel(logging.DEBUG)

def test_sanity():
    assert app.app is not None and auth is not None
    assert app.app.name == "Test"
    assert auth.REALM == "test"
    assert 'FSA_TYPE' in auth.CONF
    assert "dad" in app.UHP
    assert "calvin" in app.UHP
    assert "hobbes" in app.UHP

@pytest.fixture
def client():
    with app.app.test_client() as c:
        yield c

# test all auth variants
def all_auth(client, user, pswd, check, *args, **kwargs):
    saved = auth.AUTH
    # fake login
    auth.AUTH = 'fake'
    token_fake = json.loads(client.get("login", data={"LOGIN": user}).data)
    check(client.get(*args, **kwargs, data={"LOGIN": user}))
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    # user-pass param
    USERPASS = { "USER": user, "PASS": pswd }
    auth.AUTH = 'param'
    token_param = json.loads(client.get("login", data=USERPASS).data)
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    auth.AUTH = 'password'
    check(client.get(*args, **kwargs, data=USERPASS))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    # user-pass basic
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = { "Authorization": basic_auth(user, pswd)}
    auth.AUTH = 'basic'
    token_basic = json.loads(client.get("login", headers=BASIC).data)
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    auth.AUTH = 'password'
    check(client.get(*args, **kwargs, headers=BASIC))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    # token only
    auth.AUTH = "token"
    check(client.get(*args, **kwargs, data={"auth": token_fake}))
    check(client.get(*args, **kwargs, data={"auth": token_param}))
    check(client.get(*args, **kwargs, data={"auth": token_basic}))
    auth.AUTH = saved

def check_200(res):  # ok
    assert res.status_code == 200

def check_201(res):  # created
    assert res.status_code == 201

def check_204(res):  # no content
    assert res.status_code == 204

def check_400(res):
    assert res.status_code == 400

def check_401(res):
    assert res.status_code == 401

def check_403(res):  # forbidden
    assert res.status_code == 403

def test_perms(client):
    check_200(client.get("/all"))  # open route
    try:
        client.get("/login")  # no login login
    except auth.AuthException as e:
        assert e.status == 401
    # admin only
    check_401(client.get("/admin"))
    log.debug(f"app.is_in_group: {app.is_in_group}")
    log.debug(f"auth.user_in_group: {auth.user_in_group}")
    assert app.is_in_group("dad", app.ADMIN)
    assert auth.user_in_group("dad", app.ADMIN)
    all_auth(client, "dad", app.UP["dad"], check_200, "/admin")
    assert not app.is_in_group("calvin", app.ADMIN)
    all_auth(client, "calvin", app.UP["calvin"], check_403, "/admin")
    assert not app.is_in_group("hobbes", app.ADMIN)
    all_auth(client, "hobbes", app.UP["hobbes"], check_403, "/admin")
    # write only
    check_401(client.get("/write"))
    assert auth.user_in_group("dad", app.WRITE)
    all_auth(client, "dad", app.UP["dad"], check_200, "/write")
    assert auth.user_in_group("calvin", app.WRITE)
    all_auth(client, "calvin", app.UP["calvin"], check_200, "/write")
    assert not app.is_in_group("hobbes", app.WRITE)
    all_auth(client, "hobbes", app.UP["hobbes"], check_403, "/write")
    # read only
    check_401(client.get("/read"))
    assert not auth.user_in_group("dad", app.READ)
    all_auth(client, "dad", app.UP["dad"], check_403, "/read")
    assert auth.user_in_group("calvin", app.READ)
    all_auth(client, "calvin", app.UP["calvin"], check_200, "/read")
    assert app.is_in_group("hobbes", app.READ)
    all_auth(client, "hobbes", app.UP["hobbes"], check_200, "/read")

def test_register(client):
    # missing params
    check_400(client.post("/register", data={"user":"calvin"}))
    check_400(client.post("/register", data={"pass":"calvin-pass"}))
    # existing user
    check_403(client.post("/register", data={"user":"calvin", "pass":"calvin-pass"}))
    # new user
    check_201(client.post("/register", data={"user":"susie", "pass":"derkins"}))
    assert app.UP["susie"] == "derkins"
    all_auth(client, "susie", app.UP["susie"], check_403, "/admin")
    all_auth(client, "susie", app.UP["susie"], check_403, "/write")
    all_auth(client, "susie", app.UP["susie"], check_200, "/read")
    # clean-up
    sauth, auth.AUTH = auth.AUTH, "fake"
    check_204(client.delete("/user/susie", data={"LOGIN":"susie"}))
    auth.AUTH = sauth

def test_token():
    calvin_token = auth.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
    assert auth.get_token_auth(calvin_token) == "calvin"

def test_expired_token():
    hobbes_token = auth.create_token("hobbes")
    grace, auth.GRACE = auth.GRACE, -100
    try:
        user = auth.get_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401
    auth.GRACE = grace

def test_invalid_token():
    susie_token = auth.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = auth.get_token_auth(susie_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401

def test_wrong_token():
    realm, auth.REALM = auth.REALM, "elsewhere"
    moe_token = auth.create_token("moe")
    auth.REALM = realm
    try:
        user = auth.get_token_auth(moe_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401

def test_password_check():
    ref = auth.hash_password("hello")
    assert auth.check_password("hello", ref)
    assert not auth.check_password("bad-pass", ref)

def test_authorize():
    assert auth.user_in_group("dad", app.ADMIN)
    assert not auth.user_in_group("hobbes", app.ADMIN)
    @auth.authorize(app.ADMIN)
    def stuff():
        return "", 200
    auth.USER = "dad"
    _, status = stuff()
    assert status == 200
    auth.USER = "hobbes"
    _, status = stuff()
    assert status == 403
    lazy, auth.LAZY = auth.LAZY, False
    auth.USER = None
    _, status = stuff()
    assert status == 401
    auth.LAZY = lazy

def test_self_care(client):
    saved = app.SET_LOGIN_ACTIVE
    sauth = auth.AUTH
    app.SET_LOGIN_ACTIVE = True
    auth.AUTH = 'fake'
    check_401(client.patch("/user/calvin"))
    check_403(client.patch("/user/calvin", data={"LOGIN":"dad"}))
    who, npass, opass = "calvin", "new-calvin-password", app.UP["calvin"]
    check_204(client.patch(f"/user/{who}", data={"oldpass":opass, "newpass":npass, "LOGIN":who}))
    assert app.UP[who] == npass
    check_204(client.patch(f"/user/{who}", data={"oldpass":npass, "newpass":opass, "LOGIN":who}))
    assert app.UP[who] == opass
    check_201(client.post("/register", data={"user":"rosalyn", "pass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"rosalyn"}))  # self
    check_201(client.post("/register", data={"user":"rosalyn", "pass":"rosa-pass"}))
    check_204(client.delete("user/rosalyn", data={"LOGIN":"dad"}))  # admin
    app.SET_LOGIN_ACTIVE = saved
    auth.AUTH = sauth
