# tests with flask

import pytest
import App as app
import json

import logging
log = logging.getLogger("tests")

app.auth.log.setLevel(logging.DEBUG)
app.log.setLevel(logging.DEBUG)
log.setLevel(logging.DEBUG)

def test_sanity():
    assert app.app is not None and app.auth is not None
    assert app.app.name == "Test_Application"
    assert app.auth.REALM == "test_application"
    assert "dad" in app.UHP
    assert "calvin" in app.UHP
    assert "hobbes" in app.UHP

@pytest.fixture
def client():
    with app.app.test_client() as c:
        yield c

# test all auth variants
def all_auth(client, user, pswd, check, *args, **kwargs):
    saved = app.auth.AUTH
    # fake login
    app.auth.AUTH = 'fake'
    token = json.loads(client.get("login", data={"LOGIN": user}).data)
    log.debug(f"token: {token}")
    res = client.get(*args, **kwargs, data={"LOGIN": user})
    check(res)
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    # user-pass param
    USERPASS = { "USER": user, "PASS": pswd }
    app.auth.AUTH = 'param'
    res = client.get(*args, **kwargs, data=USERPASS)
    check(res)
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    app.auth.AUTH = 'password'
    res = client.get(*args, **kwargs, data=USERPASS)
    check(res)
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    # user-pass basic
    from requests.auth import _basic_auth_str as basic_auth
    BASIC = { "Authorization": basic_auth(user, pswd)}
    app.auth.AUTH = 'basic'
    res = client.get(*args, **kwargs, headers=BASIC)
    check(res)
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    app.auth.AUTH = 'password'
    res = client.get(*args, **kwargs, headers=BASIC)
    check(res)
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    # token only
    app.auth.AUTH = "token"
    res = client.get(*args, **kwargs, data={"auth": token})
    check(res)
    app.auth.AUTH = saved

def check_200(res):
    assert res.status_code == 200

def check_401(res):
    assert res.status_code == 401

def check_403(res):
    assert res.status_code == 403

def test_perms(client):
    check_200(client.get("/all"))  # open route
    try: 
        client.get("/login")  # no login login
    except app.auth.AuthException as e:
        assert e.status == 401
    # admin only
    check_401(client.get("/admin"))
    log.debug(f"app.is_in_group: {app.is_in_group}")
    log.debug(f"auth.user_in_group: {app.auth.user_in_group}")
    assert app.is_in_group("dad", app.ADMIN)
    assert app.auth.user_in_group("dad", app.ADMIN)
    all_auth(client, "dad", app.UP["dad"], check_200, "/admin")
    assert not app.is_in_group("calvin", app.ADMIN)
    all_auth(client, "calvin", app.UP["calvin"], check_403, "/admin")
    assert not app.is_in_group("hobbes", app.ADMIN)
    all_auth(client, "hobbes", app.UP["hobbes"], check_403, "/admin")
