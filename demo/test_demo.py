#
# NON REGRESSION TESTS FOR DEMO APP
#

import pytest
from app import app

import base64
import json

import logging
# logging.basicConfig()  # done in app
log = logging.getLogger("test")
log.setLevel(logging.DEBUG)


# authentication for tests
def basic(login, upass):
    return {"Authorization": b"Basic " + base64.b64encode(bytes(login, "utf-8") + b":" + bytes(upass, "utf-8"))}

# 2 predefined admins
FOO_BASIC = basic("foo", "bla")
BLA_BASIC = basic("bla", "foo")

# temporary users for testing
TMP_BASIC = basic("tmp", "tmp")
TMP_BASIC_2 = basic("tmp", "TMP")

@pytest.fixture
def client():
    with app.test_client() as c:
        yield c

# check that a request returned the expected result
def check(status, res):
    assert res.status_code == status
    return res

# GET /now
def test_now(client):
    res = check(200, client.get("/now"))
    assert b"2" in res.data  # okay, this test breaks on year 3000 :-)
    check(405, client.post("/now"))
    check(405, client.put("/now"))
    check(405, client.patch("/now"))
    check(405, client.delete("/now"))
    check(405, client.trace("/now"))

# GET /who
def test_who(client):
    res = check(200, client.get("/who"))
    assert b"null" in res.data
    res = check(200, client.get("/who", headers=FOO_BASIC))
    assert b"\"foo\"" in res.data
    check(405, client.post("/who"))
    check(405, client.put("/who"))
    check(405, client.patch("/who"))
    check(405, client.delete("/who"))
    check(405, client.trace("/who"))

# GET /version
def test_version(client):
    res = check(200, client.get("/version"))
    assert b"." in res.data

# GET /stuff helper
def get_stuff_id(client, stuff):
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    # assert stuff in res.data
    for t in json.loads(res.data):
        if t[1] == stuff:
            return t[0]
    return None

# GET POST DELETE PATCH /stuff
def test_stuff(client):
    res = check(401, client.get("/stuff"))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Hello" in res.data
    res = check(201, client.post("/stuff", data={"sname": "STUFF"}, headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"STUFF" in res.data
    sn = get_stuff_id(client, "STUFF")
    assert sn is not None
    res = check(200, client.get(f"/stuff/{sn}", headers=FOO_BASIC))
    assert b"STUFF" in res.data
    check(404, client.get(f"/stuff/0", headers=FOO_BASIC))
    check(204, client.delete(f"/stuff/{sn}", headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"STUFF" not in res.data
    check(204, client.patch("/stuff/1", json={"sname": "Calvin"}, headers=BLA_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Calvin" in res.data and b"Hello" not in res.data
    check(204, client.patch("/stuff/1", json={"sname": "Hello"}, headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Hello" in res.data and b"World" in res.data and b"Calvin" not in res.data
    res = check(200, client.get("/stuff", data={"pattern": "H%"}, headers=FOO_BASIC))
    assert b"Hello" in res.data and b"World" not in res.data

# GET, POST, PATCH, DELETE /scare (self-care)
def test_scare(client):
    res = check(200, client.get("/scare", headers=FOO_BASIC))
    assert b"foo" in res.data and b"bla" not in res.data
    res = check(200, client.get("/scare", headers=BLA_BASIC))
    assert b"bla" in res.data and b"foo" not in res.data
    res = check(200, client.get("/scare/token", headers=FOO_BASIC))
    assert b"demo:foo:" in res.data
    foo_token = json.loads(res.data)
    res = check(200, client.get("/scare", data={"auth": foo_token}))
    assert b"foo" in res.data
    res = check(200, client.get("/scare", json={"auth": foo_token}))
    assert b"foo" in res.data
    bad_token = foo_token[:-1] + "z"
    check(401, client.get("/scare", data={"auth": bad_token}))
    check(401, client.get("/stuff", headers=TMP_BASIC))
    check(201, client.post("/scare", data={"login": "tmp", "pass": "tmp"}, headers=FOO_BASIC))
    res = check(200, client.get("/scare", headers=TMP_BASIC))
    assert b"tmp" in res.data
    check(401, client.patch("/scare", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC_2))
    check(204, client.patch("/scare", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC))
    res = check(401, client.get("/scare", headers=TMP_BASIC))
    res = check(200, client.get("/scare", headers=TMP_BASIC_2))
    assert b"tmp" in res.data
    check(401, client.patch("/scare", data={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC))
    check(204, client.patch("/scare", data={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC_2))
    # rejected password changes
    check(400, client.patch("/scare", data={"opass": "tmp", "npass": "a"}, headers=TMP_BASIC))
    check(400, client.patch("/scare", data={"opass": "tmp", "npass": "!.?"}, headers=TMP_BASIC))
    # cleanup
    check(204, client.delete("/scare", headers=TMP_BASIC))
    check(401, client.get("/scare", headers=TMP_BASIC))

# GET POST PATCH DELETE /users 
def test_users(client):
    res = check(200, client.get("/users", headers=FOO_BASIC))
    assert b"foo" in res.data and b"bla" in res.data
    res = check(200, client.get("/users/foo", headers=BLA_BASIC))
    assert b"foo" in res.data and b"bla" not in res.data
    check(401, client.get("/stuff/1", headers=TMP_BASIC))
    check(201, client.post("/users", data={"login": "tmp", "pass": "tmp", "admin": False}, headers=FOO_BASIC))
    check(200, client.get("/stuff/1", headers=TMP_BASIC))
    check(403, client.get("/users", headers=TMP_BASIC))
    check(204, client.patch("/users/tmp", data={"admin": True}, headers=FOO_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC))
    check(204, client.patch("/users/tmp", data={"pass": "TMP"}, headers=FOO_BASIC))
    check(401, client.get("/users", headers=TMP_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC_2))
    check(204, client.delete("/users/tmp", headers=FOO_BASIC))
    check(404, client.get("/users/tmp", headers=FOO_BASIC))
