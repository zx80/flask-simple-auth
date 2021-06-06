import pytest
from app import app

import base64
import json

import logging
# logging.basicConfig()
log = logging.getLogger()
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

def check(status, res):
    assert res.status_code == status
    return res

def test_now(client):
    res = check(200, client.get("/now"))
    assert b"2" in res.data

def get_stuff_id(client, stuff):
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    # assert stuff in res.data
    for t in json.loads(res.data):
        if t[1] == "STUFF":
            return t[0]
    return None

def test_stuff(client):
    res = check(401, client.get("/stuff"))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Hello" in res.data
    res = check(201, client.post("/stuff", data={"sname": "STUFF"}, headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"STUFF" in res.data
    sn = get_stuff_id(client, b"STUFF")
    assert sn is not None
    check(204, client.delete(f"/stuff/{sn}", headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"STUFF" not in res.data
    check(204, client.patch("/stuff/1", json={"sname": "Calvin"}, headers=BLA_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Calvin" in res.data
    assert b"Hello" not in res.data
    check(204, client.patch("/stuff/1", json={"sname": "Hello"}, headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Hello" in res.data
    assert b"Calvin" not in res.data

def test_care(client):
    res = check(200, client.get("/self", headers=FOO_BASIC))
    assert b"foo" in res.data
    assert b"bla" not in res.data
    res = check(200, client.get("/self", headers=BLA_BASIC))
    assert b"bla" in res.data
    assert b"foo" not in res.data
    check(401, client.get("/stuff", headers=TMP_BASIC))
    check(201, client.post("/self", data={"login": "tmp", "upass": "tmp"}, headers=FOO_BASIC))
    res = check(200, client.get("/self", headers=TMP_BASIC))
    assert b"tmp" in res.data
    check(401, client.patch("/self", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC_2))
    check(204, client.patch("/self", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC))
    res = check(401, client.get("/self", headers=TMP_BASIC))
    res = check(200, client.get("/self", headers=TMP_BASIC_2))
    assert b"tmp" in res.data
    check(401, client.patch("/self", json={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC))
    check(204, client.patch("/self", json={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC_2))
    check(204, client.delete("/self", headers=TMP_BASIC))
    res = check(401, client.get("/self", headers=TMP_BASIC))

# TODO test_users