#
# NON REGRESSION TESTS FOR DEMO APP
#

import pytest
from app import app

import base64
import json
import jwt
import re

import logging

# logging.basicConfig()  # done in app
log = logging.getLogger("test")
log.setLevel(logging.DEBUG)


# authentication for tests
def basic(login, upass):
    return {
        "Authorization": b"Basic " + base64.b64encode(bytes(login, "utf-8") + b":" + bytes(upass, "utf-8"))
    }


# NOTE jwt does not seem to allow generating at+jwt type header
def gen_jwt(sub: str, aud: str, iss: str, delay: int, scope: str, secret: str):
    import datetime as dt

    now = int(dt.datetime.now(tz=dt.timezone.utc).timestamp())
    payload = {
        "sub": sub,
        "aud": aud,
        "iss": iss,
        "iat": now,
        "nbf": now,
        "exp": now + delay,
        "scope": scope,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


# 2 predefined admins
FOO_BASIC = basic("foo", "bla")
BLA_BASIC = basic("bla", "foo")

# temporary users for testing
TMP_BASIC = basic("tmp", "tmp")
TMP_BASIC_2 = basic("tmp", "TMP")
TMP_BASIC_3 = basic("tmp@somewhere.org", "tmp")
TMP_BASIC_4 = basic("tmp@somewhere.org", "TMP")

# JWT secrets
JWT_SECRET = "demo application secret for signing tokens"
JWT_CALVIN_RWD = gen_jwt(
    "calvin", "demo", "fabien", 3600, "read write delete", JWT_SECRET
)
JWT_CALVIN_RW = gen_jwt("calvin", "demo", "fabien", 3600, "read write", JWT_SECRET)
JWT_CALVIN_R = gen_jwt("calvin", "demo", "fabien", 3600, "read", JWT_SECRET)

CALVIN_RWD = {"Authorization": "Bearer " + JWT_CALVIN_RWD}
CALVIN_RW = {"Authorization": "Bearer " + JWT_CALVIN_RW}
CALVIN_R = {"Authorization": "Bearer " + JWT_CALVIN_R}


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
    assert b'"foo"' in res.data
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
    assert "WWW-Authenticate" in res.headers
    assert "Basic" in res.headers["WWW-Authenticate"]
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"Hello" in res.data
    res = check(201, client.post("/stuff", data={"sname": "STUFF"}, headers=FOO_BASIC))
    res = check(200, client.get("/stuff", headers=FOO_BASIC))
    assert b"STUFF" in res.data
    sn = get_stuff_id(client, "STUFF")
    assert sn is not None
    res = check(200, client.get(f"/stuff/{sn}", headers=FOO_BASIC))
    assert b"STUFF" in res.data
    check(404, client.get("/stuff/0", headers=FOO_BASIC))
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
    if app._fsa._token == "fsa":
        assert b"demo:foo:" in res.data
    foo_token = json.loads(res.data)
    if app._fsa._carrier == "param":
        res = check(200, client.get("/scare", data={"AUTH": foo_token}))
        assert b"foo" in res.data
        res = check(200, client.get("/scare", json={"AUTH": foo_token}))
        assert b"foo" in res.data
        bad_token = foo_token[:-1] + "z"
        check(401, client.get("/scare", data={"AUTH": bad_token}))
    check(401, client.get("/stuff", headers=TMP_BASIC))
    check(
        201,
        client.post(
            "/scare",
            data={"login": "tmp", "email": "tmp@somewhere.org", "pass": "tmp"},
            headers=FOO_BASIC,
        ),
    )
    res = check(200, client.get("/scare", headers=TMP_BASIC))
    assert b"tmp" in res.data
    check(
        401,
        client.patch(
            "/scare", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC_2
        ),
    )
    check(
        204,
        client.patch(
            "/scare", json={"opass": "tmp", "npass": "TMP"}, headers=TMP_BASIC
        ),
    )
    res = check(401, client.get("/scare", headers=TMP_BASIC))
    res = check(200, client.get("/scare", headers=TMP_BASIC_2))
    assert b"tmp" in res.data
    check(
        401,
        client.patch(
            "/scare", data={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC
        ),
    )
    check(
        204,
        client.patch(
            "/scare", data={"opass": "TMP", "npass": "tmp"}, headers=TMP_BASIC_2
        ),
    )
    # rejected password changes
    check(
        400,
        client.patch("/scare", data={"opass": "tmp", "npass": "a"}, headers=TMP_BASIC),
    )
    check(
        400,
        client.patch(
            "/scare", data={"opass": "tmp", "npass": "!.?"}, headers=TMP_BASIC
        ),
    )
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
    check(
        201,
        client.post(
            "/users",
            data={
                "login": "tmp",
                "email": "tmp@somewhere.org",
                "pass": "tmp",
                "admin": False,
            },
            headers=FOO_BASIC,
        ),
    )
    check(200, client.get("/stuff/1", headers=TMP_BASIC))
    check(200, client.get("/stuff/1", headers=TMP_BASIC_3))
    check(403, client.get("/users", headers=TMP_BASIC))
    check(403, client.get("/users", headers=TMP_BASIC_3))
    check(403, client.get("/users/foo", headers=TMP_BASIC))  # not self!
    check(200, client.get("/users/tmp", headers=TMP_BASIC))  # self!
    check(204, client.patch("/users/tmp", data={"admin": True}, headers=FOO_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC_3))
    check(204, client.patch("/users/tmp", data={"pass": "TMP"}, headers=FOO_BASIC))
    check(401, client.get("/users", headers=TMP_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC_2))
    check(401, client.get("/users", headers=TMP_BASIC_3))
    check(200, client.get("/users", headers=TMP_BASIC_4))
    check(
        204,
        client.patch(
            "/users/tmp", data={"email": "tmp2@somewhere.org"}, headers=FOO_BASIC
        ),
    )
    check(200, client.get("/users", headers=TMP_BASIC_2))
    check(401, client.get("/users", headers=TMP_BASIC))
    check(401, client.get("/users", headers=TMP_BASIC_3))
    check(401, client.get("/users", headers=TMP_BASIC_4))
    check(204, client.delete("/users/tmp", headers=FOO_BASIC))
    check(404, client.get("/users/tmp", headers=FOO_BASIC))


def test_types(client):
    # scalars
    res = check(200, client.get("/types/scalars", data={"i": 1}))
    assert b"i=1," in res.data
    res = check(200, client.get("/types/scalars", json={"i": 1}))
    assert b"i=1," in res.data
    res = check(200, client.get("/types/scalars", data={"f": 2.0}))
    assert b"f=2.0," in res.data
    res = check(200, client.get("/types/scalars", json={"f": 2.0}))
    assert b"f=2.0," in res.data
    res = check(200, client.get("/types/scalars", data={"b": "True"}))
    assert b"b=True," in res.data
    res = check(200, client.get("/types/scalars", json={"b": True}))
    assert b"b=True," in res.data
    # json stuff
    res = check(200, client.get("/types/json", data={"j": '[false, 1, 2.0, "Three"]'}))
    assert b"list: [False, 1, 2.0, 'Three']" in res.data
    res = check(200, client.get("/types/json", json={"j": [True, 0x2, 3.00, "Four"]}))
    assert b"list: [True, 2, 3.0, 'Four']" in res.data
    res = check(200, client.get("/types/json", json={"j": {"ff": 0xFF}}))
    assert b"dict: {'ff': 255}" in res.data
    # constrained type
    res = check(200, client.get("/types/nat", json={"i": 17, "j": 25}))
    assert res.data == b"42\n"
    res = check(400, client.get("/types/nat", json={"i": -17, "j": -25}))
    assert b"-17" in res.data and b"-25" in res.data
    # pydantic model
    CALVIN = {"name": "Calvin", "age": 6}
    ERROR = {"name": "Error", "age": "twelve"}
    res = check(201, client.post("/types/char", json={"char": CALVIN}))
    assert b"Calvin" in res.data
    res = check(400, client.post("/types/char", json={"char": ERROR}))
    assert b"type error on json parameter \"char\"" in res.data
    # pydantic dataclass
    res = check(201, client.post("/types/pers", json={"pers": CALVIN}))
    assert b"Calvin" in res.data
    res = check(400, client.post("/types/pers", json={"pers": ERROR}))
    assert b"type error on json parameter \"pers\"" in res.data


def test_jwt_oauth(client):
    if not app._fsa._token == "jwt":
        pytest.skip("test needs jwt tokens")
    check(
        201,
        client.post(
            "/users",
            data={
                "login": "calvin",
                "email": "calvin@comics.net",
                "pass": "hobbes",
                "admin": False,
            },
            headers=FOO_BASIC,
        ),
    )
    check(401, client.delete("/oauth"))
    # log.debug(f"header: {CALVIN_R}")
    check(200, client.get("/oauth", headers=CALVIN_R))
    check(200, client.get("/oauth", headers=CALVIN_RW))
    check(200, client.get("/oauth", headers=CALVIN_RWD))
    check(403, client.patch("/oauth", json={"email": "calvin@comics.org"}, headers=CALVIN_R))
    check(204, client.patch("/oauth", json={"email": "calvin@comics.org"}, headers=CALVIN_RW))
    check(204, client.patch("/oauth", json={"email": "calvin@comics.net"}, headers=CALVIN_RWD))
    check(403, client.delete("/oauth", headers=CALVIN_R))
    check(403, client.delete("/oauth", headers=CALVIN_RW))
    # final request detroys test user "calvin"
    check(204, client.delete("/oauth", headers=CALVIN_RWD))


def test_upload(client):
    import io
    res = check(201, client.post("/upload", data={"file": (io.BytesIO(b"Hello World!\n"), "hello.txt")}, headers=FOO_BASIC))
    assert re.search(r" [0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\.tmp", str(res.data))


def test_mfa(client):
    if not app._fsa._token == "fsa":
        pytest.skip("test needs fsa tokens")
    check(401, client.get("/mfa/login1"))
    # FIRST PASS
    res = check(200, client.get("/mfa/login1", headers=FOO_BASIC))
    token1 = json.loads(res.data)
    assert token1.startswith("mfa:foo:")
    # SECOND PASS (FSA token with "param" carrier)
    check(401, client.get("/mfa/login2"))
    check(401, client.get("/mfa/login2", headers=FOO_BASIC))
    check(401, client.get("/mfa/login2", data={"AUTH": "mfa:foo:20500729123456:deadbeef"}))
    check(400, client.get("/mfa/login2", data={"AUTH": token1}))
    check(401, client.get("/mfa/login2", data={"AUTH": token1, "code": "bla-code"}))
    res = check(200, client.get("/mfa/login2", data={"AUTH": token1, "code": "foo-code"}))
    token2 = json.loads(res.data)
    assert token2.startswith("demo:foo:")
    check(401, client.get("/mfa/test", data={"AUTH": token1}))
    res = check(200, client.get("/mfa/test", data={"AUTH": token2}))
