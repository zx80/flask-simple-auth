#
# NON REGRESSION TESTS FOR DEMO APP
#
# NOTE these could be simplified with FlaskTester
#

import os
import re
import base64
import json
import jwt
import logging
import pytest
from app import app

# logging.basicConfig()  # done in app
log = logging.getLogger("test")
log.setLevel(logging.DEBUG)

# authentication for tests
def basic(login, upass):
    encoded = base64.b64encode(f"{login}:{upass}".encode("UTF8"))
    return {"Authorization": f"Basic {encoded.decode('ascii')}"}

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
FOO_SECRET = "FOOSECRETFOOSECRET"
BLA_BASIC = basic("bla", "foo")
BLA_SECRET = "BLASECRETBLASECRET"
TMP_SECRET = "TMPSECRETTMPSECRET"

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
    # token auth
    if app._fsa._am._tm._token == "fsa":
        assert b"demo:foo:" in res.data
    foo_token = json.loads(res.data)
    if app._fsa._am._tm._carrier == "param":
        res = check(200, client.get("/scare", data={"AUTH": foo_token}))
        assert b"foo" in res.data
        res = check(200, client.get("/scare", json={"AUTH": foo_token}))
        assert b"foo" in res.data
        bad_token = foo_token[:-1] + "z"
        check(401, client.get("/scare", data={"AUTH": bad_token}))
    # does not exist yet, created afterwards
    check(401, client.get("/stuff", headers=TMP_BASIC))
    check(
        201,
        client.post(
            "/scare",
            data={"login": "tmp", "email": "tmp@somewhere.org", "pass": "tmp", "secret": TMP_SECRET},
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
    # cleanup, possibly with an auth token
    tmp_token = json.loads(check(200, client.get("/scare/token", headers=TMP_BASIC)).data)
    if app._fsa._am._tm._carrier == "param":
        check(204, client.delete("/scare", json={"AUTH": tmp_token}))
    else:
        check(204, client.delete("/scare", headers=TMP_BASIC))
    # this check that the cache was somehow cleaned up
    check(401, client.get("/scare", headers=TMP_BASIC))
    check(401, client.get("/scare", headers=TMP_BASIC_2))
    check(401, client.get("/scare", headers=TMP_BASIC_3))
    check(401, client.get("/scare", headers=TMP_BASIC_4))

# GET POST PATCH DELETE /users
def test_users(client):
    res = check(200, client.get("/users", headers=FOO_BASIC))
    assert b"foo" in res.data and b"bla" in res.data
    res = check(200, client.get("/users/foo", headers=BLA_BASIC))
    assert b"foo" in res.data and b"bla" not in res.data
    # tmp re-created on the next call
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
                "secret": TMP_SECRET,
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
    # switch tmp to admin
    check(204, client.patch("/users/tmp", data={"admin": True}, headers=FOO_BASIC))
    check(200, client.get("/users", headers=TMP_BASIC))
    # if cached: check(403, client.get("/users", headers=TMP_BASIC_3))
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
    # cleanup
    check(204, client.delete("/users/tmp", headers=FOO_BASIC))
    check(404, client.get("/users/tmp", headers=FOO_BASIC))

def test_auth(client):
    import model
    res = check(200, client.get("/auth", headers=FOO_BASIC))
    assert res.is_json and isinstance(res.json, list) and len(res.json) >= 2
    foo_aid = check(200, client.get("/auth/foo", headers=FOO_BASIC)).json["aid"]
    assert isinstance(foo_aid, int)
    # new tmp user
    tmp = model.User(login="tmp", upass="tmp", email="tmp@somewhere.fr", admin=True, secret=TMP_SECRET)
    assert tmp.aid is None
    res_aid = check(201, client.post("/auth", json={"user": tmp}, headers=FOO_BASIC)).json
    tmp.aid = res_aid["aid"]
    tmp_get = check(200, client.get("/auth/tmp", headers=TMP_BASIC)).json
    assert isinstance(tmp_get, dict) and len(tmp_get) == 6
    tmp2 = model.User(**tmp_get)
    tmp.upass = tmp2.upass  # override non encoded password field
    assert tmp == tmp2
    # auto-update tmp
    tmp2.upass = "TMP"
    tmp2.admin = False
    check(204, client.put(f"/auth/{tmp.aid}", json={"user": tmp2}, headers=TMP_BASIC))
    # test new password and no-admin perms!
    check(403, client.put(f"/auth/{tmp.aid}", json={"user": tmp2}, headers=TMP_BASIC_2))
    # cleanup
    check(204, client.delete("/auth/tmp", headers=FOO_BASIC))
    # more errors
    check(405, client.patch("/auth/foo", headers=FOO_BASIC))
    check(401, client.get("/auth/foo", headers=TMP_BASIC))

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
    assert b"cast error" in res.data
    # pydantic dataclass
    res = check(201, client.post("/types/pers", json={"pers": CALVIN}))
    assert b"Calvin" in res.data
    res = check(400, client.post("/types/pers", json={"pers": ERROR}))
    assert b"cast error" in res.data
    res = check(400, client.get("/types/ls", json={"ls": ["hello", 2]}))
    assert b"expecting list" in res.data
    res = check(200, client.get("/types/ls", json={"ls": ["hello", "world"]})).json
    assert res["len"] == 2 and res["all"] == "hello/world"

def test_jwt_oauth(client):
    if not app._fsa._am._tm._token == "jwt":
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
                "secret": "HOBBESSECRET2345"
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
    res = check(201,
        client.post("/upload",
                    data={"file": (io.BytesIO(b"Hello World!\n"), "hello.txt")},
                    headers=FOO_BASIC)
    )
    assert re.search(r" [0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\.tmp", str(res.data))

@pytest.mark.skipif(os.environ["DATABASE"] != "postgres", reason="test requires postgres")
def test_mfa_code(client):
    if not app._fsa._am._tm._token == "fsa":
        pytest.skip("test needs fsa tokens")
    check(401, client.get("/mfa/login"))
    # FIRST PASS
    res = check(200, client.get("/mfa/login", headers=FOO_BASIC))
    token1 = res.json
    assert isinstance(token1, str) and token1.startswith("mfa:foo:")
    # SECOND PASS (FSA token with "param" carrier)
    check(401, client.post("/mfa/code"))
    check(401, client.post("/mfa/code", headers=FOO_BASIC))
    check(401, client.post("/mfa/code", data={"AUTH": "mfa:foo:20500729123456:deadbeef"}))
    check(400, client.post("/mfa/code", data={"AUTH": token1}))
    check(401, client.post("/mfa/code", data={"AUTH": token1, "code": "bla-code"}))
    # working temporary code
    code = open("./foo_code.txt").read()
    res = check(200, client.post("/mfa/code", data={"AUTH": token1, "code": code}))
    token2 = res.json
    assert isinstance(token2, str) and token2.startswith("demo:foo:")
    check(200, client.get("/mfa/test", data={"AUTH": token2}))
    # code replay attack
    check(401, client.post("/mfa/code", data={"AUTH": token1, "code": code}))
    # bad tokens
    check(401, client.get("/mfa/test", data={"AUTH": "mfa:foo:20500729123456:deadbeef"}))
    check(401, client.get("/mfa/test", data={"AUTH": token1}))

@pytest.mark.skipif(os.environ["DATABASE"] != "postgres", reason="test requires postgres")
def test_mfa_otp(client):
    if not app._fsa._am._tm._token == "fsa":
        pytest.skip("test needs fsa tokens")
    import pyotp
    check(401, client.get("/mfa/login"))
    # FIRST PASS
    res = check(200, client.get("/mfa/login", headers=BLA_BASIC))
    token1 = res.json
    assert isinstance(token1, str) and token1.startswith("mfa:bla:")
    # SECOND PASS (FSA token with "param" carrier)
    check(401, client.post("/mfa/totp"))
    check(401, client.post("/mfa/totp", headers=BLA_BASIC))
    check(401, client.post("/mfa/totp", data={"AUTH": "mfa:foo:20500729123456:deadbeef"}))
    check(400, client.post("/mfa/totp", data={"AUTH": token1}))
    check(401, client.post("/mfa/totp", data={"AUTH": token1, "otp": "abcdef"}))
    DIGITS = int(os.environ.get("OTP_DIGITS", 6))
    code = pyotp.TOTP(BLA_SECRET, digits=DIGITS).now()
    # working OTP
    res = check(200, client.post("/mfa/totp", data={"AUTH": token1, "otp": code}))
    token2 = res.json
    assert isinstance(token2, str) and token2.startswith("demo:bla:")
    check(200, client.get("/mfa/test", data={"AUTH": token2}))
    # OTP replay attack
    check(401, client.post("/mfa/totp", data={"AUTH": token1, "otp": code}))
    # bad tokens
    check(401, client.get("/mfa/test", data={"AUTH": "mfa:bla:20500729123456:deadbeef"}))
    check(401, client.get("/mfa/test", data={"AUTH": token1}))
