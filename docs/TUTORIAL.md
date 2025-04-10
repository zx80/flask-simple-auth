# FlaskSimpleAuth Tutorial

In this tutorial, you will build a secure
[REST](https://en.wikipedia.org/wiki/REST)
[HTTP](https://en.wikipedia.org/wiki/HTTP)
[Python](https://python.org/)
[WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)
back end using
[FlaskSimpleAuth](https://pypi.org/project/flasksimpleauth), a
[Flask](https://flask.palletsprojects.com/) extension.
It will feature basic and parameter password **authentication** (who is the
user?), as well as group and object **authorizations** (permissions associated
to the authenticated *who*).
This is not very different from starting a Flask project, *but* if you start
with Flask you will have to unlearn things as FlaskSimpleAuth framework extends
and simplifies Flask on key points.

This tutorial assumes a working knowledge of the HTTP protocol in a REST
API context, intermediate level programming in `Python`, and interacting from a
terminal with a shell.
It should work with Python 3.1x on Unix (Linux, MacOS) and possibly Windows with
[WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux).
It is advisable to use a version control tool such as `git` to commit the
tutorial state after each section.
Feel free to report any issue with this tutorial by opening a ticket on the
project GitHub.

## Application Setup

Let us first create a minimal running REST application back end *without*
authentication and authorizations.  
Create and activate a Python virtual environment in a new directory, from a
shell terminal:

```shell
python --version  # must show 3.1x
mkdir fsa-tuto
cd fsa-tuto
python -m venv venv
source venv/bin/activate
pip install FlaskSimpleAuth[password]
```

Using your favorite text editor, create in the `fsa-tuto` directory the `app.py`
file with an open (unauthenticated) `GET /hello` route.
The `authz` route parameter is **mandatory** to declare
authorization requirements on the route.
If not set, the route would be closed (aka 403).

```python
# File "app.py"
# necessary for debug messages to show up…
import logging
logging.basicConfig()

# Flask initialization
import FlaskSimpleAuth as fsa
app = fsa.Flask("acme")
app.config.from_envvar("ACME_CONFIG")

# TODO LATER MORE INITIALIZATIONS

# GET /hello route, not authenticated
@app.get("/hello", authz="OPEN")
def get_hello():
    return { "msg": "hello", "version": fsa.__version__ }, 200

# TODO LATER MORE ROUTES
```

Create the `acme.conf` configuration file:

```python
# File "acme.conf"
FSA_AUTH = "none"    # allow non authenticated routes (aka OPEN authorization)
FSA_MODE = "debug1"  # debug level 1, max is 4
FSA_ADD_HEADERS = { "Application": "Acme" }
```

Start the application in a terminal with the *flask* local test server.

```shell
export ACME_CONFIG="acme.conf"  # where to find the configuration file
flask --app ./app.py run --debug --reload
# various log traces...
# control-c to stop
```

Test the route, for instance using `curl` from another terminal:

```shell
curl -si -X GET http://localhost:5000/hello  # 200
```

You should see a log line for the request in the application terminal,
possibly some debug output, and the JSON response in the second terminal,
with 3 FSA-specific headers telling the request, the authentication and
execution time from the framework point of view:

```http
HTTP/1.1 200 OK
Server: Werkzeug/... Python/...
Date: ...
Application: Acme
FSA-Request: GET /hello
FSA-User: None (None)
FSA-Delay: 0.000666
Content-Type: application/json
Content-Length: 42
Connection: close

{
  "msg": "hello",
  "version": "35.3"
}
```

It is good practice to automate application tests, for instance with
[`pytest`](https://pytest.org/).  
Create a `test.py` file with a test to cover this route:

```python
# File "test.py"
import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_hello(client):
    res = client.get("/hello")         # GET /hello
    assert res.status_code == 200
    assert res.json["msg"] == "hello"

# TODO MORE TESTS
```

Install and run `pytest`:

```shell
pip install pytest
pytest test.py  # 1 passed
```

## Acme Database

Our incredible application will hold some data in a toy *Acme* database with
*Users* who can own *Stuff* at a price.  
Create file `acme.py` to manage a simplistic in-memory database implemented
as the `AcmeData` class:

```python
# File "acme.py"
import re
import FlaskSimpleAuth as fsa

class AcmeData:

    def __init__(self):
        # Users: login -> (password_hash, email, is_admin)
        self.users: dict[str, list[str, str, bool]] = {}
        # Stuff: name -> (owner, price)
        self.stuff: dict[str, list[str, float]] = {}

    def user_exists(self, login: str) -> bool:
        return login in self.users

    def add_user(self, login: str, password: str, email: str, admin: bool) -> None:
        self.user_exists(login) and fsa.err(f"cannot overwrite existing user: {login}", 409)
        re.match(r"^[a-z][a-z0-9]+$", login) or fsa.err(f"invalid login name: {login}", 400)
        self.users[login] = [password, email, admin]

    def get_user_pass(self, login: str) -> str|None:
        return self.users[login][0] if login in self.users else None

    def user_is_admin(self, login: str) -> bool:
        return self.users[login][2] if login in self.users else False

    def add_stuff(self, stuff: str, login: str, price: float) -> None:
        stuff in self.stuff and fsa.err(f"cannot overwrite existing stuff: {stuff}", 409)
        login in self.users or fsa.err(f"no such user: {login}", 404)
        self.stuff[stuff] = [login, price]

    def get_user_stuff(self, login: str) -> list[tuple[str, float]]:
        login in self.users or fsa.err(f"no such user: {login}", 404)
        return [ (stuff, row[1]) for stuff,row in self.stuff.items() if row[0] == login ]

    def change_stuff(self, stuff: str, price: float) -> None:
        stuff in self.stuff or fsa.err(f"no such stuff: {stuff}", 404)
        self.stuff[stuff][1] = price
```

This class can be tested with `test.py`:

```python
# append to "test.py"
import acme

def test_acmedata():
    db = acme.AcmeData()
    # users
    assert not db.user_exists("susie")
    db.add_user("susie", "susie-pass", "susie@acme.org", True)
    db.add_user("calvin", "calvin-pass", "calvin@acme.org", False)
    assert db.user_exists("susie") and db.user_exists("calvin")
    assert db.get_user_pass("susie") == "susie-pass"
    assert db.get_user_pass("calvin") == "calvin-pass"
    assert db.user_is_admin("susie") and not db.user_is_admin("calvin")
    # stuff
    db.add_stuff("pencil", "susie", 3.12)
    db.add_stuff("toy", "calvin", 2.72)
    assert db.get_user_stuff("calvin") == [ ("toy", 2.72) ]
    db.change_stuff("pencil", 3.14)
    assert db.get_user_stuff("susie") == [ ("pencil", 3.14) ]
    # FIXME should also test errors...
```

Run `pytest` as before to achieve _2 passed_.

## Basic Authentication

Let us now add new routes with *basic* authentication, which requires to:

- configure the application.
- store user credentials somewhere.
- provide a password callback.
- create authenticated routes.

Edit the `acme.conf` file to tell about basic authentication:

```python
# update "acme.conf"
FSA_AUTH = ["basic", "none"]
FSA_REALM = "acme"  # the app name, also the default
```

For non trivial projects, it is good practice to split the application in
several files.
This creates an annoying chicken-and-egg issue with Python initializations.
A common pattern is to define `init_app(app: Flask)` initialization functions
in each file, to call them from the main application file, and to use proxy
objects to avoid loading ordering issues.  
Create a `database.py` file which will hold our application primitive database
interface:

```python
# File "database.py"
import os
import FlaskSimpleAuth as fsa
import acme

# this is a proxy object to the actual database created when calling init_app
db = fsa.Reference()

# application database initialization
def init_app(app: fsa.Flask):
    # initialize proxy object
    db.set(acme.AcmeData())
    # add user acme as an admin
    db.add_user("acme", app.hash_password(os.environ["ACME_PASS"]), "acme@acme.org", True)
```

Create an `auth.py` file for the authentication and authorization callbacks:

```python
# File "auth.py"
import FlaskSimpleAuth as fsa

# the database is needed!
from database import db

# FlaskSimpleAuth password authentication hook
def get_user_pass(login: str) -> str|None:
    # NOTE returning None would work as well, but the result would be cached
    db.user_exists(login) or fsa.err(f"no such user: {login}", 401)
    return db.get_user_pass(login)

# TODO MORE CALLBACKS

# application auth initialization
def init_app(app: fsa.Flask):
    # register password hook
    app.get_user_pass(get_user_pass)
    # app.get_user_pass(db.get_user_pass)  # would work as well…
    # TODO MORE REGISTRATIONS
```

Edit the `app.py` file to import and initialize database and auth:

```python
# insert in "app.py" initialization
import database
database.init_app(app)
db = database.db

import auth
auth.init_app(app)
```

And add routes which can be accessed by _AUTH_-enticated users:

```python
# append to "app.py" routes
# all authenticated users can access this route
@app.get("/hello-me", authz="AUTH")
def get_hello_me(user: fsa.CurrentUser):
    return { "msg": "hello", "user": user }, 200

# users can add stuff for themselves
@app.post("/stuff", authz="AUTH")
def post_stuff(stuff: str, price: float, user: fsa.CurrentUser):
    db.add_stuff(stuff, user, price)
    return f"stuff added: {stuff}", 201

# and consult them
@app.get("/stuff", authz="AUTH")
def get_stuff(user: fsa.CurrentUser):
    return fsa.jsonify(db.get_user_stuff(user)), 200
```

The `user` parameter will be automatically filled with the name of the
authenticated user.
Other parameters are filled and converted from the request HTTP or JSON
parameters.  
Set the admin password in the environment, in each terminal:

```shell
# hint for 64+ bit random password: head -c 9 /dev/random | base64
export ACME_PASS="<a-good-admin-password>"
```

Restart and test the application:

```shell
curl -si -X GET                          http://localhost:5000/hello-me  # 401
curl -si -X GET -u 'meca:Mec0!'          http://localhost:5000/hello-me  # 401
curl -si -X GET -u "acme:$ACME_PASS"     http://localhost:5000/hello-me  # 200
curl -si -X POST -u "acme:$ACME_PASS" \
    -d stuff=pinte -d price=6.5          http://localhost:5000/stuff     # 201
curl -si -X POST -u "acme:$ACME_PASS" \
    -d stuff=pinte -d price=6.5          http://localhost:5000/stuff     # 409
curl -si -X GET -u "acme:$ACME_PASS"     http://localhost:5000/stuff     # 200
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _3 passed_:

```python
# append to "test.py"
import os
import base64

# NOTE basic auth should be managed by the test client…
# see https://pypi.org/project/FlaskTester/ for instance
def basic_auth(login: str, passwd: str) -> dict[str, str]:
    encoded = base64.b64encode(f"{login}:{passwd}".encode("UTF8"))
    return { "Authorization": f"Basic {encoded.decode('ascii')}" }

ACME_BASIC = basic_auth("acme", os.environ["ACME_PASS"])

MECA_PASS = "Mec0!"
MECA_BASIC = basic_auth("meca", MECA_PASS)

def test_basic_authn(client):
    res = client.get("/hello-me")
    assert res.status_code == 401
    res = client.get("/hello-me", headers=MECA_BASIC)
    assert res.status_code == 401
    res = client.get("/hello-me", headers=ACME_BASIC)
    assert res.status_code == 200
    assert res.json["user"] == "acme"
    res = client.post("/stuff", headers=ACME_BASIC, json={"stuff": "pinte", "price": 6.5})
    assert res.status_code == 201
    res = client.post("/stuff", headers=ACME_BASIC, json={"stuff": "pinte", "price": 6.5})
    assert res.status_code == 409
    res = client.get("/stuff", headers=ACME_BASIC)
    assert res.status_code == 200 and res.json[0][0] == "pinte"
    # FIXME should cleanup data
```

## Param Authentication

Another common way to authenticate a user is to provide the credentials as
request *parameters*.
This is usually done once to get some *token* (bearer, cookie…) which will be
used to access other routes, as discussed in the next section.
Initialization requirements are the same as for *basic* authentication, as
retrieving the user password is also needed.  
To enable parameter authentication as well as *basic* authentication, simply
update the `FSA_AUTH` configuration directive in `acme.conf`:

```python
# update "acme.conf"
FSA_AUTH = ["basic", "param", "none"]
```

Which parameters are used for authentication is also configurable in
`acme.conf`:

```python
# append to "acme.conf"
FSA_PARAM_USER = "username"  # parameter for the user name (default is USER)
FSA_PARAM_PASS = "password"  # parameter for the password (default is PASS)
```

Test from a terminal:

```shell
curl -si -X GET -d username=acme -d password="$ACME_PASS" http://localhost:5000/hello-me  # 200
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _4 passed_:

```python
# append to "test.py"
def test_param_authn(client):
    # authentication parameters
    acme_auth_params = {"username": "acme", "password": os.environ["ACME_PASS"]}
    # passed as HTTP parameters
    res = client.get("/hello-me", data=acme_auth_param)
    assert res.status_code == 200 and res.json["user"] == "acme"
    # or as JSON parameters
    res = client.get("/hello-me", json=acme_auth_param)
    assert res.status_code == 200 and res.json["user"] == "acme"
```

Authentication is often managed with tokens instead of passwords.
This approach is discussed in the next section.

## Token Authentication

Let us now activate *token* authentication.
This avoids sending login/passwords in each request, and is much more efficient
for the server because cryptographic password hashing functions are *designed*
to be very slow. Moreover, you may not want to pay for cpu cycles and have your
users endure additional latency just for that.  
Token authentication can be activated explicitely by prepending *token* to
`FSA_AUTH` in `acme.conf`:

```python
# update "acme.conf"
FSA_AUTH = ["token", "basic", "param", "none"]
```

Then we need a token signature secret and a route to create a token.  
Edit File `acme.conf` to add the secret and delay of your chosing:

```python
# append to "acme.conf"
# Unix 256+ bits random secret in ASCII: head -c 33 /dev/random | base64
FSA_TOKEN_SECRET = "<some-good-and-long-secret-for-token-signature>"
# NOTE: if not set, a random default is used instead
FSA_TOKEN_DELAY = 10.0  # set token expiration to 10 minutes (default is 1 hour)
```

In a more realistic setting, the token secret would probably not be directly
in the configuration, but passed to it or loaded by it somehow.  
Edit File `app.py` to add new routes to create a token for the current
user authenticated by a password scheme:

```python
# append to "app.py"
@app.get("/token", authz="AUTH", authn=["token", "basic", "param"])
def get_token(user: fsa.CurrentUser):
    return { "token": app.create_token(user) }, 200

# web application like to POST with authentication parameters to get a token
@app.post("/token", authz="AUTH", authn="param")
def post_token(user: fsa.CurrentUser):
    return { "token": app.create_token(user) }, 201
```

Then restart and test:

```shell
curl -si -X GET -u "acme:$ACME_PASS"                       http://localhost:5000/token
curl -si -X POST -d username=acme -d password="$ACME_PASS" http://localhost:5000/token
```

You should see the token as a JSON property in the response.
The default token type is *fsa*, with a short human-readable format.  
Proceed to use the token instead of the login/password to authenticate the user
on a route:

```shell
curl -si -X GET -H "Authorization: Bearer <put-the-raw-token-value-here>" \
                                        http://localhost:5000/hello-me  # 200
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _5 passed_:

```python
# append to "test.py"
def test_token_authn(client):
    acme_param_auth = {"username": "acme", "password": os.environ["ACME_PASS"]}
    # GET /token basic
    res = client.get("/token", headers=ACME_BASIC)
    assert res.status_code == 200 and "token" in res.json
    ACME_TOKEN = { "Authorization": f"Bearer {res.json['token']}" }
    # GET /hello-me with the token
    res = client.get("/hello-me", headers=ACME_TOKEN)
    assert res.status_code == 200 and res.json["user"] == "acme"
    # GET /token param
    res = client.get("/token", data=acme_param_auth)
    assert res.status_code == 200 and "token" in res.json
    res = client.get("/token", json=acme_param_auth)
    assert res.status_code == 200 and "token" in res.json
    # POST /token param
    res = client.post("/token", data=acme_param_auth)
    assert res.status_code == 201 and "token" in res.json
    res = client.post("/token", json=acme_param_auth)
    assert res.status_code == 201 and "token" in res.json
    res = client.post("/token", headers=ACME_BASIC)
    assert res.status_code == 401  # no basic auth
```

## Group Authorization

For *group* authorization, we need to:

- store group membership information somewhere.
- provide callbacks to check for group membership.
- define a route which requires some group membership.

Whether a user belongs to the *admin* group is defined as a boolean
in the user profile managed by *AcmeData*.  
First, write the group checking hook:

```python
# in "auth.py"
def user_is_admin(user: str) -> bool:
    return db.user_is_admin(user)
```

Then register it in the auth initializations:

```python
# append to "init_app" in "auth.py"
    app.group_check("admin", user_is_admin)
    # app.group_check("admin", db.user_is_admin)  # would work as well…
```

Then edit `app.py` to create a route reserved to admins which insert new users,
with three mandatory parameters: `login`, `password` and `email`:

```python
# append to "app.py"
@app.post("/user", authz="admin")
def post_user(login: str, password: str, email: str):
    db.add_user(login, app.hash_password(password), email, False)
    return f"user added: {login}", 201
```

Then restart and test:

```shell
curl -si -X POST -u "acme:$ACME_PASS" \
                                      http://localhost:5000/user      # 400 (missing parameters)
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="acme" -d email="acme@acme.org" -d password='P0ss!' \
                                      http://localhost:5000/user      # 409 (user exists)
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="123" -d email="123@acme.org" -d password='P1ss!' \
                                      http://localhost:5000/user      # 400 (bad login parameter)
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="meca" -d email="meca@acme.org" -d password='Mec0!' \
                                      http://localhost:5000/user      # 201
curl -si -X GET -u 'meca:Mec0!'       http://localhost:5000/hello-me  # 200
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _6 passed_:

```python
# append to "test.py"
def test_group_authz(client):
    res = client.post("/user", headers=ACME_BASIC)
    assert res.status_code == 400
    res = client.post("/user", headers=ACME_BASIC, json={"login": "acme", "email": "acme@acme.org", "password": "P0ss!"})
    assert res.status_code == 409
    res = client.post("/user", headers=ACME_BASIC, json={"login": "123", "email": "123@acme.org", "password": "P1ss!"})
    assert res.status_code == 400
    res = client.post("/user", headers=ACME_BASIC, json={"login": "meca", "email": "meca@acme.org", "password": MECA_PASS})
    assert res.status_code == 201
    res = client.get("/hello-me", headers=MECA_BASIC)
    assert res.status_code == 200 and res.json["user"] == "meca"
    # FIXME should cleanup data
```

## Object Authorization

Object permissions link a user to some *objects* to allow operations.
We want to allow object _owners_ to change the price of _their_ stuff.  
First, create the permission verification hook for stuff accesses:

```python
# insert in "auth.py"
def stuff_permissions(login: str, stuff: str, role: str) -> bool|None:
    if stuff not in db.stuff:  # if no stuff, trigger a 404
        return None
    elif role == "owner":  # tell whether current user is the owner
        return db.stuff[stuff][0] == login
    else:  # pragma: no cover
        raise fsa.ErrorResponse(f"unexpected stuff role {role}", 500)
```

Then register it in the auth initializations, associated to domain *stuff*:

```python
# append to "init_app" in "auth.py"
    app.object_perms("stuff", stuff_permissions)
```

Then implement the route, with the `authz` tuple telling that the *user*
must have *owner* access permission to the object identified by variable `sid`
value in domain *stuff*:

```python
# append to "app.py"
@app.patch("/stuff/<sid>", authz=("stuff", "sid", "owner"))
def patch_stuff_sid(sid: str, price: float):
    db.change_stuff(sid, price)
    return f"stuff changed: {sid}", 200
```

Then restart and test:

```shell
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="mace" -d email="mace@acme.org" -d password='Mac1!' \
                                      http://localhost:5000/user        # 201
curl -si -X POST -u 'mace:Mac1!' \
    -d stuff=bear -d price=2.0        http://localhost:5000/stuff       # 201
curl -si -X PATCH -u "acme:$ACME_PASS" \
                  -d price=3.0        http://localhost:5000/stuff/bear  # 403
curl -si -X PATCH -u 'mace:Mac1!' \
                  -d price=3.0        http://localhost:5000/stuff/bear  # 200
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _7 passed_:

```python
# append to "test.py"
MACE_PASS = "M@c1!"
MACE_BASIC = basic_auth("mace", MACE_PASS)

def test_objperm_authz(client):
    res = client.post("/user", headers=ACME_BASIC,
                      json={"login": "mace", "password": MACE_PASS, "email": "mace@acme.org"})
    assert res.status_code == 201
    res = client.post("/stuff", headers=MACE_BASIC, json={"stuff": "bear", "price": 2.0})
    assert res.status_code == 201
    res = client.patch("/stuff/bear", headers=ACME_BASIC, json={"price": 3.0})
    assert res.status_code == 403
    res = client.patch("/stuff/bear", headers=MACE_BASIC, json={"price": 3.0})
    assert res.status_code == 200
    # FIXME should cleanup data
```

## Dataclass Parameters

Application front ends are typically developed with *JavaScript*, thus JSON
*(JavaScript Object Notation)* is a convenient serialization format to
exchange data with a Python back end.
FlaskSimpleAuth supports data classes for parameters and return values.  
Let us install the `pydantic` data-structure validation library:

```shell
pip install pydantic
```

Then add data type definitions and an open route to `app.py` to compute the age
of _Someone_ in _days_.

```python
# append to "app.py"
from pydantic.dataclasses import dataclass
import datetime

@dataclass
class Someone:
    name: str
    born: datetime.date

@dataclass
class Days:
    name: str
    days: int

@app.get("/days", authz="OPEN")
def get_days(who: Someone):
    age = datetime.datetime.now().date() - who.born
    return fsa.jsonify(Days(name=who.name, days=age.days))
```

This route can be tested directly:

```shell
# http parameter
curl -si -X GET -d who='{"name":"Hobbes","born":"2020-07-29"}' http://localhost:5000/days
# json parameter
curl -si -X GET -H "Content-Type: application/json" \
    -d '{"who":{"name":"Calvin","born":"1970-03-20"}}'         http://localhost:5000/days
# with an invalid date
curl -si -X GET -d who='{"name":"Calvin","born":"unknown"}'    http://localhost:5000/days
```

Then automatically, run with `pytest` to achieve _8 passed_:

```python
# append to "test.py"
def test_days(client):
    res = client.get("/days", data={"who":{"name":"Calvin","born":"1970-03-20"}})
    assert res.status_code == 200
    assert res.json["name"] == "Calvin" and isinstance(res.json["days"], int)
    res = client.get("/days", json={"who":{"name":"Susie","born":"1970-10-14"}})
    assert res.status_code == 200
    assert res.json["name"] == "Susie" and isinstance(res.json["days"], int)
    # invalid data should lead to 400
    res = client.get("/days", json={"who":{"name":"Hobbes","born":"not yesterday"}})
    assert res.status_code == 400
```

Note that this also works with standard dataclasses.

## Standard Type Hints Parameters

Types hints based on standard types (`list`, `dict`…) are also supported
through JSON serialization. Let us add a route to report which numbers from a
list are primes with the help of the `sympy` package:

```shell
pip install sympy
```

Then add an open route to `app.py` to return which integers are prime from a
list of integers:

```python
# append to "app.py"
import sympy

@app.get("/primes", authz="OPEN")
def get_primes(li: list[int]):
    return fsa.jsonify(filter(sympy.isprime, li))
```

This can be tested directly:

```shell
# http parameters
curl -si -X GET -d li=1 -d li=10 -d li=11 http://localhost:5000/primes
# json parameters
curl -si -X GET -H "Content-Type: application/json" \
  -d '{"li":[1,10,11,20,21,23]}'          http://localhost:5000/primes
# bad parameters should get a 400
curl -si -X GET -d li=prime -d li=time    http://localhost:5000/primes
```

Then automatically, run with `pytest` to achieve _9 passed_:

```python
# append to "test.py"
def test_primes(client):
    res = client.get("/primes?li=7&li=8")
    assert res.status_code == 200 and res.json == [7]
    res = client.get("/primes", json={"li": [1, 2, 3, 4, 5, 6, 7, 8, 9]})
    assert res.status_code == 200 and res.json == [2, 3, 5, 7]
    res = client.get("/primes", json={"li": ["odd", "even"]})
    assert res.status_code == 400
```

## JSON Parameters

Arbitrary JSON parameters can be declared with special type `JsonData`:

```python
# append to "app.py"
@app.get("/len", authz="OPEN")
def get_len(p: fsa.JsonData):
    try:
        return {"len": len(p)}
    except TypeError:
        return {"len": "not available"}
```

Which it can be tested manually:

```shell
curl -si -d 'p={"hi":"w!"}' http://localhost:5000/len  # 200: 1
curl -si -d 'p=[1,2]'       http://localhost:5000/len  # 200: 2
curl -si -d 'p="hi!"'       http://localhost:5000/len  # 200: 3
curl -si -d 'p=3.14'        http://localhost:5000/len  # 200: not available
curl -si -d 'p=null'        http://localhost:5000/len  # 200: not available
curl -si -d 'p=not-json'    http://localhost:5000/len  # 400: invalid parameter
curl -si                    http://localhost:5000/len  # 400: missing parameter
```

And automatically:

```python
# append to "test.py"
def test_len(client):
    # working
    res = client.get("len", json={"p": {"hi":"w!"}})
    assert res.status_code == 200 and res.json["len"] == 1
    res = client.get("len", json={"p": ["foo", "bla"]})
    assert res.status_code == 200 and res.json["len"] == 2
    res = client.get("len", json={"p": "hi!"})
    assert res.status_code == 200 and res.json["len"] == 3
    res = client.get("len", data={"p": '"hi!"'})
    assert res.status_code == 200 and res.json["len"] == 3
    res = client.get("len", json={"p": null})
    assert res.status_code == 200 and res.json["len"] == "not available"
    # errors
    res = client.get("len")
    assert res.status_code == 400  # missing parameter
    res = client.get("len", data={"p": "bad-json"})
    assert res.status_code == 400  # invalid parameter value
```

## Further Improvements

Let us edit `acme.conf` to activate or change some features.

Errors are shown as `text/plain` by default, but this can be changed to JSON
which will be more easily handled by JavaScript clients:

```python
# append to "acme.conf"
FSA_ERROR_RESPONSE = "json:error"  # show errors as JSON
```

You can add minimal password strength requirements:

```python
# append to "acme.conf"
# passwords must contain at least 5 characters
FSA_PASSWORD_LENGTH = 5
# including an upper case letter, a lower case letter, and a digit.
FSA_PASSWORD_RE = [ r"[A-Z]", r"[a-z]", r"[0-9]" ]
```

After restarting the application, weak passwords are rejected, and error
messages as shown as JSON objects:

```shell
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="came" -d email="came@acme.org" -d password="C@me" \
                                         http://localhost:5000/user  # 400 (pass length)
curl -si -X POST -u "acme:$ACME_PASS" \
  -d login="came" -d email="came@acme.org" -d password="Cameleon" \
                                         http://localhost:5000/user  # 400 (pass regex)
```

Also append these same tests to `test.py`, and run them with `pytest` to
achieve _10 passed_:

```python
# append to "test.py"
def test_weak_password(client):
    res = client.post("/user", headers=ACME_BASIC,
                      data={"login": "came", "password": "C@me", "email": "came@acme.org"})
    assert res.status_code == 400
    assert "too short" in res.json["error"]
    res = client.post("/user", headers=ACME_BASIC,
                      data={"login": "came", "password": "Cameleon", "email": "came@acme.org"})
    assert res.status_code == 400
    assert "must match" in res.json["error"]
```

You may want to use standard *JWT* (*JSON Web Token*) instead of *fsa* tokens.
For that, install package dependencies `pip install FlaskSimpleAuth[jwt]` and
update the application configuration:

```python
# append to "acme.conf"
FSA_TOKEN_TYPE = "jwt"  # default is "fsa"
```

The authentication configuration can be simplified to the same effect by
setting it to *password*, which stands for both *basic* and *param*, and the
fact that *token* and *none* are added implicitely when the configuration
is a scalar:

```python
# update "acme.conf"
FSA_AUTH = "password"
```

The default behavior is that _any_ authentication scheme can be used on _any_
route which requires authentication.
Often, an application can be more selective, for instance by requiring
an actual password on the login route and only tokens on the others.  
In order to achieve this behavior:

```python
# append to "acme.conf"
FSA_AUTH_DEFAULT = "token"  # default authentication scheme
```

Then update route definitions to require some other scheme when needed with
parameter `authn="param"`, `authn="basic"`, `authn="password"` for both, or
`authn="none"` for open routes.

Finally, as the debugging level is not useful anymore, it can be
reduced by updating `FSA_MODE` setting:

```python
# update in "acme.conf"
FSA_MODE = "dev"
```

Restart and test the application with these new settings…

## Colophon

By following this tutorial, you have built a secure *Flask* application by
taking advantage of features provided by *FlaskSimpleAuth*: basic, parameter and
token authentications, group and object permissions authorizations, and handling
data classes.

Note: a tutorial is **not** the standard way of doing things, it is just a
simplistic and minimal example to demonstrate available features.
You should develop your skills by using tools such as `make` and `shell`
scripting to simplify, automate and speed up your development process.
Also, the above tests with authentications could be simplified with
the [FlaskTester](https://pypi.org/project/FlaskTester/) package.
