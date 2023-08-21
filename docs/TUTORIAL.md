# FlaskSimpleAuth Tutorial

This tutorial present how to build a
[FlaskSimpleAuth](https://pypi.org/project/flasksimpleauth) REST back-end
project with basic authentication plus group and object authorizations.
This is not very different from starting a Flask project, *but* if you start
with Flask you will have to unlearn things as FlaskSimpleAuth framework extends
and simplifies Flask on key points.

## Application Setup

Let us first create a minimal running REST application back-end without
authentication and authorizations.

Create and activate a Python virtual environment, in a terminal:

```shell
python -m venv venv
source venv/bin/activate
pip install FlaskSimpleAuth[password]
```

Create the `app.py` file with an unauthenticated `GET /hello` route.
The route is open because it is authorized to *ANY*one.
The `authorize` route parameter is mandatory to declare authorization
requirements on the route. If not set, the route is closed (403).

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
@app.get("/hello", authorize="ANY")
def get_hello():
    return { "msg": "hello", "version": fsa.__version__ }, 200

# TODO LATER MORE ROUTES
```

Create the `acme.conf` configuration file:

```python
# File "acme.conf"
FSA_MODE = "debug1"  # debug level 1, max is 4
```

Start the application in a terminal with the *flask* local test server.

```shell
export ACME_CONFIG="acme.conf"  # where to find the config file
flask --app ./app.py run --debug --reload
# control-c to stop
```

Test the route, for instance using `curl` from another terminal:

```shell
curl -si -X GET http://localhost:5000/hello  # 200
```

You should see a log line for the request in the application terminal, some
debug output, and the JSON response in the second terminal, with 3 FSA-specific
headers telling the request, the authentication and execution time:

```http
HTTP/1.1 200 OK
Server: Werkzeug/... Python/...
Date: ...
FSA-Request: GET /hello
FSA-User: None (None)
FSA-Delay: 0.000668
Content-Type: application/json
Content-Length: 42
Connection: close

{
  "msg": "hello",
  "version": "24.0"
}
```

## Acme Database and Tests

This incredible application has some data hold in our toy *Acme* database
with *Users* who can own *Stuff* at a price. Create file `acme.py`:

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
        if self.user_exists(login):
            raise fsa.ErrorResponse(f"cannot overwrite existing user: {login}", 409)
        if not re.match(r"^[a-z][a-z0-9]+$", login):
            raise fsa.ErrorResponse(f"invalid login name: {login}", 400)
        self.users[login] = [password, email, admin]

    def get_user_pass(self, login: str) -> str|None:
        if self.user_exists(login)
            return self.users[login][0]
        else:
            # NOTE returning None would work as well, but the result is cached
            raise fsa.ErrorResponse(f"no such user: {login}", 401)

    def user_is_admin(self, login: str) -> bool:
        return self.users[login][2]

    def add_stuff(self, stuff: str, login: str, price: float) -> None:
        if stuff in self.stuff:
            raise fsa.ErrorResponse(f"cannot overwrite existing stuff: {stuff}", 409)
        if login not in self.users:
            raise fsa.ErrorResponse(f"no such user: {login}", 404)
        self.stuff[stuff] = [login, price]

    def get_user_stuff(self, login: str) -> list[tuple[str, float]]:
        if login not in self.users:
            raise fsa.ErrorResponse(f"no such user: {login}", 404)
        return [ (stuff, row[1]) for stuff,row in self.stuff.items() if row[0] == login ]

    def change_stuff(self, stuff: str, price: float) -> None:
        if stuff not in self.stuff:
            raise fsa.ErrorResponse(f"no such stuff: {stuff}", 404)
        self.stuff[stuff][1] = price
```

It is good practice to test your application, for instance with `pytest`:

```python
# file "test.py"
import pytest

from acme import AcmeData

def test_acmedata():
    db = AcmeData()
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

from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_hello(client):
    res = client.get("/hello")
    assert res.status_code == 200
    assert res.json["msg"] == "hello"

# TODO MORE TESTS
```

Install and run with `pytest`:

```shell
pip install pytest requests
pytest test.py  # 2 passed
```

## Basic Authentication

Let us now add new routes with basic authentication.
This requires:

- configuring the application
- storing user credentials somewhere.
- providing a password callback.
- creating authenticated routes.

Edit the `acme.conf` file to tell about basic authentication:

```python
# append to "acme.conf"
FSA_AUTH = "basic"
FSA_REALM = "acme"  # the app name is also the default
```

For non trivial projects, it is good practice to split the application in
several files. This creates an annoying chicken-and-egg issue with Python
initializations. A common pattern is to define `init_app(app: Flask)`
initialization functions in each file, to call them from the application file,
and to use proxy objects to avoid loading ordering issues.

Create a `database.py` file which will hold our application primitive database
interface:

```python
# File "database.py"
import os
import FlaskSimpleAuth as fsa
from acme import AcmeData

# this is a proxy object to the actual database
db = fsa.Reference()

# application database initialization, should probably just connect to an actual db.
def init_app(app: fsa.Flask):
    # initialize proxy object
    db.set(AcmeData())
    # add an "admin" user if necessary
    if not db.user_exists("acme"):
        db.add_user("acme", app.hash_password(os.environ["ACME_ADMIN_PASS"]), "acme@acme.org", True)
```

Create an `auth.py` file for the authentication and authorization stuff:

```python
# File "auth.py"
import FlaskSimpleAuth as fsa

# we need the database!
from database import db

# FlaskSimpleAuth password authentication hook
def get_user_pass(login: str) -> str|None:
    return db.get_user_pass(login)

# TODO MORE CALLBACKS

# application auth initialization
def init_app(app: fsa.Flask):
    # register password hook
    app.get_user_pass(get_user_pass)
    # TODO MORE REGISTRATIONS
```

Edit the `app.py` file to initialize database and auth:

```python
# insert in "app.py" initialization
import database
database.init_app(app)
db = database.db

import auth
auth.init_app(app)
```

And add routes which are open to *ALL* authenticated users:

```python
# append to "app.py" routes
# all authentication users can access this route
@app.get("/hello-me", authorize="ALL")
def get_hello_me(user: fsa.CurrentUser):
    return { "msg": "hello", "user": user }, 200

# users can add stuff for themselves
@app.post("/stuff", authorize="ALL")
def post_stuff(stuff: str, price: float, user: fsa.CurrentUser):
    db.add_stuff(stuff, user, price)
    return f"stuff added: {stuff}", 201

# and consult them
@app.get("/stuff", authorize="ALL")
def get_stuff(user: fsa.CurrentUser):
    return fsa.jsonify(db.get_user_stuff(user)), 200
```

The `user` parameter will be automatically filled with the name of the
authenticated user. Other parameters are filled and converted from the request
HTTP or JSON parameters.

Add the admin password in the environment, in each terminal:

```shell
export ACME_ADMIN_PASS="<a-good-admin-password>"
```

Restart and test the application:

```shell
curl -si -X GET                            http://localhost:5000/hello-me  # 401
curl -si -X GET -u 'meca:Mec0!'            http://localhost:5000/hello-me  # 401
curl -si -X GET -u "acme:$ACME_ADMIN_PASS" http://localhost:5000/hello-me  # 200
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
    -d stuff=pinte -d price=6.5            http://localhost:5000/stuff     # 201
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
    -d stuff=pinte -d price=6.5            http://localhost:5000/stuff     # 409
curl -si -X GET -u "acme:$ACME_ADMIN_PASS" http://localhost:5000/stuff     # 200
```

Also append these same tests to `test.py`, and run them with `pytest`:

```python
import os
from requests.auth import _basic_auth_str as basic_auth

ACME_BASIC = { "Authorization": basic_auth("acme", os.environ["ACME_ADMIN_PASS"]) }

MECA_PASS = "Mec0!"
MECA_BASIC = { "Authorization": basic_auth("meca", MECA_PASS) }

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
    assert res.status_code == 200
    assert res.json[0][0] == "pinte"
    # FIXME should cleanup data
```

## Parameter Authentication

Another common way to authenticate a user is to provide the credentials as
request parameters.
This is usually done once to get some *token* (bearer, cookie…) which will be
used to access other routes.
Initialization requirements are the same as for *basic* authentication.
To enable parameter authentication as well as *basic* authentication, simply
update the `FSA_AUTH` configuration directive in `acme.conf`:

```python
# update "acme.conf"
FSA_AUTH = "password"  # allow both "param" and "basic"
```

The default parameter names are `USER` and `PASS`.
Test from a terminal:

```shell
curl -si -X GET -d USER=acme -d PASS="$ACME_ADMIN_PASS" http://localhost:5000  # 200
```

Also append these same tests to `test.py`, and run them with `pytest`:

```python
def test_param_authn(client):
    # HTTP parameters
    res = client.get("/hello-me", data={"USER": "acme", "PASS": os.environ["ACME_ADMIN_PASS"]})
    assert res.status_code == 200
    assert res.json["user"] == "acme"
    # also with JSON parameters
    res = client.get("/hello-me", json={"USER": "acme", "PASS": os.environ["ACME_ADMIN_PASS"]})
    assert res.status_code == 200
    assert res.json["user"] == "acme"
```

## Group Authorization

For group authorization, a callback function must be provided to tell whether a
user belongs to a group.

First, we add the group checking function:

```python
# in "auth.py"
def user_in_group(user: str, group: str) -> bool:
    if group == "admin":
        return db.user_is_admin(user)
    else:  # handle other groups here…
        return False
```

Then when register it in the initialization:

```python
# append to "init_app" in "auth.py"
    app.user_in_group(user_in_group)
```

Then edit `app.py` to create a route reserved to admins which insert new users,
with two mandatory parameters: `login` and `password`.

```python
# append to "app.py"
@app.post("/user", authorize="admin")
def post_user(login: str, password: str, email: str):
    db.add_user(login, app.hash_password(password), email, False)
    return f"user added: {login}", 201
```

Then restart and test:

```shell
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
                                      http://localhost:5000/user  # 400 (missing parameters)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="acme" -d email="acme@acme.org" -d password='P0ss!' \
                                      http://localhost:5000/user  # 409 (user exists)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="123" -d email="123@acme.org" -d password='P1ss!' \
                                      http://localhost:5000/user  # 400 (bad login parameter)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="meca" -d email="meca@acme.org" -d password='Mec0!' \
                                      http://localhost:5000/user  # 201
curl -si -X GET -u 'meca:Mec0!' http://localhost:5000/hello-me    # 200
```

Also append these same tests to `test.py`, and run them with `pytest`:

```python
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
    assert res.status_code == 200
    assert res.json["user"] == "meca"
    # FIXME should cleanup data
```

## Token Authentication

Let us now activate token authentication.
This avoids sending login/passwords in each request, and is much more efficient
for the server because cryptographic password hashing functions are *designed*
to be very slow.

There is nearly nothing to do: token authentication is activate by default, we
only need to provide a route which allows to create a token:

Edit file `app.py`:

```python
# append to "app.py"
@app.get("/token", authorize="ALL")
def get_token(user: fsa.CurrentUser):
    return { "token": app.create_token(user) }, 200
```

Then restart and test:

```shell
curl -si -X GET -u "acme:$ACME_ADMIN_PASS" http://localhost:5000/token
```

You should see the token as a JSON field in the response.
Then proceed to use the token instead of the login/password:

```shell
curl -si -X GET -H "Authorization: Bearer <put-the-token-value-here>" \
                                        http://localhost:5000/hello-me  # 200
```

Also append these same tests to `test.py`, and run them with `pytest`:

```python
def test_token_authn(client):
    res = client.get("/token", headers=ACME_BASIC)
    assert res.status_code == 200
    token = res.json["token"]
    ACME_TOKEN = { "Authorization": f"Bearer {token}" }
    res = client.get("/hello-me", headers=ACME_TOKEN)
    assert res.status_code == 200
    assert res.json["user"] == "acme"
```

## Object Permission Authorization

Object permissions link a user to some object to allow operations.
We want to allow object owners to change the price of their stuff.
First, we create the permission verification function:

```python
# insert in "auth.py"
def stuff_permissions(login: str, stuff: str, role: str):
    if role == "owner" and stuff in db.stuff:
        return db.stuff[stuff][0] == login
    else:
        return False
```

Then we register it when the application authentication is initialized:

```python
# append to "init_app" in "auth.py"
    app.object_perms("stuff", stuff_permissions)
```

Then we implement the route:

```python
# append to "app.py"
@app.patch("/stuff/<sid>", authorize=("stuff", "sid", "owner"))
def patch_stuff_sid(sid: str, price: float):
    db.change_stuff(sid, price)
    return f"stuff changed: {sid}", 204
```

Then we can restart and test:

```shell
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="mace" -d email="mace@acme.org" -d password='Mac1!' \
                                      http://localhost:5000/user        # 201
curl -si -X POST -u 'mace:Mac1!' \
    -d stuff=bear -d price=2.0        http://localhost:5000/stuff       # 201
curl -si -X PATCH -u "acme:$ACME_ADMIN_PASS" \
                  -d price=3.0        http://localhost:5000/stuff/bear  # 403
curl -si -X PATCH -u 'mace:Mac1!' \
                  -d price=3.0        http://localhost:5000/stuff/bear  # 204
```

Also append these same tests to `test.py`, and run them with `pytest`:

```python
MACE_PASS = "M@c1!"
MACE_BASIC = { "Authorization": basic_auth("mace", MACE_PASS) }

def test_objperm_authz(client):
    res = client.post("/user", headers=ACME_BASIC,
                      json={"login": "mace", "password": MACE_PASS, "email": "mace@acme.org"})
    assert res.status_code == 201
    res = client.post("/stuff", headers=MACE_BASIC, json={"stuff": "bear", "price": 2.0})
    assert res.status_code == 201
    res = client.patch("/stuff/bear", headers=ACME_BASIC, json={"price": 3.0})
    assert res.status_code == 403
    res = client.patch("/stuff/bear", headers=MACE_BASIC, json={"price": 3.0})
    assert res.status_code == 204
    # FIXME should cleanup data
```

## Further Improvements

Edit `acme.conf` to add minimal password strength requirements:

```python
# append to "acme.conf"
# passwords must contain at least 5 characters
FSA_PASSWORD_LENGTH = 5
# including an upper case letter, a lower case letter, and a digit.
FSA_PASSWORD_RE = [ r"[A-Z]", r"[a-z]", r"[0-9]" ]
```

After restarting the application, weak passwords are rejected:

```python
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="came" -d email="came@acme.org" -d password="C@me" \
                                         http://localhost:5000/user  # 400 (pass length)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="came" -d email="came@acme.org" -d password="Cameleon" \
                                         http://localhost:5000/user  # 400 (pass regex)
```

By default, any group name is accepted with `authorize`, and may fail at run
time.
Available groups can be explicitely declare with `FSA_AUTHZ_GROUPS` so that a
configuration error is raised instead:

```python
# append to "acme.conf"
FSA_AUTHZ_GROUPS = ["admin"]
```

Errors are shown as `text/plain` by default, but this can be changed to JSON:

```python
# append to "acme.conf"
FSA_ERROR_RESPONSE = "json:error"  # show errors as JSON
```

Finally, the very verbose debugging level is not useful anymore, thus can be
reduces by updating `FSA_MODE` setting:

```python
# update in "acme.conf"
FSA_MODE = "dev"
```

Restart and test the application with these new settings…
