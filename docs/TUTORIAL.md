# FlaskSimpleAuth Tutorial

This tutorial present how to build a
[FlaskSimpleAuth](https://pypi.org/project/flasksimpleauth) project
with basic authentication and group authorizations.

This is not very different from starting a Flask project, *but*
if you start with Flask you will have to unlearn things as
FlaskSimpleAuth framework extends and simplifies Flask on key points.

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

```python
# File "app.py"

# necessary for debug messages to show up…
import logging
logging.basicConfig()

# Flask initialization
FlaskSimpleAuth as fsa
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
FSA_MODE = "debug4"  # maximum verbosity
```

Start the application in a terminal with the *werkzeug* local test server.

```shell
export ACME_CONFIG="acme.conf"  # where to find the config file
flask --app ./app.py run --debug --reload
# control-c to stop
```

Test the route, for instance using `curl` from another terminal:

```shell
curl -si -X GET http://localhost:5000/hello
```

You should see a log line for the request in the application terminal, and the
JSON response in the second, with 3 FSA-specific headers telling the request,
the authentification and execution time.

The `authorize` route parameter is mandatory.
It declares the authorization requirements on the route.
If not set, the route is close and the response is 403.

## Basic Authentication

Let us now add a new route with basic authentification.
This requires:

- storing user credentials somewhere.
- providing a password callback.
- creating an authenticated route.

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

First, create a `database.py` file which will hold our primitive database:

```python
# File "database.py"
import re
import os
import FlaskSimpleAuth as fsa

# an incredible database
class AcmeData:
    def __init__(self):
        self.users: dict[str, tuple[str, bool]] = {}

    def user_exists(self, login: str) -> bool:
        return login in db.users

    def add_user(self, login: str, password: str, admin: bool) -> None:
        if self.user_exists(login):
            raise fsa.ErrorResponse(f"cannot overwrite existing user: {login}", 409)
        if not re.match(r"^[a-z][a-z0-9]+$", login):
            raise fsa.ErrorResponse(f"invalid login name: {login}", 400)
        self.users[login] = (password, admin)

    def get_user_pass(self, login: str) -> str|None:
        return self.users[login][0] if self.user_exists(login) else None

    def user_is_admin(self, login: str) -> bool:
        return self.users[user][1]

# this is a proxy object to the actual database
db = fsa.Reference()

# application database initialization, should probably just connect to an actual db.
def init_app(app: fsa.Flask):
    # initialize proxy object
    db = db.set(AcmeData())
    # add an "admin" user if necessary
    if not db.user_exists("acme"):
        db.add_user("acme", app.hash_password(os.environ["ACME_ADMIN_PASS"]), True)
```

Create an `auth.py` file for the authentication and authorization stuff:

```python
# File "auth.py"

# we need the database!
from database import db

# FlaskSimpleAuth password authentication hook
def get_user_pass(login: str) -> str|None:
    return db.get_user_pass(login)

# TODO MORE HOOKS

# application auth initialization
def init_app(app: fsa.Flask):
    # register password hook
    app.get_user_pass(get_user_pass)
    # TODO MORE REGISTRATIONS
```

Edit the `app.py` file to initialize database and auth, and add a route
which is open to *ALL* authenticated users:

```
# insert in "app.py" initialization
import database
database.init_app(app)

import auth
auth.init_app(app)

# append to "app.py" routes
# all authentication users can access this route
@app.get("hello-me", authorize="ALL")
def get_hello_me(user: fsa.CurrentUser):
    return { "msg": "hello", "user": user }, 200
```

The `user` parameter will be automatically filled with the name of the
authenticated user.

Add the admin password in the environment:

```shell
export ACME_ADMIN_PASS="<a-good-password>"
```

Restart and test the application:

```shell
curl -si -X GET                 http://localhost:5000/hello-me  # 401
curl -si -X GET -u "meca:Mec0!" http://localhost:5000/hello-me  # 404
curl -si -X GET -u "acme:$ACME_ADMIN_PASS" http://localhost:5000/hello-me  # 200
```

## Group Authorization and Parameters

For group authorization, a callback function must be provided to tell whether a
user belongs to a group.

Edit `auth.py`:

```python
# in "auth.py"
# add group checking function
def user_in_group(user: str, group: str) -> bool:
    if group == "admin":
        return db.user_is_admin(user)
    else:  # handle other groups here…
        return False

# append to "init_app":
    # register group hook
    app.user_in_group(user_in_group)
```

Then edit `app.py` to create a route reserved to admins which inserts new users:

```python
# append to "app.py"
@app.post("/user", authorize="admin")
def post_user(login: str, password: str):
    # login checks are in "add_user"
    # password checks are in "hash_password"
    db.add_user(login, app.hash_password(pass), False)
    return f"user {login} added", 201
```

This routes requires 2 mandatory parameters: `login` and `password`.
Then test:

```shell
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
                                      http://localhost:5000/user  # 400 (missing parameters)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="acme" -d password="Pass!" http://localhost:5000/user  # 409 (user exists)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="123" -d password="Pass!" http://localhost:5000/user   # 400 (bad user parameter)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="meca" -d password="Mec0!" http://localhost:5000/user  # 201
curl -si -X GET -u "meca:Mec0!" http://localhost:5000/hello-me    # 200
```

## Token Authentication

Let us now activate token authencation.
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

Then test:

```shell
curl -si -X GET -u "acme:$ACME_ADMIN_PASS" http://localhost:5000/token
```

You should see the token as a JSON field in the response.
Then proceed to use the token instead of the login/password:

```shell
curl -si -X GET -H "Authorization: Bearer <token>" http://localhost:5000/hello-me
```

## Further Improvements

Edit `acme.conf` to add minimal password strength requirements:

```python
# append to "acme.conf"
# passwords must contain at least 5 characters
FSA_PASSWORD_LENGH = 5
# including an upper case letter, a lower case letter, and a digit.
FSA_PASSWORD_RE = [ r"[A-Z]", r"[a-z]", r"[0-9]" ]
```
After restarting the application, weak passwords are rejected:

```python
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="came" -d password="C@me" http://localhost:5000/user      # 400 (pass)
curl -si -X POST -u "acme:$ACME_ADMIN_PASS" \
  -d login="came" -d password="Cameleon" http://localhost:5000/user  # 400 (pass)
```

By default, any group name is accepted with `authorize`, and may fail at run
time. Available groups can be explicitely declare with `FSA_GROUPS` so that
a configuration error is raised instead:

```python
# append to "acme.conf"
FSA_AUTHZ_GROUPS = ["admin"]
```

Errors are shown as `text/plain` by default, but this can be changed to JSON:

```python
# append to "acme.conf"
FSA_ERROR_RESPONSE = "json:error"  # show errors as JSON
```
