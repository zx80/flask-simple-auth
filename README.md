# FlaskSimpleAuth: The Secure Flask Framework

FlaskSimpleAuth is a [Flask](https://flask.palletsprojects.com/) wrapper to add
a declarative security layer to routes with authentification, authorization and
parameter management.

![Status](https://github.com/zx80/flask-simple-auth/actions/workflows/fsa.yml/badge.svg?branch=master&style=flat)
![Tests](https://img.shields.io/badge/tests-80%20✓-success)
![Coverage](https://img.shields.io/badge/coverage-100%25-success)
![Issues](https://img.shields.io/github/issues/zx80/flask-simple-auth?style=flat)
![Python](https://img.shields.io/badge/python-3-informational)
![Version](https://img.shields.io/pypi/v/FlaskSimpleAuth)
![Badges](https://img.shields.io/badge/badges-8-informational)
![License](https://img.shields.io/pypi/l/flasksimpleauth?style=flat)

With FlaskSimpleAuth, application and security concerns are separated:

- the **application** focusses on *what* to do, and *declares* its security
  requirements.
- the **configuration** declares *how* the authentification and authorization
  constraints are checked and *provides* necessary hook functions.
- the **framework** *implements* and *enforces* the security on the application
  routes, with safe defaults so that security cannot be overlooked.

The following Flask application provides two routes:

- `GET /store` allows any authenticated *user* in group *employee* to
  access the store list.
- `POST /store/<sid>` allows an authenticated *user* who is a *manager* of
  *store* number *sid* to add a quantity of product to the store inventory.

```python
# file "app.py"
from FlaskSimpleAuth import Flask

app = Flask("acme")
app.config.from_envvar("ACME_CONFIG")

@app.get("/store", authorize="employee")
def get_store(pattern: str = "%"):
    # return the list of stores matching optional parameter pattern
    return ..., 200

@app.post("/store/<sid>", authorize=("store", "sid", "manager"))
def post_store_sid(sid: int, product: str, quantity: int):
    # product is added in quantity to store sid
    return ..., 201
```

In this code, there is *no* clue about how users are authenticated, as this is
set from the configuration.
Only authorizations are declared on the route with the mandatory ``authorize``
parameter.
How these are checked is also set from the configuration.
HTTP or JSON parameters are automatically converted to the expected type.

Authentication and authorizations are provided to the framework with callback functions.
For our example, we will need to retrieve the salted hashed password for a user,
to check whether a user belongs to a group, and
to tell whether a user can access a given store in a particular role:

```python
# file "auth.py"

def get_user_pass(user: str) -> str|None:
    return ...  # hashed password retrieved from somewhere

def user_in_group(user: str, group: str) -> bool:
    return ...  # whether user belongs to group

def store_perms(user: str, sid: int, role: str) -> bool|None:
    return ...  # whether user can access store sid in role
```

Here is an example of configuration for the above application:
Users are identified either with a JWT token or with a basic authentification.

```python
# acme configuration
import os
import auth

FSA_MODE = "dev"
FSA_AUTH = ["token", "basic"]
FSA_TOKEN_TYPE = "jwt"
FSA_TOKEN_SECRET = os.environ["ACME_SECRET"]
FSA_GET_USER_PASS = auth.get_user_pass
FSA_USER_IN_GROUP = auth.user_in_group
FSA_OBJECT_PERMS = { "store": auth.store_perms }
```

The framework will ensure that routes are only called by authenticated users
who have the right authorizations.
Secure and reasonable defaults are provided.
Most features can be adjusted or extended to particular needs through numerous
directives and hooks.
Authentication and authorization callback invocations are cached for efficiency.

## More

- [documentation](https://zx80.github.io/flask-simple-auth/)
  including a [tutorial](https://zx80.github.io/flask-simple-auth/TUTORIAL)
  and convenient [recipes](https://zx80.github.io/flask-simple-auth/RECIPES),
  [sources](https://github.com/zx80/flask-simple-auth) and
  [issues](https://github.com/zx80/flask-simple-auth/issues) are hosted on
  [GitHub](https://github.com/).
- install [package](https://pypi.org/project/FlaskSimpleAuth/) from
  [PyPI](https://pypi.org/).

## License

This software is *public domain*.

All software has bug, this is software, hence…
Beware that you may lose your hairs or your friends because of it.
If you like it, feel free to send a postcard to the author.
