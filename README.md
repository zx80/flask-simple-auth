# Flask Simple Auth

Simple authentication, authorization, parameter checks and utils
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.

![Status](https://github.com/zx80/flask-simple-auth/actions/workflows/fsa.yml/badge.svg?branch=master&style=flat)
![Tests](https://img.shields.io/badge/tests-77%20✓-success)
![Coverage](https://img.shields.io/badge/coverage-100%25-success)
![Issues](https://img.shields.io/github/issues/zx80/flask-simple-auth?style=flat)
![Python](https://img.shields.io/badge/python-3-informational)
![Version](https://img.shields.io/pypi/v/FlaskSimpleAuth)
![Badges](https://img.shields.io/badge/badges-8-informational)
![License](https://img.shields.io/pypi/l/flasksimpleauth?style=flat)

**Contents:** [Example](#example), [Features](#features),
[Documentation](#documentation), [License](#license), [Versions](#versions).

## Example

The application code below (yes, the **6** lines of code, plus arguably some
configurations) performs *authentication*, *authorization* and *parameter* type
checks triggered by the extended `route` decorator, or per-method shortcut
decorators (`get`, `patch`, `post`…).
There is no clue in the source about what kind of authentication is used,
which is the point: authentication is managed in the configuration,
not in the application code.
The authorization rule is declared explicitely on each function with the
mandatory `authorize` parameter.
Path and HTTP/JSON parameters are type checked and converted automatically
based on type annotations.
Basically, you just have to implement a type-annotated Python function and
most of the crust is managed by `FlaskSimpleAuth`.

```python
from FlaskSimpleAuth import Flask
app = Flask("acme")
app.config.from_envvar("ACME_CONFIG")

@app.patch("/users/<id>", authorize="admin")
def patch_users_id(id: int, password: str, email: Email = None):
    # Admins can patch user *id* with a mandatory *password* and
    # an optional *email* parameter. Type conversions are performed
    # so that invalid values are rejected with a *400* automatically.
    return f"users {id} updated", 204
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives from
the configuration file (`ACME_CONFIG`):

```python
FSA_AUTH = "httpd"     # inherit web-serveur authentication
# or others schemes such as: basic, token (eg jwt)…
# hooks must be provided for retrieving user's passwords and
# checking whether a user belongs to a group, if these features are used.
```

If the `authorize` argument is not supplied, the security first approach
results in the route to be forbidden (*403*).
Various aspects of the implemented schemes can be configured with other
directives, with reasonable defaults provided so that not much is really
needed beyond choosing the authentication scheme.
Look at the [demo application](demo/README.md) for a simple full-featured
application.

## Features

The module provides a wrapper around the `Flask` class which extends its
capabilities for managing authentication, authorization and parameters.
This is intended for a REST API implementation serving a remote client
application through HTTP methods called on a path, with HTTP or JSON
parameters passed in and a JSON result is returned: this help implement
an authenticated function call over HTTP.

[**Authentication**](DOCUMENTATION.md#authentication),
i.e. checking *who* is doing the request, is performed whenever an
authorization is required on a route.
The module implements inheriting the web-server authentication,
various password authentication (HTTP Basic, or HTTP/JSON parameters),
tokens (custom or JWT passed in headers or as a parameter),
a fake authentication scheme useful for local application testing,
or relying on a user provided function to check a password or code.
It allows to have a login route to generate authentication tokens.
For registration, support functions allow to hash new passwords consistently
with password checks.
Alternate password checking schemes (eg temporary code, external LDAP server)
can be plug in easily through a hook.
Multi-factor authentication can be implemented easily thanks to per-route
*realms*.

[**Authorizations**](DOCUMENTATION.md#authorization),
i.e. checking whether the above *who* can perform a request, are managed by
mandatory permission declaration on a route (eg a role name, or an object
access), and relies on supplied functions to check whether a user has this role
or can access a particular object.
Authorization can also be provided from a third party through JWT tokens
following the [OAuth2](https://oauth.net/2/) approach.

[**Parameters**](DOCUMENTATION.md#parameters) expected in the request can be
declared, their presence and type checked, and they are added automatically as
named parameters to route functions, skipping the burden of checking them in
typical flask functions. The module manages *http*, *json* and *files*.
In practice, importing Flask's `request` global variable is not necessary.
The philosophy is that a REST API entry point is a function call through HTTP,
so the route definition should be a function, avoiding relying on magic globals.
The parameter handling based on type hints was inspired and is an extension of
[fastapi](https://fastapi.tiangolo.com/lo/) approach.

[**Utils**](DOCUMENTATION.md#utils) include the convenient `Reference` class which
allows to share possibly thread-local data for import, error and CORS handling.

It makes sense to integrate these capabilities into a Flask wrapper so that only
one extended decorator is needed on a route, meaning that the security cannot be
forgotten, compared to an extension which would require additional decorators.
Also, parameters checks are relevant to security in general and interdependent
as checking for object ownership requires accessing parameters.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, where the server does not care about
presenting login forms or managing views, for instance.
However, some provisions are made so that it can *also* be used for a web
application: CORS, login page redirection…

## Documentation

See the [detailed documentation](DOCUMENTATION.md) for how to best take advantage
of this module.

## License

This software is *public domain*.

All software has bug, this is software, hence…
Beware that you may lose your hairs or your friends because of it.
If you like it, feel free to send a postcard to the author.

## Versions

[Sources](https://github.com/zx80/flask-simple-auth),
[documentation](https://zx80.github.io/flask-simple-auth/) and
[issues](https://github.com/zx80/flask-simple-auth/issues)
are hosted on [GitHub](https://github.com).
Install [package](https://pypi.org/project/FlaskSimpleAuth/) from
[PyPI](https://pypi.org/).

Latest version is *23.2* published on 2023-07-23.

See [all versions](VERSIONS.md).
