# Flask Simple Auth

Simple authentication, authorization, parameter checks and utils
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.

![Status](https://github.com/zx80/flask-simple-auth/actions/workflows/fsa.yml/badge.svg?branch=master&style=flat)
![Tests](https://img.shields.io/badge/tests-64%20✓-success)
![Coverage](https://img.shields.io/badge/coverage-100%25-success)
![Issues](https://img.shields.io/github/issues/zx80/flask-simple-auth?style=flat)
![Python](https://img.shields.io/badge/python-3-informational)
![Version](https://img.shields.io/pypi/v/FlaskSimpleAuth)
![Badges](https://img.shields.io/badge/badges-8-informational)
![License](https://img.shields.io/pypi/l/flasksimpleauth?style=flat)

## Example

The application code below performs authentication, authorization and
parameter type checks triggered by the extended `route` decorator,
or per-method shortcut decorators (`get`, `patch`, `post`…).
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
app = Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

# users belonging to the "patcher" group can patch "whatever/*"
# the function gets 3 typed parameters: one integer coming from the path (id)
# and the remaining two ("some", "stuff") are coming from HTTP or JSON request
# parameters. "some" is mandatory, "stuff" is optional because it has a default.
# the declared parameter typing is enforced.
@app.patch("/whatever/<id>", authorize="patcher")
def patch_whatever_id(id: int, some: int, stuff: str = "wow"):
    # ok to do it, with parameters "id", "some" & "stuff"
    return "", 204
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives from
the configuration file (`DEMO_CONFIG`):

```python
FSA_AUTH = "httpd"     # inherit web-serveur authentication
# or others schemes such as: basic, digest, token (eg jwt), param…
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

[**Authorizations**](DOCUMENTATION.md#authorization),
i.e. checking whether the above who can perform a request, are managed by
mandatory permission declaration on a route (eg a role name, or an object
access), and relies on supplied functions to check whether a user has this role
or can access an object.
Authorization can also be provided from a third party through JWT tokens
following the [OAuth2](https://oauth.net/2/) approach.

[**Parameters**](DOCUMENTATION.md#parameters) expected in the request can be
declared, their presence and type checked, and they are added automatically as
named parameters to route functions, skipping the burden of checking them in
typical flask functions.
In practice, importing Flask's `request` global variable is not necessary anymore.
The philosophy is that a REST API entry point is a function call through HTTP,
so the route definition should be a function, avoiding relying on magic globals.

[**Utils**](DOCUMENTATION.md#utils) include the convenient `Reference` class which
allows to share possibly thread-local data for import, and CORS handling.

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

Latest version is *20.0* published on 2022-12-22.
Initial version was *0.9.0* on 2021-02-21.

See [all versions](VERSIONS.md).
