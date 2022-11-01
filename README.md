# Flask Simple Auth

Simple authentication, authorization, parameter checks and utils
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.

![Status](https://github.com/zx80/flask-simple-auth/actions/workflows/fsa.yml/badge.svg?branch=master&style=flat)
![Tests](https://img.shields.io/badge/tests-58%20✓-success)
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
most of the crust is managed by Flask and FlaskSimpleAuth.

```Python
from FlaskSimpleAuth import Flask
app = Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

# users belonging to the "patcher" group can patch "whatever/*"
# the function gets 3 typed parameters: one integer coming from the path (id)
# and the remaining two ("some", "stuff") are coming from HTTP or JSON request
# parameters. "some" is mandatory, "stuff" is optional because it has a default.
# the declared parameter typing is enforced.
@app.patch("/whatever/<id>", authorize="patcher")
def patch_whatever(id: int, some: int, stuff: str = "wow"):
    # ok to do it, with parameters "id", "some" & "stuff"
    return "", 204
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives:

```Python
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

## Documentation

This module helps managing authentication, authorizations and parameters
in a Flask REST application back-end.

### Features

The module provides a wrapper around the `Flask` class which
extends its capabilities for managing authentication, authorization and
parameters.

This is intended for a REST API implementation serving a remote client
application through HTTP methods called on a path, with HTTP or JSON
parameters passed in and a JSON result is returned: this help implement
an authenticated function call over HTTP.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, where the server does not care about
presenting login forms for instance.
However, some provisions are made so that it can also be used for a web
application: CORS, login page redirection…

[**Authentication**](#authentication) is available through the `get_user`
function.
It is performed on demand when the function is called or when checking for
permissions.
The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
authentication tokens (custom or JWT passed in headers or as a
parameter), and a fake authentication scheme useful for local application
testing.
It allows to have a login route to generate authentication tokens.
For registration, support functions allow to hash new passwords consistently
with password checks.
Alternate password checking schemes (eg temporary code, external LDAP server)
can be plug in easily through a hook.

[**Authorizations**](#authorization) are managed by mandatory permission
declaration on a route (eg a role name, or an object access), and relies
on supplied functions to check whether a user has this role or can access
an object.

[**Parameters**](#parameters) expected in the request can be declared, their
presence and type checked, and they are added automatically as named parameters
to route functions, skipping the burden of checking them in typical REST functions.
In practice, importing Flask's `request` global variable is not necessary anymore.

[**Utils**](#utils) include the convenient `Reference` class which allows to
share possibly thread-local data for import, and CORS handling.

### Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.

Depending on options, the following modules should be installed:

- [passlib](https://pypi.org/project/passlib/) for password management.
- [cachetools](https://pypi.org/project/cachetools/) and
  [CacheToolsUtils](https://pypi.org/project/cachetoolsutils/) for caching.
- [ProxyPatternPool](https://pypi.org/project/ProxyPatternPool/) for sharing.
- [bcrypt](https://pypi.org/project/bcrypt/)  for password hashing (default algorithm).
- [PyJWT](https://pypi.org/project/PyJWT/) for JSON Web Token (JWT).
- [cryptography](https://pypi.org/project/cryptography/) for pubkey-signed JWT.
- [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth)
  for `http-*` authentication options.
- [Flask CORS](https://github.com/corydolphin/flask-cors) for CORS handling.

### Initialization

The module is simply initialize by calling its `Flask` constructor
and providing a configuration through `FSA_*` directives, or possibly
by calling some methods to register helper functions, such as:

- a function to retrieve the password hash from the user name.
- a function which tells whether a user is in a group or role.
- functions which define object ownership.

```Python
from FlaskSimpleAuth import Flask
app = Flask("acme")
app.config.from_envvar("ACME_CONFIG")

# register some hooks

# return password hash if any (see with FSA_GET_USER_PASS)
@app.get_user_pass
def get_user_pass(user):
    return …

# return whether user is in group (see with FSA_USER_IN_GROUP)
@app.user_in_group
def user_in_group(user, group):
    return …

# return whether user can access the foo object for an operation
@app.object_perms("foo")
def allow_foo_access(user, fooid, mode):
    return …
```

Once initialized `app` is a standard Flask object with some additions:

- `route` decorator, an extended version of Flask's own with an `authorize`
  parameter and transparent management of request parameters.
- per-method shortcut decorators `post`, `get`, `put`, `patch` and `delete`
  which support the same extensions.
- `user_in_group`, `get_user_pass` and `object_perms` functions/decorators to
  register authentication and authorization helper functions.
- `get_user` to extract the authenticated user or raise an exception.
- `current_user` to get the authenticated user if any, or `None`.
- `hash_password` and `check_password` to hash or check a password.
- `create_token` to compute a new authentication token for the current user.
- `clear_caches` to clear internal process caches (probably a bad idea).
- `cast` a function/decorator to register no str to some type casts for
  parameters.

It is also possible, but *not* recommended to use the flask extensions model,
in which case the `FlaskSimpleAuth` object must be instanciated and routes
*must* be created using this object:

```Python
from flask import Flask
app = Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

from FlaskSimpleAuth import FlaskSimpleAuth
fsa = FlaskSimpleAuth(app)

# imaginary blueprint registration on the fsa object:
from DemoAdmin import abp
fsa.register_blueprint(abp, url_path="/admin")

# define a route with an optional paramater "flt"
@fsa.get("/what", authorize="ALL")
def get_what(flt: str = None):
    …
```

### Authentication

The main authentication configuration directive is `FSA_AUTH` which governs the
authentication methods used by the `get_user` function, as described in the
following sections. Defaut is `httpd`.

If a non-token single scheme is provided, authentication will be `token`
followed by the provided scheme, i.e. `token` is tried first anyway.

To take full control of authentication scheme, provide an ordered list.
Note that it does not always make much sense to mix some schemes, e.g.
*basic* and *digest* password storage assumptions are distinct and should
not be merged.  Also, only one HTTPAuth-based scheme can be active at a time.

Authentication is *always* performed on demand, either to check for a route
authorization declared with `authorize` or when calling `get_user`.

The authentication scheme attempted on a route can be altered with the `auth`
parameter added to the `route` decorator.
This may be used to restrict the authentication scheme to a *subset* if those
configured globally, and may or may not work otherwise depending on module
internals.
This feature is best avoided but in very particular cases because it counters
a goal of this module which is to remove authentication considerations from the
code and put them in the configuration only.
A legitimate use for a REST API is to have `FSA_AUTH` defined to *token* and have
only one *basic* route to obtain the token used by other routes.

#### Authentication Schemes

The available authentication schemes are:

- `none`

  Use to disactivate authentication.

- `httpd`

  Inherit web server supplied authentication through `request.remote_user`.
  This is the default.

  There are plenty authentication schemes available in a web server such as
  [Apache](https://httpd.apache.org/) or [Nginx](https://nginx.org/), including
  LDAP or other databases, all of which probably more efficiently implemented
  than this python code, so it should be the preferred option.
  However, it could require significant configuration effort compared to the
  application-side approach.

- `basic`

  HTTP Basic password authentication, which rely on the `Authorization`
  HTTP header in the request.
  Directive `FSA_REALM` provides the authentication realm.

  See also [Password Management](#password-management) below for
  how the password is retrieved and checked.

- `http-basic`

  Same as previous based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

  Directive `FSA_REALM` provides the authentication realm.
  Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
  HTTPAuth authentication class.

- `param`

  HTTP or JSON parameter for password authentication.
  User name and password are passed as request parameters.

  The following configuration directives are available:

  - `FSA_PARAM_USER` parameter name for the user name.
    Default is `USER`.
  - `FSA_PARAM_PASS` parameter name for the password.
    Default is `PASS`.

  See also [Password Management](#password-management) below for
  the password is retrieved and checked.

- `password`

  Tries `basic` then `param` authentication.

- `http-digest` or `digest`

  HTTP Digest authentication based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

  Note that the implementation relies on *sessions*, which may require the
  `SECRET_KEY` option to be set to something.
  The documentation states that server-side sessions are needed because
  otherwise the *nonce* and *opaque* parameters could be reused, which
  may be a security issue under some conditions. I'm unsure about that,
  but I agree that client-side cookie sessions are strange things best
  avoided if possible.

  Directive `FSA_REALM` provides the authentication realm.
  Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
  HTTPAuth authentication class, such as `use_ha1_pw`, as a dictionary.

  See also [Password Management](#password-management) below for
  how the password is retrieved and checked. Note that password management
  is different for digest authentication because the simple hash of the
  password or the password itself is needed for the verification.

- `token`

  Only rely on signed tokens for authentication.
  A token certifies that a *user* is authenticated in a *realm* up to some
  time *limit*.
  The token is authenticated by a signature which is usually the hash of the
  payload (*realm*, *user* and *limit*) and a secret hold by the server.

  There are two token types chosen with the `FSA_TOKEN_TYPE` configuration
  directive: `fsa` is a simple compact readable custom format, and `jwt`
  [RFC 7519](https://tools.ietf.org/html/rfc7519) standard based
  on [PyJWT](https://pypi.org/project/PyJWT/) implementation.

  The `fsa` token syntax is: `<realm>:<user>:<limit>:<signature>`,
  for instance: `comics:calvin:20380119031407:4ee89cd4cc7afe0a86b26bdce6d11126`.
  The time limit is a simple UTC timestamp *YYYYMMDDHHmmSS* that
  can be checked easily by the application client.
  Compared to `jwt` tokens, they are easy to interpret and compare manually,
  no decoding is involved.

  The following configuration directives are available:

  - `FSA_TOKEN_TYPE` type of token, either *fsa*, *jwt* or `None` to disable.
    Default is *fsa*.
  - `FSA_TOKEN_CARRIER` how to transport the token: *bearer* (`Authorization`
    HTTP header), *param*, *cookie* or *header*.
    Default is *bearer*.
  - `FKA_TOKEN_NAME` name of parameter or cookie holding the token, or
    bearer scheme, or header name.
    Default is `AUTH` for *param* carrier, `auth` for *cookie* carrier,
    `Bearer` for HTTP Authorization header (*bearer* carrier),
    `Auth` for *header* carrier.
  - `FSA_REALM` realm of authentication for token, basic or digest.
    Default is the simplified lower case application name.
    For *jwt*, this is translated as the audience.
  - `FSA_TOKEN_SECRET` secret string used for validating tokens.
    Default is a system-generated random string containing 256 bits.
    This default will only work with itself, as it is not shared
    across server instances or processes.
  - `FSA_TOKEN_SIGN` secret string used for signing tokens, if
    different from previous secret. This is only relevant for public-key
    *jwt* schemes (`R…`, `E…`, `P…`).
    Default is to use the previous secret.
  - `FSA_TOKEN_DELAY` number of minutes of token validity.
    Default is *60* minutes.
  - `FSA_TOKEN_GRACE` number of minutes of grace time for token validity.
    Default is *0* minutes.
  - `FSA_TOKEN_ALGO` algorithm used to sign the token.
    Default is `blake2s` for `fsa` and `HS256` for *jwt*.
  - `FSA_TOKEN_LENGTH` number of hash bytes kept for token signature.
    Default is *16* for `fsa`. The directive is ignored for `jwt`.
  - `FSA_TOKEN_RENEWAL` for cookie token, the fraction of delay under
    which the cookie/token is renewed automatically.
    Default is *0.0*, meaning no renewal.

  Function `create_token(user)` creates a token for the user depending
  on the current scheme. If `user` is not given, the current user is taken.

  Token authentication is always attempted unless the secret is empty.
  Setting `FSA_AUTH` to `token` results in *only* token authentication to be used.

  Token authentication is usually much faster than password verification because
  password checks are designed to be slow so as to hinder password cracking,
  whereas token authentication relies on simple hashing for its security.
  Another benefit of token is that it avoids sending passwords over and over.
  The rational option is to use a password scheme to retrieve a token and then to
  use it till it expires. This can be enforced by setting `FSA_AUTH` to `token`
  and to only add `auth="basic"` on the login route.

  Token expiration can be understood as a kind of automatic logout, which suggests
  to choose the delay with some care depending on the use case.

  When the token is carried as a *cookie*, it is automatically updated when 25% of
  the delay remains, if possible.

  Internally *jwt* token checks are cached so that even with slow public-key schemes
  the performance impact should be low.

- `http-token`

  Token scheme based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).
  Carrier is *bearer* or *header*.

  Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
  HTTPAuth authentication class, such as `header`, as a dictionary.

- `fake`

  Trust a parameter for authentication claims.
  Only for local tests, obviously.
  This is enforced.

  - `FSA_FAKE_LOGIN` name of parameter holding the user name.
    Default is `LOGIN`.

#### Password Management

Password authentication is performed for the following authentication
schemes: `param`, `basic`, `http-basic`, `http-digest`, `digest`, `password`.

For checking passwords the password (salted hash) must be retrieved through
`get_user_pass(user)`.
This function must be provided by the application when the module is initialized.
Because this function is cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

The following configuration directives are available to configure
`passlib` password checks:

- `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
  Default is `bcrypt`.
  See [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
  for available options.
  Set to `None` to disable password checking.
- `FSA_PASSWORD_OPTS` relevant options (for `passlib.CryptContext`).
  Default is `{'bcrypt__default_rounds': 4, 'bcrypt__default_ident': '2y'}`.

Beware that modern password checking is often pretty expensive in order to
thwart password cracking if the hashed passwords are leaked, so that you
do not want to have to use that on every request in real life (eg *hundreds*
milliseconds for passlib bcrypt *12* rounds).
The above defaults result in manageable password checks of a few milliseconds.
Consider using tokens to reduce the authentication load on each request.

For `digest` authentication, the password must be either in *plaintext* or a
simple MD5 hash ([RFC 2617](https://www.rfc-editor.org/rfc/rfc2617.txt)).
The authentication setup must be consistent (set `use_ha1_pw` as *True* for the
later).
As retrieving the stored information is enough to steal the password (plaintext)
or at least impersonate a user (hash), consider avoiding `digest` altogether.
HTTP Digest Authentication only makes sense for unencrypted connexions, which
are a bad practice anyway.
It is just provided here for completeness.

Function `hash_password(pass)` computes the password salted digest compatible
with the current configuration, and may be used for setting or resetting
passwords.

The standard password checking can be overridden by providing an alternate
password checking function with a directive:
- `FSA_PASSWORD_CHECK` hook function which returns whether user and password
  provided is acceptable for said user.
This allows to plug a LDAP server or a temporary password recovery scheme or
other one-time or limited-time passwords sent by SMS or mail, for instance.
This hook can also be filled with the `password_check` method/decorator.
This alternate check is used if the primary check failed.

The function checks the password quality by relying on:
- `FSA_PASSWORD_LEN` minimal password length, *0* to disable
- `FSA_PASSWORD_RE` list of regular expressions that a password must match
- `FSA_PASSWORD_QUALITY` hook function which returns whether the password is
  acceptable, possibly raising an exception to complain if not.
  This hook can also be filled with the `password_quality` method/decorator.
  It allows to plug a password strength estimator such as
  [zxcvbn](https://github.com/dropbox/zxcvbn).

An opened route for user registration with mandatory parameters
could look like that:

```Python
@app.post("/register", authorize="ANY")
def post_register(user: str, password: str):
    if user_already_exists(user):
        return f"cannot create {user}", 409
    add_new_user_with_hashed_pass(user, app.hash_password(password))
    return "", 201
```

Because password checks are usually expensive, it is advisable to switch
to `token` authentication. A token can be created on a path authenticated
by a password method:

```Python
# token creation route for all registered users
@app.get("/login", authorize="ALL")
def get_login():
    return jsonify(app.create_token()), 200
```

The client application will return the token as a parameter or in
headers for authenticating later requests, till it expires.

### Authorization

Authorizations are declared with the `authorize` parameter to
the `route` decorator (and its per-method shortcuts).
The modules supports two permission models:

- a group-oriented model
- an object-oriented model

The parameter accepts a list of `str` and `int` for groups, and of
`tuple` for object permissions.  If a scalar is provided, it is assumed
to be equivalent to a list of one element.

When multiple authorizations are provided they are cumulative,
that is all conditions must be met.

#### Group Authorizations

A group or role is identified as an integer or a string.
The `user_in_group(user, group)` function is called to check whether the
authenticated user belongs to a given group.
Because this function is cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

```Python
@app.get("/admin-only", authorize="ADMIN")
def get_admin_only():
    # only authenticated "ADMIN" users can get here!
    …
```

There are three special values that can be passed to the `authorize` decorator:

- `ANY` declares that no authentication is needed on that route.
- `ALL` declares that all authenticated user can access this route,
  without group checks.
- `NONE` returns a *403* on all access. It can be used to close a route
  temporarily. This is the default.

```Python
@app.get("/closed", authorize=NONE)
def get_closed():
    # nobody can get here

@app.get("/authenticated", authorize=ALL)
def get_authenticated():
    # ALL authenticated users can get here

@app.get("/opened", authorize=ANY)
def get_opened():
    # ANYone can get here, no authentication is required
```

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-object and per-operation authorization will still be needed.

#### Object Authorizations

Non trivial application have access permissions which depend on the data
stored by the application. For instance, a user may alter a data because
they *own* it, or access a data because they are *friends* of the owner.

In order to implement this model, the `authorize` decorator parameter can
hold a tuple `(domain, variable, mode)` which designates a permission domain
(eg a table or object or concept name in the application), the name of
a variable in the request (path or HTTP or JSON parameters) which identifies
an object of the domain, and the operation or level of access necessary for
this route:

```Python
@app.get("/message/<mid>", authorize=("msg", "mid", "read"))
def get_message_mid(mid: int):
    …
```

The system will check whether the current user can access message *mid*
in *read* mode by calling a per-domain user-supplied function:

```Python
@app.object_perms("msg")
def can_access_message(user: str, mid: int, mode: str) -> bool:
    # can user access message mid for operation mode?
    return …

# also: app.object_perms("msg", can_access_message)
```

If the check function returns *None*, a *404 Not Found* response is generated.
If it returns *False*, a *403 Forbidden* response is generated.
If it returns *True*, the route function is called to generate the response.

If `mode` is not supplied, *None* is passed to the check function.
If `variable` is not supplied, the *first* parameter of the route function
is taken:

```Python
# same as authorize=("msg", "mid", None)
@app.patch("/message/<mid>", authorize=("msg",))
def patch_message_mid(mid: int):
    …
```

The `FSA_OBJECT_PERMS` configuration directive can be set as a dictionary
which maps domains to their access checking functions:

```Python
FSA_OBJECT_PERMS = { "msg": can_access_message, "blog": can_access_blog }
```

Because these functions are cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

### Parameters

Request parameters (HTTP or JSON) are translated automatically to named function
parameters, by relying on function type annotations.
Parameters are considered mandatory unless a default value is provided.

```python
@app.get("/something/<id>", authorize=…)
def get_something_id(id: int, when: date, what: str = "nothing"):
    # `id` is an integer path-parameter
    # `when` is a mandatory date HTTP or JSON parameter
    # `what` is an optional string HTTP or JSON parameter
    return …
```

Request parameter string values are actually *converted* to the target type.
For `int`, base syntax is accepted for HTTP/JSON parameters, i.e. `0x11`,
`0o21`, `0b10001` and `17` all mean decimal *17*.
For `bool`, *False* is an empty string, `0`, `False` or `F`, otherwise
the value is *True*.
Type `path` is a special `str` type which allows to trigger accepting
any path on a route.
Type `JsonData` is a special type to convert, if necessary, a string value
to JSON, expecting a list or a dictionary.

If one parameter is a dict of keyword arguments, all request parameters are
provided into it, as shown below:

```Python
@app.put("/awesome", authorize="ALL")
def put_awesome(**kwargs):
    …
```

Custom classes can be used as path and HTTP parameter types, provided that
the constructor accepts a string to convert the parameter value to the
expected type.

```Python
class EmailAddr:
    def __init__(self, addr: str):
        self._addr = addr

@app.get("/mail/<addr>", authorize="ALL")
def get_mail_addr(addr: EmailAddr):
    …
```

If the constructor does not match, a custom function can be provided
with the `cast` function/decorator and will be called automatically
to convert parameters:

```Python
class House:
    …

@app.cast(House)
def strToHouse(s: str) -> House:
    return …

# or: app.cast(House, strToHouse)

@app.get("/house/<h>", authorize="ANY")
def get_house_h(h: House)
    …
```

The `FSA_CAST` directive can also be defined as a dictionary mapping
types to their conversion functions:

```Python
FSA_CAST = { House: strToHouse, … }
```

As a special case, the `Request`, `Session`, `Globals` and `Environ` types,
when used for parameters, result in the `request`, `session`, `g` flask special
objects and `environ` WSGI parameter to be passed as this parameter to the
function, allowing to keep a functional programming style by hidding away these
special proxies.

More special parameters can be added with the `special_parameter` app
function/decorator, by providing a type and a function which returns the
expected value. For instance, the `Request` definition corresponds to:

```Python
app.special_parameter(Request, lambda: request)
```

The `FSA_SPECIAL_PARAMETER` directive can also be defined as a dictionary
mapping types to their parameter value function.

Finally, python parameter names can be prepended with a `_`,
which is ignored when translating HTTP parameters.
This allows to use python keywords as parameter names, such
as `pass` or `def`.

```Python
@app.put("/user/<pass>", authorize="ALL")
def put_user_pass(_pass: str, _def: str, _import: str):
    …
```

### Utils

Utilities include the `Reference` generic object wrapper class and
miscellaneous configuration directives which cover security,
caching and CORS.

#### `Reference` Object Wrapper

This class provides a proxy object based on the `Proxy` class
from [ProxyPatternPool](https://pypi.org/project/proxypatternpool/).

This class implements a generic share-able global variable which can be
used by modules (eg app, blueprints…) with its initialization differed.

Under the hood, most methods calls are forwarded to a possibly sub-thread-local
object stored inside the wrapper, so that the Reference object mostly
behaves like the wrapped object itself.

See the module for a detailed documentation.

### Miscellaneous Configuration Directives

Some directives govern various details for this extension internal working.

- `FSA_SECURE` only allows secured requests on non-local connections.
  Default is *True*

- `FSA_SERVER_ERROR` controls the status code returned on the module internal
  errors, to help distinguish these from other internal errors which may occur.
  Default is *500*.

- `FSA_NOT_FOUND_ERROR` controls the status code returned when a permission
  checks returns *None*.
  Default is *404*.

- `FSA_REJECT_UNEXPECTED_PARAM` tells whether to reject requests with
  unexpected parameters.
  Default is *True*.

- `FSA_DEBUG` set module in debug mode, generating excessive traces…
  Default is *False*.

- `FSA_LOGGING_LEVEL` adjust module internal logging level.
  Default is *None*.

Some control is available about internal caching features used for user
authentication (user password access and token validations) and
authorization (group and per-object permissions):

- `FSA_CACHE` controls the type of cache to use, set to *None* to disallow
  caches. Values for standard `cachetools` cache classes are `ttl`, `lru`,
  `lfu`, `mru`, `fifo`, `rr` plus `dict`.
  MemCached is supported by setting it to `memcached`, and Redis with `redis`.
  Default is `ttl`.

- `FSA_CACHE_OPTS` sets internal cache options with a dictionary.
  This must contain the expected connection parameters for `pymemcache.Client`
  and for `redis.Redis` redis, for instance.
  For `redis` and `ttl`, an expiration ttl of 10 minutes is used and can be
  overwritten by providing the `ttl` parameter.

- `FSA_CACHE_SIZE` controls size of internal `cachetools` caches.
  Default is *262144*, which should use a few MiB.
  *None* means unbounded, more or less.

- `FSA_CACHE_PREFIX` use this application-level prefix, useful for shared
  distributed caches.  A good candidate could be `app.name + "."`.
  Default is *None*, meaning no prefix.

Web-application oriented features:

- `FSA_401_REDIRECT` url to redirect to on *401*.
  Default is *None*.
  This can be used for a web application login page.

- `FSA_URL_NAME` name of parameter for the target URL after a successful login.
  Default is `URL` if redirect is activated, else *None*.
  Currently, the login page should use this parameter to redirect to when ok.

- `FSA_CORS` and `FSA_CORS_OPTS` control CORS (Cross Origin Resource Sharing) settings.

  [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) is a
  security feature implemented by web browsers to check whether a server
  accepts requests from a given origin (*i.e.* from JavaScript code
  provided by some domain).

  CORS request handling is enabled by setting `FSA_CORS` to *True* which
  allows requests from any origin. Default is *False*.
  Additional options are controled with `FSA_CORS_OPTS`.
  The implementation is delegated to the
  [`flask_cors`](https://pypi.org/project/Flask-Cors/) Flask extension
  which must be available if the feature is enabled.

## License

This software is *public domain*.
All software has bug, this is software, hence…
Beware that you may lose your hairs or your friends because of it.
If you like it, feel free to send a postcard to the author.

## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth)
and packaged on [PyPI](https://pypi.org/project/FlaskSimpleAuth/).

Latest version is *17.0* published on 2022-10-29.
Initial version was *0.9.0* on 2021-02-21.

See [all versions](VERSIONS.md).

## See Also

[Flask-Security](https://github.com/Flask-Middleware/flask-security/) is a
feature-full web-oriented authentication and authorization framework based on
an ORM. By contrast, *Flask Simple Auth*:
- does NOT assume any ORM or impose a data model,
  you only have to provide callback functions to access the needed data
  (password, groups, object permissions…).
- does NOT do any web-related tasks (forms, views, templates, blueprint,
  translation…), it just helps providing declarative security layer (role or
  object permissions) to an HTTP API, well integrated into Flask by
  extending the existing `route` decorator.
- does provide a nice integrated parameter management to Flask,
  including conversions and type checks, detecting missing parameters…
- does care about performance by providing an automatic and relevant caching
  mechanism to expensive authentication and authorization checks, including
  relying on external stores such as *redis*.
- provides simple hooks to extend features, such as adding an
  password strength checker or a password alternate verifier.
- is much smaller (about 1/10th, ignoring dependencies), so probably it does
  less things!

## TODO

- add option not to renew auth cookies automatically?
- `FSA_PARAM_STYLE` *any/http/json* to restrict/force parameters?
- test `FSA_HTTP_AUTH_OPTS`?
- add `any` token scheme?
- add app.log?
- on-demand supplied user data?
  `get\_identity(user: str) -> Any` which is to be cached
  registered with `app.identity(get_identity)`
  then `id = app.get_identity(user: str = app.get_user())`
  does it really need to be inside `FlaskSimpleAuth`?
  possibly the id can be passed to perm hooks instead of the login?
  can be managed there as well?
- reduce cloc?
- pypy compatibility? issues with date/time fromisoformat
  and packages bcrypt, psycopg2, psycopg2cffi, psycopg…
- check thread safety, esp cachetools
- thread-local stuff in Reference: what about teardown?
- what about asyncio?
- should have explicit tests for psycopg version 2 and 3 drivers
- password re could use a dict for providing an explanation?
- should try to reduce "no cover" pragmas
- document ErrorResponse?
- coverage should include demo run
- add ldap password check how-to?
- add JWT authorizations?
- how to use external authentication stuff? eg LDAP? others?
  it should also work as an alternate pm…
- refactor password manager in a separate class?
