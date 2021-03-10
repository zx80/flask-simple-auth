# Flask Simple Auth

Simple authentication, authorization and parameter checks
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and decorators.


## Example

The application code below performs authentication, authorization and
parameter checks triggered by decorators.
There is no clue in the source about what kind of authentication is used,
which is the whole point: authentication schemes are managed elsewhere, not
explicitely in the application code.
Parameters are type checked and converted automatically.
Basically, you just have to implement a Python function and most of the
crust is managed by Flask and FlaskSimpleAuth.

```Python
# app is the Flask application…
# user_to_password_fun is a function returning the hashed password for a user.
# user_in_group_fun is a function telling whether a user is in a group.

# initialize module
import FlaskSimpleAuth as fsa
fsa.setConfig(app, user_to_password_fun, user_in_group_fun)

# users belonging to the "patcher" group can patch "whatever/*"
# the function gets 3 arguments: one coming from the path (id)
# and the remaining two coming from request parameters (some, stuff).
# "some" is mandatory, stuff is optional because it has a default.
@fsa.route("/whatever/<id>", methods=["PATCH"], authorize=["patcher"])
def patch_whatever(id: int, some: int, stuff: str = "wow"):
    # ok to do it, with parameters id, some & stuff
    return "", 204
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives:

```Python
FSA_TYPE = 'httpd'     # inherit web-serveur authentication
# OR others such as:
FSA_TYPE = 'basic'     # HTTP Basic auth
FSA_TYPE = 'param'     # HTTP parameter auth
```

If the `authorize` argument is not supplied, the security first approach
results in the route to be aborted with a *500*.

Various aspects of the implemented schemes can be configured with other
directives, with reasonable defaults provided so that not much is really
needed beyond choosing the authentication scheme.


## Description

Help to manage authentication, authorizations and parameters in
a Flask REST application.

**Authentication** is available through the `get_user` function.
It is performed on demand when the function is called, automatically when
checking for permissions in a per-role authorization model, or possibly
forced for all/most paths.
The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
authentication tokens (custom or jwt), and
a fake authentication scheme useful for application testing.
It allows to have a login route to generate authentication tokens.
For registration, support functions allow to hash new passwords consistently
with password checks.

**Authorization** can be managed with a simple decorator to declare required
permissions on a route (eg a role name), and relies on a supplied function to
check whether a user has this role.  This approach is enough for basic
authorization management, but would be insufficient for realistic applications
where users can edit their own data but not those of others.
An additional feature is that the application aborts requests on routes
for which there is no explicit authorization declarations, allowing to
catch forgotten requirements.

**Parameters** expected in the request can be declared, their presence and type
checked, and they are added automatically as named parameters to route functions,
skipping the burden of checking them in typical REST functions.


## Documentation

### Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.

### Features

This simple module allows configurable authentication (`FSA_TYPE`):

- `httpd` web-server checked authentication passed in the request.

- `basic` HTTP basic auth with a function hook for getting
  the password hash.

- `param` same with HTTP parameter-provided login/password.

- `password` tries `basic` then `param`.

- `token` auth uses a signed token to authenticate a
  user in a realm for some limited time. The token can be
  obtained by actually authenticating with other methods.
  It can be provided as a *bearer* authorization header or
  a parameter.

- `fake` parameter-based auth for fast and simple testing
  the claimed login is coldly trusted…

I have considered [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth)
obviously, which provides many options, but I do not want to force their
per-route-only model and explicit classes but rather rely on mandatory request hooks
and have everything managed from the configuration file to easily switch
between schemes, without impact on the application code.

Note that this is intended for a REST API implementation serving
a remote application. It does not make much sense to "login" and "logout"
to/from a REST API because the point of the API is to serve and collect data
to all who deserve it, i.e. are authorized, unlike a web application
which is served while the client is on the page which maintains a session
and should disappear when disconnected as the web browser page is wiped out.
However, there is still a "login" concept which is only dedicated at
obtaining an auth token, that the application client needs to update from
time to time.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, where the server does not care about
presenting login forms for instance.

### Initialisation

The module is initialized by calling `setConfig` with three arguments:

 - the Flask application object.
 - a function to retrieve the password hash from the user name.
 - a function which tells whether a user is in a group or role.

```Python
# app is already initialized and configured the Flask application

# return password hash if any, or None
def get_user_password(user):
    return …

# return whether user is in group
def user_in_group(user, group):
    return …

import FlaskSimpleAuth as fsa
fsa.setConfig(app, get_user_password, user_in_group)
```

Then the module can be used to retrieve the authenticated user with `get_user`,
which raises `AuthException` on failures.
Some path may require to skip authentication, for instance registering a new user.

Three directives impact how and when authentication is performed.

- `FSA_TYPE` governs the *how*: `httpd`, `basic`, `param`, `password`, `token`…
as described below.
Default is `httpd`.

- `FSA_ALWAYS` tells whether to perform authentication in a before request
hook. Default is *True*.  On authentication failures *401* are returned.
Once in a route function, `get_user` will always return the authenticated
user and cannot fail.

- `FSA_SKIP_PATH` is a list of regular expression patterns which are matched
against the request path for skipping systematic authentication.
Default is empty, i.e. authentication is applied for all paths.

- `FSA_LAZY` tells whether to attempt authentication lazily when checking an
authorization through a `authorize` decorator or argument to the `route`
decorator.
Default is *True*.

- `FSA_CHECK` tells whether to generate a *500* internal error if a route
is missing an explicit authorization check.
Default is *True*.


### Using Authentication, Authorization and Parameter Check

Then all route functions can take advantage of this information to check for
authorizations with the `authorize` decorator, and for parameters with the
`parameters` decorator. All decorators are wrapped into a convenient `route`
decorator which extends Flask's own with authentication, authorization and
parameter management.

```Python
@fsa.route("/somewhere", methods=["POST"], authorize=["posters"])
def post_somewhere(stuff: str, nstuff: int, bstuff: bool = False):
    …
```

Note that more advanced permissions (eg users can edit themselves) will
still require manual permission checks at the beginning of the function.

An opened route for user registration with mandatory parameters
could look like that:

```Python
# with FSA_SKIP_PATH = (r"/register", …)
@app.route("/register", methods=["POST"])
@fsa.authorize(fsa.OPEN)
@fsa.parameters()
def post_register(user: str, password: str):
    if user_already_exists_somewhere(user):
        return f"cannot create {user}", 409
    add_new_user_with_hashed_pass(user, fsa.hash_password(password))
    return "", 201
```

For `token` authentication, a token can be created on a path authenticated
by one of the other methods. The code for that would be as simple as:

```Python
# token creation route for any registered user
@app.route("/login", methods=["GET"])
@fsa.authorize(fsa.AUTHENTICATED)
def get_login():
    return jsonify(fsa.create_token(get_user())), 200
```

The client application will return the token as a parameter for
authenticating later requests, till it expires.

The main configuration directive is `FSA_TYPE` which governs authentication
methods used by the `get_user` function, as described in the following sections:

### `httpd` Authentication

Inherit web server supplied authentication through `request.remote_user`.
This is the default.

There are plenty authentication schemes available in a web server
such as Apache or Nginx, all of which probably more efficiently implemented
than python code, so this should be the preferred option.
However, it could require significant configuration effort compared to
the application-side approach.

### `basic` Authentication

HTTP Basic password authentication, which rely on the `Authorization`
HTTP header in the request.

See also Password Authentication below for how the password is retrieved
and checked.

### `param` Authentication

HTTP parameter or JSON password authentication.
User name and password are passed as request parameters.

The following configuration directives are available:

 - `FSA_PARAM_USER` parameter name for the user name.
   Default is `USER`.
 - `FSA_PARAM_PASS` parameter name for the password.
   Default is `PASS`.

See also Password Authentication below for how the password is retrieved
and checked.

### `password` Authentication

Tries `basic` then `param` authentication.

### `token` Authentication

Only rely on signed tokens for authentication.
A token certifies that a *user* is authenticated in a *realm* up to some
time *limit*.
The token is authenticated by a signature which is the hash of the payload
(*realm*, *user* and *limit*) and a secret hold by the server.

There are two token types chosen with the `FSA_TOKEN_TYPE` configuration
directive: `fsa` is a compact custom format, and `jwt`
[RFC 7519](https://tools.ietf.org/html/rfc7519) standard based
on [PyJWT](https://pypi.org/project/PyJWT/) implementation.

The `fsa` token syntax is: `<realm>:<user>:<limit>:<signature>`,
for instance: `kiva:calvin:20210221160258:4ee89cd4cc7afe0a86b26bdce6d11126`.
The time limit is an easily parsable UTC timestamp *YYYYMMDDHHmmSS* so that
it can be checked easily by the application client.
Compared to `jwt` tokens, they are easy to interpret manually, no
decoding is involved.

The following configuration directives are available:

 - `FSA_TOKEN_TYPE` type of token, either *fsa* or *jwt*.
   Default is *fsa*.
 - `FSA_TOKEN_REALM` realm of token.
   Default is the simplified lower case application name.
   For *jwt*, this is translated as the audience.
 - `FKA_TOKEN_NAME` name of parameter holding the auth token, or
   *None* to use a *bearer* authorization header.
   Default is *None*.
 - `FSA_TOKEN_SECRET` secret string used for validating tokens.
   Default is a system-generated random string containing 256 bits.
   This default with only work with itself, as it is not shared
   across server instances or processes.
   Set to *None* to disable tokens.
 - `FSA_TOKEN_SIGN` secret string used for signing tokens, if
   different from previous secret. This is only relevant for public-key
   *jwt* schemes (`R…`, `E…`, `P…`).
   Default is to use the previous secret.
 - `FSA_TOKEN_DELAY` number of minutes of token validity.
   Default is *60* minutes.
 - `FSA_TOKEN_GRACE` number of minutes of grace time for token validity.
   Default is *0* minutes.
 - `FSA_TOKEN_HASH` hash algorithm used to sign the token.
   Default is `blake2s` for `fsa` and `HS256` for *jwt*.
 - `FSA_TOKEN_LENGTH` number of hash bytes kept for token signature.
   Default is *16* for `fsa`. The directive is ignored for `jwt`.

Function `create_token(user)` creates a token for the user depending
on the current scheme.

Note that token authentication is always attempted unless the secret is empty.
Setting `FSA_TYPE` to `token` results in *only* token authentication to be used.

Also note that token authentication is usually much faster than password verification
because password checks are designed to be slow so as to hinder password cracking.
Another benefit of token is that it avoids sending passwords over and over.
The rational option is to use a password scheme to retrieve a token and then to
use it till it expires.

### `fake` Authentication

Trust a parameter for authentication claims.
Only for local tests, obviously.
This is inforced.

The following configuration directive is available:

 - `FSA_FAKE_LOGIN` name of parameter holding the user name.
   Default is `LOGIN`.

### Password Authentication (`param` or `basic`)

For checking passwords the password (salted hash) must be retrieved through
`get_user_password(user)`.
This function must be provided by the application when the module is initialized.

The following configuration directives are available to configure
`passlib` password checks:

 - `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
   Default is `bcrypt`.
   See [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
   for available options.
 - `FSA_PASSWORD_OPTIONS` relevant options (for `passlib.CryptContext`).
   Default is `{'bcrypt__default_rounds': 4}`.

Beware that modern password checking is often pretty expensive in order to
thwart password cracking if the hashed passwords are leaked, so that you
do not want to have to use that on every request in real life (eg hundreds
milliseconds for passlib bcrypt 12 rounds).
The above defaults result in manageable password checks of a few milliseconds.
Consider enabling tokens to reduce the authentication load on each request.

Function `hash_password(pass)` computes the password salted digest compatible
with the current configuration.

### `authorize` Decorator

The decorator expects a list of identifiers, which are typically names or
numbers.
When several groups are specified, any will allow the operation to proceed.

```Python
# group ids
ADMIN, WRITE, READ = 1, 2, 3

@app.route("/some/place", methods=["POST"])
@fsa.authorize(ADMIN, WRITE)
def post_some_place():
    …
```

The check will call `user_in_group(user, group)` function to check whether the
authenticated user belongs to any of the authorized groups.

There are two special values that can be passed to the `authorize` decorator:

 - `fsa.OPEN` declares that no authentication is needed on that route.
 - `fsa.AUTHENTICATED` declares that any authenticated user can access this route.
 - `fsa.FORBIDDEN` returns a *403* on all access. It can be used to close a route
   temporarily.

The following configuration directive is available:

 - `FSA_LAZY` allows the `authorize` decorator to perform the authentication
   when needed, which mean that the before request hook can be skipped.
   Default is *True*.

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-operation authorization will still be needed.

### `parameters` Decorator

This decorators translates automatically request parameters (HTTP or JSON)
to function parameters, relying on function type annotations to do that.

By default, the decorator guesses whether parameters are mandatory based on
provided default values, i.e. they are optional when a default is provided.

The `required` parameter allows to declare whether all parameters
must be set (when *True*), or whether they are optional (*False*) in which
case *None* values are passed if no defaults are given.

The `allparams` parameter makes all request parameters be translated to
named function parameters that can be manipulated as such.

```Python
@app.route("/thing/<int:tid>", methods=["PATCH"])
@fsa.parameters()
def patch_thing_tid(tid: int, name: str = None, price: float = None):
    if name is not None:
        update_name(tid, name)
    …
    return "", 204
```

The `parameters` decorator **must** be placed *after* the `authorize` decorator.

The decorator also accepts positional string arguments. It expects these
parameter names and generates a *400* if any is missing from the request,
and passes them to function named parameters.
The decorator looks for HTTP or JSON parameters.

```Python
@app.route("/thing/<int:tid>", methods=["PUT"])
@fsa.parameters("name")
def put_thing_tid(tid, name):
    …
```

The decorator also accepts named parameters associated to a type. It expects
these parameter names and generate a *400* if any is missing from the request,
it converts the parameter string value to the expected type, resulting in a
*400* again if the type conversion fails, and it passes these to the function
as named parameters.

```Python
@app.route("/add", methods=["GET"])
@fsa.parameters(a=float, b=float)
def get_add(a, b):
    return str(a + b), 200
```

Request parameter string values are converted to the target type.
For `int`, base syntax is accepted, i.e. `0x11`, `0b10001` and `17`
all mean decimal *17*.
For `bool`, *False* is an empty string, `0`, `False` or `F`, otherwise
the value is *True*.

A side-effect of the `parameters` decorator passing of request parameters as
named function parameters is that request parameter names must be valid python
identifiers, which excludes keywords such as `pass`, `def` or `for`.

## `route` Decorator

This decorator is a shortcut for Flask's `route`, and FlaskSimpleAuth
`authorize` and `parameters`.

```Python
@fsa.route("/foo/<id>", methods=["GET"], authorize=["getters"])
def get_foo(id: int, j: int, k = 0):
    …
```

Is the same as:

```Python
@app.route("/foo/<int:id>", methods=["GET"])
@fsa.authorize("getters")
@fsa.parameters()
def get_foo(id: int, j: int, k = 0):
    …
```

Note that path section type `int` for path parameter `id` is inferred from
the function declaration. Also, optional parameter `k` is typed as int because
of its default value.

## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth)
and packaged on [PyPI](https://pypi.org/project/FlaskSimpleAuth/).

### 1.9.0

Add *bearer* authorization for tokens and make it the default.
Add *JWT* tokens, both hmac and pubkey variants.
Add *500* generation if a route is missing an authorization declaration.
Add convenient `route` decorator.
Add type inference for HTTP/JSON parameters based on default value, when provided.
Add type inference for root path parameters based on function declaration.

### 1.8.1

Fix typo in distribution configuration file.

### 1.8.0

Merge `autoparams` and `parameters` decorators into a single `parameters`
decorator.
Make it guess optional parameters based on default values.
Fix conversion issues with boolean type parameters.
Enhance integer type to accept other base syntaxes.
Improve documentation to advertise the simple and elegant approach.
Implement decorator with functions instead of a class.

### 1.7.0

Simplify code.
Add `FSA_ALWAYS` configuration directive and move the authentication before request
hook logic inside the module.
Add `FSA_SKIP_PATH` to skip authentication for some paths.
Update documentation to reflect this simplified model.
Switch all decorators to functions.

### 1.6.0

Add `autoparams` decorator with required or optional parameters.
Add typed parameters to `parameters` decorator.
Make `parameters` pass request parameters as named function parameters.
Simplify `authorize` decorator syntax and implementation.
Advise `authorize` *then* `parameters` or `autoparams` decorator order.
Improved documentation.

### 1.5.0

Flask *internal* tests with a good coverage.
Switch to `setup.cfg` configuration.
Add convenient `parameters` decorator.

### 1.4.0

Add `FSA_LAZY` configuration directive.
Simplify code.
Improve warning on short secrets.
Repackage…

### 1.3.0

Improved documentation.
Reduce default token signature length and default token secret.
Warn on random or short token secrets.

### 1.2.0

Add grace time for auth token validity.
Some code refactoring.

### 1.1.0

Add after request module cleanup.

### 1.0.0

Add `authorize` decorator.
Add `password` authentication scheme.
Improved documentation.

### 0.9.0

Initial release in beta.


## TODO

Features
 - better control which schemes are attempted?
 - should it be a full wrapper around Flask?

Implementation
 - should it be an object instead of a flat module?
 - expand tests
 - token caching? how to deal with expiration?
