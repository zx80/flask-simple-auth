# Flask Simple Auth

Simple authentication, authorization, parameter checks and utils
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.


## Example

The application code below performs authentication, authorization and
parameter checks triggered by the extended `route` decorator.
There is no clue in the source about what kind of authentication is used,
which is the whole point: authentication schemes are managed in the configuration,
not explicitely in the application code.
The authorization rule is declared explicitely on each function with the
`authorize` parameter.
Path and HTTP/JSON parameters are type checked and converted automatically
based on type annotations.
Basically, you just have to implement a type-annotated Python function and
most of the crust is managed by Flask and FlaskSimpleAuth.

```Python
from FlaskSimpleAuth import Flask
app = Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

# register hooks
# user_to_password_fun is a function returning the hashed password for a user.
app.get_user_pass(user_to_password_fun)
# user_in_group_fun is a function telling whether a user is in a group.
app.user_in_group(user_in_group_fun)

# users belonging to the "patcher" group can patch "whatever/*"
# the function gets 3 arguments: one int coming from the path (id)
# and the remaining two coming from request parameters (some, stuff).
# "some" is mandatory, stuff is optional because it has a default.
@app.route("/whatever/<id>", methods=["PATCH"], authorize="patcher")
def patch_whatever(id: int, some: int, stuff: str = "wow"):
    # ok to do it, with parameters id, some & stuff
    return "", 204
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives:

```Python
FSA_TYPE = "httpd"     # inherit web-serveur authentication
# or others such as: basic, token (eg jwt), param…
```

If the `authorize` argument is not supplied, the security first approach
results in the route to be forbidden (*403*).

Various aspects of the implemented schemes can be configured with other
directives, with reasonable defaults provided so that not much is really
needed beyond choosing the authentication scheme.


## Description

This module helps managing authentication, authorizations and parameters
in a Flask REST application.

**Authentication** is available through the `get_user` function.
It is performed on demand when the function is called, automatically when
checking for permissions in a per-role authorization model, or possibly
forced for all/most paths.
The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
authentication tokens (custom or jwt passed in headers or as a
parameter), and a fake authentication scheme useful for application testing.
It allows to have a login route to generate authentication tokens.
For registration, support functions allow to hash new passwords consistently
with password checks.

**Authorization** are managed by declaring permissions on a route (eg a role name),
and relies on a supplied function to check whether a user has this role.
This approach is enough for simple authorization management, but would be
insufficient for realistic applications where users can edit their own data
but not those of others.
An additional feature is that the application aborts requests on routes
for which there is no explicit authorization declarations, allowing to
catch forgotten requirements.

**Parameters** expected in the request can be declared, their presence and type
checked, and they are added automatically as named parameters to route functions,
skipping the burden of checking them in typical REST functions. In practice,
importing Flask's `request` global variable is not necessary.

**Utils** include the convenient `Reference` class which allows to share for
import an unitialized variable, and the `CacheOK` decorator to memoize true
answers (eg for user/group checks).


## Documentation

### Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.

Depending on options, the following modules should be installed:

- [passlib](https://pypi.org/project/passlib/) for password management
- [bcrypt](https://pypi.org/project/bcrypt/)  for password hashing (default algorithm)
- [PyJWT](https://pypi.org/project/PyJWT/) for JSON Web Token (JWT)
- [cryptography](https://pypi.org/project/cryptography/) for pubkey-signed JWT

### Features

The module provides a wrapper around the `Flask` class which
extends its capabilities for managing authentication, authorization and
parameters.

This is intended for a REST API implementation serving a remote client application.
It does not make much sense to "login" and "logout" to/from a REST API
because the point of the API is to serve and collect data
to all who deserve it, i.e. are authorized, unlike a web application
which is served while the client is on the page which maintains a session
and should disappear when disconnected as the web browser page is wiped out.
However, there is still a "login" concept which is only dedicated at
obtaining an auth token, that the application client needs to update from
time to time.

You should also consider the many options provided by
[Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth).
However, it cannot be easily configured to change authentication methods.
Also, this module performs authentication before any user code is executed.
It also adds a convenient management of request parameters.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, where the server does not care about
presenting login forms for instance.

### Initialisation

The module is simply initialize by calling its `Flask` constructor
and providing a configuration through `FSA_*` directives, or possibly
by calling some methods to register helper functions.

 - a function to retrieve the password hash from the user name.
 - a function which tells whether a user is in a group or role.

```Python
from FlaskSimpleAuth import Flask
app = Flask("test")
app.config.from_envvar("TEST_CONFIG")

# register hooks

# return password hash if any, or None
@app.get_user_pass
def get_user_pass(user):
    return …

# return whether user is in group
@app.user_in_group
def user_in_group(user, group):
    return …

# they can also be provided in the Flask configuration with
# - FSA_GET_USER_PASS
# - FSA_USER_IN_GROUP
```

Once initialized `app` is a standard Flask object with some additions:

- `route` decorator, an extended version of Flask's own.
- `user_in_group` and `get_user_pass` methods/decorator to register helper functions.
- `get_user` to extract the authenticated user or raise an `AuthException`.
- `current_user` to get the authenticated user if any, or `None`
- `hash_password` and `check_password` to hash or check a password.
- `create_token` to compute a new authentication token for the current user.

Alternatively, it is possible to use the flask extension model, in which case
the `FlaskSimpleAuth` object must be instanciated and routes must be created
using this object:

```Python
from flask import Flask
app = Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

from FlaskSimpleAuth import FlaskSimpleAuth, ALL
fsa = FlaskSimpleAuth(app)

# imaginary blueprint registration on the fsa object:
from DemoAdmin import abp
fsa.register_blueprint(abp, url_path="/admin")

# define a route with an optional paramater "flt"
@fsa.route("/users", methods=["GET"], authorize=ALL)
def get_what(flt: str = None):
    …
```

### Using Authentication, Authorization and Parameter Check

The authentication, authorization and parameter chechs are managed
automatically through the extented `route` decorator.

**Authentication** is transparently activated and controlled by many
configuration directives as described in the next section.

**Authorization** is managed through the added `authorize` parameter
to the `route` decorator.
Three special group names are available in the module: `ANY`
to declare a route opened to anyone, `NONE` to close a route (eg
temporarily) and `ALL` for all authenticated users.
If the authorize directive is absent or empty, the route is forbidden (*403*).
Note that more advanced permissions (eg users can edit themselves) will
still require manual permission checks at the beginning of the function.

**Parameters** are managed transparently, either coming from the route path
or from HTTP/JSON parameters. Type conversion are performed based on
type annotations for all parameters. Parameters with default values are
optional, those without are mandatory.

```Python
@app.route("/somewhere/<stuff>", methods=["POST"], authorize="posters")
def post_somewhere(stuff: str, nstuff: int, bstuff: bool = False):
    …
```

An opened route for user registration with mandatory parameters
could look like that:

```Python
# with FSA_SKIP_PATH = (r"/register", …)
@app.route("/register", methods=["POST"], authorize=ANY)
def post_register(user: str, password: str):
    if user_already_exists_somewhere(user):
        return f"cannot create {user}", 409
    add_new_user_with_hashed_pass(user, app.hash_password(password))
    return "", 201
```

For `token` authentication, a token can be created on a path authenticated
by one of the other methods. The code for that would be:

```Python
# token creation route for all registered users
@app.route("/login", methods=["GET"], authorize=ALL)
def get_login():
    return jsonify(app.create_token(app.get_user())), 200
```

The client application will return the token as a parameter or in
headers for authenticating later requests, till it expires.


### Authentication

Three directives impact how and when authentication is performed.
The main configuration directive is `FSA_TYPE` which governs authentication
methods used by the `get_user` function, as described in the following sections.

- `FSA_TYPE` governs the *how*: `none`, `httpd`, `basic`, `param`, `password`,
`token`… as described in details in the next sections.  Default is `httpd`.

- `FSA_ALWAYS` tells whether to perform authentication in a before request
hook. Default is *True*.  On authentication failures *401* are returned.
Once in a route function, `get_user` will always return the authenticated
user and cannot fail.

- `FSA_SKIP_PATH` is a list of regular expression patterns which are matched
against the request path for skipping systematic authentication when
`FSA_ALWAYS` is enabled.  Default is empty, i.e. authentication is applied
for all paths.

- `FSA_LAZY` tells whether to attempt authentication lazily when checking an
authorization through a `authorize` decorator or argument to the `route`
decorator.
Default is *True*.

- `FSA_CHECK` tells whether to generate a *500* internal error if a route
is missing an explicit authorization check.
Default is *True*.


#### `httpd` Authentication

Inherit web server supplied authentication through `request.remote_user`.
This is the default.

There are plenty authentication schemes available in a web server
such as Apache or Nginx, all of which probably more efficiently implemented
than python code, so this should be the preferred option.
However, it could require significant configuration effort compared to
the application-side approach.

#### `none` Authentication

Use to disactivate authentication.

#### `basic` Authentication

HTTP Basic password authentication, which rely on the `Authorization`
HTTP header in the request.

See also Password Authentication below for how the password is retrieved
and checked.

#### `param` Authentication

HTTP parameter or JSON password authentication.
User name and password are passed as request parameters.

The following configuration directives are available:

 - `FSA_PARAM_USER` parameter name for the user name.
   Default is `USER`.
 - `FSA_PARAM_PASS` parameter name for the password.
   Default is `PASS`.

See also Password Authentication below for how the password is retrieved
and checked.

#### `password` Authentication

Tries `basic` then `param` authentication.

#### `token` Authentication

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

 - `FSA_TOKEN_TYPE` type of token, either *fsa*, *jwt* or `None` to disable.
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

Function `create_token(user)` creates a token for the user depending
on the current scheme.

Token authentication is always attempted unless the secret is empty.
Setting `FSA_TYPE` to `token` results in *only* token authentication to be used.

Token authentication is usually much faster than password verification because
password checks are designed to be slow so as to hinder password cracking.
Another benefit of token is that it avoids sending passwords over and over.
The rational option is to use a password scheme to retrieve a token and then to
use it till it expires.

Internally *jwt* token checks are cached so that even with slow public-key schemes
the performance impact should be low.

#### `fake` Authentication

Trust a parameter for authentication claims.
Only for local tests, obviously.
This is inforced.

The following configuration directive is available:

 - `FSA_FAKE_LOGIN` name of parameter holding the user name.
   Default is `LOGIN`.

#### Password Authentication (`param` or `basic`)

For checking passwords the password (salted hash) must be retrieved through
`get_user_pass(user)`.
This function must be provided by the application when the module is initialized.

The following configuration directives are available to configure
`passlib` password checks:

 - `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
   Default is `bcrypt`.
   See [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
   for available options.
   Set to `None` to disable password checking.
 - `FSA_PASSWORD_OPTIONS` relevant options (for `passlib.CryptContext`).
   Default is `{'bcrypt__default_rounds': 4, 'bcrypt__default_ident': '2y'}`.

Beware that modern password checking is often pretty expensive in order to
thwart password cracking if the hashed passwords are leaked, so that you
do not want to have to use that on every request in real life (eg hundreds
milliseconds for passlib bcrypt *12* rounds).
The above defaults result in manageable password checks of a few milliseconds.
Consider enabling tokens to reduce the authentication load on each request.

Function `hash_password(pass)` computes the password salted digest compatible
with the current configuration.


### Authorization

Role-oriented authorizations are managed through the `authorize` parameter to
the `route` decorator, which provides a just one or possibly a list of roles
authorized to call a route. A role is identified as an integer or a string.
The check calls `user_in_group(user, group)` function to check whether the
authenticated user belongs to any of the authorized roles.

There are three special values that can be passed to the `authorize` decorator:

 - `ANY` declares that no authentication is needed on that route.
 - `ALL` declares that all authenticated user can access this route.
 - `NONE` returns a *403* on all access. It can be used to close a route
   temporarily. This is the default.

The following configuration directive is available:

 - `FSA_LAZY` allows the `authorize` decorator to perform the authentication
   when needed, which mean that the before request hook can be skipped.
   Default is *True*.

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-operation authorization will still be needed.


### Parameters

Request parameters (HTTP or JSON) are translated automatically to
function parameters, by relying on function type annotations.
By default, the decorator guesses whether parameters are mandatory based on
provided default values, i.e. they are optional when a default is provided.

```python
@app.route("/something/<id>", methods=…, authorize=…)
def do_some_id(id: int, when: date, what: str = "nothing):
    # `id` is a integer path-parameter
    # `when` is a mandatory date HTTP or JSON parameter
    # `what` is an optional string HTTP or JSON parameter
    return …
```

Request parameter string values are actually *converted* to the target type.
For `int`, base syntax is accepted for HTTP/JSON parameters, i.e. `0x11`,
`0b10001` and `17` all mean decimal *17*.
For `bool`, *False* is an empty string, `0`, `False` or `F`, otherwise
the value is *True*.
Type `path` is a special `str` type which allow to trigger accepting
any path on a route.

The `required` parameter allows to declare whether all parameters
must be set (when *True*), or whether they are optional (*False*) in which
case *None* values are passed if no defaults are given, or if this is
guessed (when *None*, the default).

The `allparams` parameter makes all request parameters be translated to
named function parameters that can be manipulated as such, as shown below:

```Python
@app.route("/awesome", methods=["PUT"], authorize=ALL, allparams=True)
def put_awesome(**kwargs):
    …
```

A side-effect of passing of request parameters as named function parameters
is that request parameter names must be valid python identifiers,
which excludes keywords such as `pass`, `def` or `for`, unless passed
as keyword arguments.

Custom classes can be used as path and HTTP parameter types, provided that
the constructor accepts a string to convert the parameter value to the
expected type.

```Python
class EmailAddr:
    def __init__(self, addr: str):
        self._addr = addr

@app.route("/mail/<addr>", methods=["GET"], authorize=ALL)
def get_mail_addr(addr: EmailAddr):
    …
```


## `Reference` Object Wrapper

This class implements a generic share-able global variable which can be
used by modules (eg app, blueprints…) with its initialization differed.
Under the hood, most methods calls are forwarded to the object stored
inside the wrapper, so that the Reference object mostly behaves like
the wrapped object.  The wrapped object can be reset at will with `set`.
The `set` method name can be changed with the `set_name` initialization
parameter.

```Python
# file Shared.py
from FlaskSimpleAuth import Reference
stuff = Reference()
def init_app(**conf):
    stuff.set(…)
```

Then in a blueprint:

```Python
# file SubStuff.py
from FlaskSimpleAuth import Blueprint, ALL
from Shared import stuff

sub = Blueprint(…)

@sub.add("/stuff", authorize=ALL):
def get_stuff():
    return str(stuff), 200
```

Then in the app itself:

```Python
# file App.py
from FlaskSimpleAuth import Flask
app = Flask(__name__)

from SubStuff import sub
app.register_blueprint(sub, url_prefix="/sub")

# deferred "stuff" initialization
import Shared
Shared.init_app(…)

…
```


## `CacheOK` Decorator

This decorator memorize the underlying function true answers, but keep trying
on false answers. Call `cache_clear` to reset cache.

```Python
@CacheOK
def user_in_group(user, group):
    return …
```


## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth)
and packaged on [PyPI](https://pypi.org/project/FlaskSimpleAuth/).
Software license is *public domain*.

### 2.2.0

Rename `_setobj` to `set` in `Reference`, with an option to rename the method
if needed.
Shorten `Reference` class implementation.
Add `current_user` to `FlaskSimpleAuth` as well.
Add python documentation on class and methods.
Fix `Reference` issue when using several references.

### 2.1.0

Add `Reference` any object wrapper class.
Add `CacheOK` positive caching decorator.
Add `current_user` function.
Add `none` authentication type.
Add `path` parameter type.
Add more tests.

### 2.0.0

Make the module as an extension *and* a full `Flask` wrapper.
Advertise only the extended `route` decorator in the documentation
(though others are still used internally).
Change passlib bcrypt version to be compatible with Apache httpd.
Allow disabling password checking.
Rename `FSA_TOKEN_HASH` as `FSA_TOKEN_ALGO`.
Disable tokens by setting their type to `None`.
Import Flask `session`, `redirect`, `url_for`, `make_response`,
`abort`, `render_template`, `current_app` objects.
Add parameter support for `date`, `time` and `datetime` in iso format.
Allow to use any type as path parameters, not just Flask predefined ones.
Make blueprints work.
Add special `path` type for parameters taken from the path.

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

Hmmm…
