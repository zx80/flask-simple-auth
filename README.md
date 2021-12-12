# Flask Simple Auth

Simple authentication, authorization, parameter checks and utils
for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.


## Example

The application code below performs authentication, authorization and
parameter checks triggered by the extended `route` decorator,
or per-method shortcut decorators (`get`, `patch`, `post`…).
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

# users belonging to the "patcher" group can patch "whatever/*"
# the function gets 3 typed parameters: one integer coming from the path (id)
# and the remaining two coming from request parameters (some, stuff).
# "some" is mandatory, stuff is optional because it has a default.
@app.patch("/whatever/<id>", authorize="patcher")
def patch_whatever(id: int, some: int, stuff: str = "wow"):
    # ok to do it, with parameters id, some & stuff
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
in a Flask REST application.

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
However, there is still a "login" concept which is only dedicated to
obtaining an auth token, that the application client needs to update from
time to time.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, where the server does not care about
presenting login forms for instance.

[**Authentication**](#authentication) is available through the `get_user`
function.
It is performed on demand when the function is called, automatically when
checking for permissions in a per-role authorization model, or possibly
forced for all/most paths.
The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
authentication tokens (custom or JWT passed in headers or as a
parameter), and a fake authentication scheme useful for local application
testing.
It allows to have a login route to generate authentication tokens.
For registration, support functions allow to hash new passwords consistently
with password checks.

[**Authorizations**](#authorization) are managed by declaring permissions
on a route (eg a role name), and relies on a supplied function to check
whether a user has this role.
This approach is enough for simple authorization management, but would be
insufficient for realistic applications where users can edit their own data
but not those of others.
An additional feature is that the application aborts requests on routes
for which there is no explicit authorization declarations, allowing to
catch forgotten requirements.

[**Parameters**](#parameters) expected in the request can be declared, their
presence and type checked, and they are added automatically as named parameters
to route functions, skipping the burden of checking them in typical REST functions.
In practice, importing Flask's `request` global variable is not necessary.

[**Utils**](#utils) include the convenient `Reference` class which allows to
share for import an unitialized variable, and the `CacheOK` decorator to
memoize true answers (eg for user/group checks).

### Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.

Depending on options, the following modules should be installed:

- [passlib](https://pypi.org/project/passlib/) for password management.
- [bcrypt](https://pypi.org/project/bcrypt/)  for password hashing (default algorithm).
- [PyJWT](https://pypi.org/project/PyJWT/) for JSON Web Token (JWT).
- [cryptography](https://pypi.org/project/cryptography/) for pubkey-signed JWT.
- [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth) for `http-*` authentication options.
- [Flask CORS](https://github.com/corydolphin/flask-cors) for CORS handling.

### Initialization

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
- `current_user` to get the authenticated user if any, or `None`.
- `hash_password` and `check_password` to hash or check a password.
- `create_token` to compute a new authentication token for the current user.
- `clear_caches` to clear internal caches.

Alternatively, it is possible to use the flask extension model, in which case
the `FlaskSimpleAuth` object must be instanciated and routes must be created
using this object:

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
@fsa.route("/users", methods=["GET"], authorize="ALL")
def get_what(flt: str = None):
    …
```

### Authentication

Three directives impact how and when authentication is performed.
The main configuration directive is `FSA_AUTH` which governs authentication
methods used by the `get_user` function, as described in the following sections.

- `FSA_AUTH` governs the *how*: `none`, `httpd`, `basic`, `param`, `password`,
  `token`… as described in details in the next sections.
  Default is `httpd`.

  If a non-token single scheme is provided, authentication will be `token`
  followed by the provided scheme, i.e. `token` are tried first anyway.

  To take full control of authentication scheme, provide an ordered list.
  Note that it does not always make much sense to mix some schemes, e.g.
  *basic* and *digest* password storage assumptions are distinct and should
  not be merged.
  Also, only one HTTPAuth-based scheme can be active at a time.

- `FSA_MODE` tells when to attempt authentication.

  - With `always`, authentication is performed in a before request hook.
    Once in a route function, `get_user` will always return the authenticated
    user and cannot fail.

  - With `lazy`, it is performed lazily when needed by an authorization
    or when calling the `get_user` function.

  - With `all`, it is always performed in the hook, which may skip some path
    because of `FSA_SKIP_PATH`, and may be re-attempted lazily for path that
    were skipped.

  On authentication failures *401* is returned.
  Default is `lazy`.

- `FSA_SKIP_PATH` is a list of regular expression patterns which are matched
  against the request path for skipping systematic authentication when in
  `always` mode.
  Default is empty, i.e. authentication is applied for all paths.

- `FSA_CHECK` tells whether to generate a *500* internal error if a route
  is missing an explicit authorization check.
  Default is *True*.

- `FSA_CACHE_SIZE` control size of internal lru caches. Default is *1024*.
  *None* means unbounded. Disable with *0*.

- `FSA_401_REDIRECT` url to redirect to on *401*.
  Default is *None*.
  This can be used for the web application login page.

- `FSA_URL_NAME` name of parameter for the target URL after a successful login.
  Default is `URL` if redirect is activated, else *None*.
  Currently, the login page should use this parameter to redirect to when ok.

The authentication scheme attempted on a route can be altered with the
`auth` parameter added to the `route` decorator.
This may be used to restrict the authentication scheme to a *subset*
if those configured globally, and may or may not work otherwise
depending on module internals.
This feature is best avoided but in very particular cases because
it counters a goal of this module which is to remove authentication
considerations from the code and put them in the configuration only.

#### `none` Authentication

Use to disactivate authentication.

#### `httpd` Authentication

Inherit web server supplied authentication through `request.remote_user`.
This is the default.

There are plenty authentication schemes available in a web server such as
[Apache](https://httpd.apache.org/) or [Nginx](https://nginx.org/), all of
which probably more efficiently implemented than python code, so this
should be the preferred option.
However, it could require significant configuration effort compared to
the application-side approach.

#### `basic` Authentication

HTTP Basic password authentication, which rely on the `Authorization`
HTTP header in the request.
Directive `FSA_REALM` provides the authentication realm.

See also [Password Management](#password-management) below for
how the password is retrieved and checked.

#### `http-basic` Authentication

Same as previous based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

Directive `FSA_REALM` provides the authentication realm.
Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
HTTPAuth authentication class.

#### `param` Authentication

HTTP parameter or JSON password authentication.
User name and password are passed as request parameters.

The following configuration directives are available:

 - `FSA_PARAM_USER` parameter name for the user name.
   Default is `USER`.
 - `FSA_PARAM_PASS` parameter name for the password.
   Default is `PASS`.

See also [Password Management](#password-management) below for
how the password is retrieved and checked.

#### `password` Authentication

Tries `basic` then `param` authentication.

#### `http-digest` or `digest` Authentication

HTTP Digest authentication based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

Note that the implementation relies on *sessions*, which may require
the `SECRET_KEY` option to be set to something.
The documentation states that server-side sessions are needed because
otherwise the *nonce* and *opaque* parameters could be reused, which
may be a security issue under some conditions. I'm unsure about that,
but I agree that client-side cookie sessions are strange things best
avoided if possible.

Directive `FSA_REALM` provides the authentication realm.
Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
HTTPAuth authentication class, such as `use_ha1_pw`, as a dictionnary.

See also [Password Management](#password-management) below for
how the password is retrieved and checked. Note that password management
is different for digest authentication because the simple hash of the
password or the password itself is needed for the verification.

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
for instance: `kiva:calvin:20380119031407:4ee89cd4cc7afe0a86b26bdce6d11126`.
The time limit is an easily parsable UTC timestamp *YYYYMMDDHHmmSS* so that
it can be checked easily by the application client.
Compared to `jwt` tokens, they are easy to interpret and compare manually,
no decoding is involved.

The following configuration directives are available:

 - `FSA_TOKEN_TYPE` type of token, either *fsa*, *jwt* or `None` to disable.
   Default is *fsa*.
 - `FSA_TOKEN_CARRIER` how to transport the token: *bearer* (`Authentication`
   HTTP header), *param*, *cookie* or *header*.
   Default is *bearer*.
 - `FKA_TOKEN_NAME` name of parameter or cookie holding the token, or
   bearer scheme, or header name.
   Default is *auth* for *param* and *cookie* carrier,
   *Bearer* for HTTP Authentication header (*bearer* carrier),
   *Auth* for *header* carrier.
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

Function `create_token(user)` creates a token for the user depending
on the current scheme. If `user` is not given, the current user is taken.

Token authentication is always attempted unless the secret is empty.
Setting `FSA_AUTH` to `token` results in *only* token authentication to be used.

Token authentication is usually much faster than password verification because
password checks are designed to be slow so as to hinder password cracking,
whereas token authentication relies on simple hashing for its security.
Another benefit of token is that it avoids sending passwords over and over.
The rational option is to use a password scheme to retrieve a token and then to
use it till it expires.

Token expiration can be understood as a kind of automatic logout, which suggests
to choose the delay with some care depending on the use case.

When the token is carried as a *cookie*, it is automatically updated when 25% of
the delay remains, if possible.

Internally *jwt* token checks are cached so that even with slow public-key schemes
the performance impact should be low.

#### `http-token` Authentication

Token scheme based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).
Carrier is *bearer* or *header*.

Directive `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
HTTPAuth authentication class, such as `header`, as a dictionnary.

#### `fake` Authentication

Trust a parameter for authentication claims.
Only for local tests, obviously.
This is enforced.

The following configuration directive is available:

 - `FSA_FAKE_LOGIN` name of parameter holding the user name.
   Default is `LOGIN`.

#### Password Management

Password authentication is performed for the following authentication
schemes: `param`, `basic`, `http-basic`, `http-digest`, `digest`, `password`.

For checking passwords the password (salted hash) must be retrieved through
`get_user_pass(user)`.
This function must be provided by the application when the module is initialized.
Because this function is cached by default, caches must be reset when users
are changed by calling `clear_caches`.

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
Consider using tokens to reduce the authentication load on each request.

For `digest` authentication, the password must be either in *plaintext* or a
simple MD5 hash ([RFC 2617](https://www.rfc-editor.org/rfc/rfc2617.txt)), and
the authentication setup must be consistent (set `use_ha1_pw` as *True* for the
later).
As retrieving the stored information is enough to steal the password (plaintext)
or at least impersonate a user, consider avoiding `digest` altogether.
HTTP Digest Authentication only makes sense for unencrypted connexions, which
are a bad practice anyway.
It is just provided here for completeness.

Function `hash_password(pass)` computes the password salted digest compatible
with the current configuration.

An opened route for user registration with mandatory parameters
could look like that:

```Python
# with FSA_SKIP_PATH = (r"/register", …)
@app.route("/register", methods=["POST"], authorize="ANY")
def post_register(user: str, password: str):
    if user_already_exists_somewhere(user):
        return f"cannot create {user}", 409
    add_new_user_with_hashed_pass(user, app.hash_password(password))
    return "", 201
```

Because password checks are usually expensive, it is advisable to switch
to `token` authentication. A token can be created on a path authenticated
by a password method:

```Python
# token creation route for all registered users
@app.route("/login", methods=["GET"], authorize="ALL")
def get_login():
    return jsonify(app.create_token()), 200
```

The client application will return the token as a parameter or in
headers for authenticating later requests, till it expires.


### Authorization

Role-oriented authorizations are managed through the `authorize` parameter to
the `route` decorator, which provides just one or possibly a list of roles
authorized to call a route. A role is identified as an integer or a string.
The check calls `user_in_group(user, group)` function to check whether the
authenticated user belongs to any of the authorized roles.
Because this function is cached by default, caches must be reset when roles
are changed by calling `clear_caches`.

There are three special values that can be passed to the `authorize` decorator:

 - `ANY` declares that no authentication is needed on that route.
 - `ALL` declares that all authenticated user can access this route.
 - `NONE` returns a *403* on all access. It can be used to close a route
   temporarily. This is the default.

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
def do_some_id(id: int, when: date, what: str = "nothing"):
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
Type `path` is a special `str` type which allow to trigger accepting
any path on a route.

The `required` parameter allows to declare whether all parameters
must be set (when *True*), or whether they are optional (*False*) in which
case *None* values are passed if no defaults are given, or if this is
guessed (when *None*, the default).

The `allparams` parameter makes all request parameters be translated to
named function parameters that can be manipulated as such, as shown below:

```Python
@app.route("/awesome", methods=["PUT"], authorize="ALL", allparams=True)
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

@app.route("/mail/<addr>", methods=["GET"], authorize="ALL")
def get_mail_addr(addr: EmailAddr):
    …
```

If the constructor does not match, a custom function can be provided
with `register_cast` and will be called automatically to convert
parameters:

```Python
class SomeType:
    …

def str_to_SomeType(s: str) -> SomeType:
    return …

FlaskSimpleAuth.register_cast(SomeType, str_to_SomeType)
```

Finally, python parameter names can be prepended with a `_`,
which is ignored when translating HTTP parameters.
This allows to use python keywords as parameter names, such
as `pass` or `def`.


### Utils

Utilities include the `Reference` generic object wrapper class, the
`CacheOK` decorator, and CORS handling.

#### `Reference` Object Wrapper

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
from FlaskSimpleAuth import Blueprint
from Shared import stuff

sub = Blueprint(…)

@sub.get("/stuff", authorize="ALL"):
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


#### `CacheOK` Decorator

This decorator memorize the underlying function true answers, but keep trying
on false answers. Call `cache_clear` to reset cache.

```Python
@CacheOK
def user_in_group(user, group):
    return …
```


#### CORS -- Cross Origin Resource Sharing

[CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) is a
security feature implemented by web browsers, and does only make sense for
web applications. It allows the browser to check whether a server
accepts requests from a given origin (*i.e.* from JavaScript code
provided by some domain).

The module allows to enable CORS request handling on the application
by setting the `FSA_CORS` directive to true, and to add additional
options with `FSA_CORS_OPTIONS`.  The implementation is delegated to the
[`flask_cors`](https://pypi.org/project/Flask-Cors/) Flask extension
which must be available if the feature is enabled.

Setting the directive to True allows requests from any origin.
The default is not to enable CORS.


## License

This software is public domain.
All software has bug, this is software, hence…
Beware that you may lose your hairs or your friends because of it.
If you like it, feel free to send a postcard to the author.


## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth)
and packaged on [PyPI](https://pypi.org/project/FlaskSimpleAuth/).
Software license is *public domain*.

#### 4.5.0 on 2021-12-12

Add `FSA_PASSWORD_LEN` and `FSA_PASSWORD_RE` directives to check
for password quality when hashing.
Remove `VERSION` and `VERSION\_NUM`, replaced with `__version__`,
although not from the package resources because of some issue obscure issue…

#### 4.4.0 on 2021-12-11

Add support for CORS with directives `FSA_CORS` and `FSA_CORS_OPTIONS`.

#### 4.3.1 on 2021-12-05

Add `FSA_TOKEN_RENEWAL` directive to manage automatic renewal of cookie-based
authentication tokens.
Fix version in module.

#### 4.3.0 on 2021-10-14

Rename `FSA_TOKEN_REALM` as `FSA_REALM`, because it is not token specific.
Make demo work with psycopg 3.

#### 4.2.0 on 2021-09-14

Add `register_cast` to provide a cast function for custom types, if the type
itself would not work.
Add `VERSION` as a string and `VERSION_NUM` as an integer tuple.
Improve documentation.
Allow to use Python keywords as HTTP parameters by prepending the
parameter with a `_`.

#### 4.1.0 on 2021-06-12

Add support for per-method decorator shortcuts to `Flask` wrapper class.
Add `FSA_LOGGING_LEVEL` directive.
Make `current_user` attempt an authentication, but not fail on errors.
Check configuration directive names to warn about possible typos or errors.
Warn about some unused directives.
Check `get_user_pass` and `user_in_group` returned types.
Update documentation.
Add a demo application.

#### 4.0.0 on 2021-06-01

Port to Flask 2.0, working around a regression on `request.values` handling.
Add support for Flask 2.0 per-method decorator shortcuts `get`, `post`, `put`,
`delete` and `patch`.
Rework documentation.
Minor style improvements.
Fix `all` authentication mode.

#### 3.1.1 on 2021-05-31

Tell setup that Flask 2.0 is not yet supported.

#### 3.1.0 on 2021-04-17

Defer password manager setup till it is actually needed, so as to avoid
importing `passlib` for nothing.
Do not attempt to re-create a token if it is not possible, i.e. when
relying on a third party token provider.
Allow to fully control the list of authentication schemes.
Allow to control the authentication scheme on a route.
Improve test code coverage.

#### 3.0.0 on 2021-04-07

Add `FSA_CACHE_SIZE` to control caches.
Merge `FSA_ALWAYS` and `FSA_LAZY` in a single `FSA_MODE` directive
with 3 values: `always`, `lazy` and `all`.
Make `ANY`, `ALL` and `NONE` special groups simple strings as well.
Package as a one file module (again), and add more files to packaging.

#### 2.5.0 on 2021-04-04

Add *header* carrier for authentication tokens.
Make it work both with internal and HTTPAuth implementations.
Force HTTPAuth implementation on `http-token`.

#### 2.4.1 on 2021-03-29

Fix packaging issue… the python file was missing.
Add `digest` as a synonymous for `http-digest`.
Improve documentation.

#### 2.4.0 on 2021-03-29

Add `http-basic`, `http-digest` and `http-token` authentication schemes based on flask-HTTPAuth.
Add coverage report on tests.
Distribute as a one file python module.
Only simplify realm for *fsa* tokens.
Renew cookies when they are closing expiration.

#### 2.3.0 on 2021-03-27

Use a fully dynamic method for `set` in `Reference`.
Add a `string` type.
Add caching of `get_user_pass` and `user_in_group` helpers.
Add `clear_caches` method.
Warn on missing `authorize` on a route declaration.
Add `FSA_TOKEN_CARRIER` to specify how token auth is transfered,
including a new *cookie* option.
Rename `FSA_TYPE` to `FSA_AUTH`.
Make `create_token` argument optional.
Add `WWW-Authenticate` headers when appropriate.
Set `Content-Type` to `text/plain` on generated responses.

#### 2.2.1 on 2021-03-22

Partial fix for method renaming in `Reference`.

#### 2.2.0 on 2021-03-22

Rename `_setobj` to `set` in `Reference`, with an option to rename the method
if needed.
Shorten `Reference` class implementation.
Add `current_user` to `FlaskSimpleAuth` as well.
Add python documentation on class and methods.
Fix `Reference` issue when using several references.

#### 2.1.0 on 2021-03-21

Add `Reference` any object wrapper class.
Add `CacheOK` positive caching decorator.
Add `current_user` function.
Add `none` authentication type.
Add `path` parameter type.
Add more tests.

#### 2.0.0 on 2021-03-16

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

#### 1.9.0 on 2021-03-10

Add *bearer* authorization for tokens and make it the default.
Add *JWT* tokens, both hmac and pubkey variants.
Add *500* generation if a route is missing an authorization declaration.
Add convenient `route` decorator.
Add type inference for HTTP/JSON parameters based on default value, when provided.
Add type inference for root path parameters based on function declaration.

#### 1.8.1 on 2021-03-02

Fix typo in distribution configuration file.

#### 1.8.0 on 2021-03-02

Merge `autoparams` and `parameters` decorators into a single `parameters`
decorator.
Make it guess optional parameters based on default values.
Fix conversion issues with boolean type parameters.
Enhance integer type to accept other base syntaxes.
Improve documentation to advertise the simple and elegant approach.
Implement decorator with functions instead of a class.

#### 1.7.0 on 2021-03-01

Simplify code.
Add `FSA_ALWAYS` configuration directive and move the authentication before request
hook logic inside the module.
Add `FSA_SKIP_PATH` to skip authentication for some paths.
Update documentation to reflect this simplified model.
Switch all decorators to functions.

#### 1.6.0 on 2021-02-28

Add `autoparams` decorator with required or optional parameters.
Add typed parameters to `parameters` decorator.
Make `parameters` pass request parameters as named function parameters.
Simplify `authorize` decorator syntax and implementation.
Advise `authorize` *then* `parameters` or `autoparams` decorator order.
Improved documentation.

#### 1.5.0 on 2021-02-27

Flask *internal* tests with a good coverage.
Switch to `setup.cfg` configuration.
Add convenient `parameters` decorator.

#### 1.4.0 on 2021-02-23

Add `FSA_LAZY` configuration directive.
Simplify code.
Improve warning on short secrets.
Repackage…

#### 1.3.0 on 2021-02-23

Improved documentation.
Reduce default token signature length and default token secret.
Warn on random or short token secrets.

#### 1.2.0 on 2021-02-22

Add grace time for auth token validity.
Some code refactoring.

#### 1.1.0 on 2021-02-22

Add after request module cleanup.

#### 1.0.0 on 2021-02-21

Add `authorize` decorator.
Add `password` authentication scheme.
Improved documentation.

#### 0.9.0 on 2021-02-21

Initial release in beta.


### TODO

- test `FSA_HTTP_AUTH_OPTS`?
- add `any` token scheme?
- automate URL-parameter redirect?
