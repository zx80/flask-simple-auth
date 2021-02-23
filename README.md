# Flask Simple Auth

Simple authentication and authorization for [Flask](https://flask.palletsprojects.com/),
which is controled from Flask configuration.


## Description

Help to manage authentication and authorizations in a Flask application.

For authentication, the idea is that the authentication is checked in a
`before_request` hook, and can be made available through some global
*à-la-Flask* variable.

The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
simple time-limited authentication tokens, and
a fake authentication scheme useful for application testing.

It allows to have a login route to generate authentication tokens.
Support functions allow to hash new passwords consistently with password
checks performed by the module.

For authorization, a simple decorator allows to declare required permissions
on a route (eg a role name), and relies on a supplied function to check
whether a user has this role. This is approach is enough for basic
authorization management, but would be insufficient for most application where
user can edit their own data but not those of others.

Compared to [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth),
there is one code in the app which does not need to know about which authentication
scheme is being used, so switching between schemes only impacts the configuration,
*not* the application code.


## Simple Example

The application code extract below maintains a `LOGIN` global variable which
holds the authenticated user name for the current request.
There is no clue in the source about what kind of authentication is used,
which is the whole point: authentication schemes are managed elsewhere, not
explicitely in the application code.

```Python
# app is the Flask application…
# user_to_password_fun is a function returning the hashed password for a user.
# user_in_group_fun is a function telling whether a user is in a group.

# initialize module
import FlaskSimpleAuth as auth
auth.setConfig(app, user_to_password_fun, user_in_group_fun)

# mandatory authentication
LOGIN = None

def set_login():
    global LOGIN
    LOGIN = None                  # remove previous value, just in case
    try:
        LOGIN = auth.get_user()    
    except auth.AuthException as e:
        return Response(e.message, e.status)
    assert LOGIN is not None      # defensive check

app.before_request(set_login)

# elsewhere use the authentication
# here implicitely by the authorize decorator
@app.route("/whatever", methods=["PATCH"])
@auth.authorize("patcher")
def patch_whatever():
    # ok to do it, then
    return "", 204

# here explicitely at the beginning of the function
@app.route("/something", methods=["PUT"])
def put_something():
    if not can_put_something(LOGIN):
        return "", 403
    # else ok to do it, then
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

Various aspects of the implemented schemes can be configured with other
directives, with reasonable defaults provided so that not much is really
needed beyond choosing the authentication scheme.
See below for details.


## Documentation

### Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.

### Features

This simple module allows configurable authentication (`FSA_TYPE`):

- `httpd` web-server checked authentication passed in the request.

- `basic` http basic auth with a function hook for getting
  the password hash.

- `param` same with http parameter-provided login/password.

- `password` tries `basic` then `param`.

- `token` auth uses a signed parameter to authenticate a
  user in a realm for some limited time. The token can be
  obtained by actually authenticating with other methods.

- `fake` parameter-based auth for fast and simple testing
  the claimed login is coldly trusted…

I have considered [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth)
obviously, which provides many options, but I do not want to force their
per-route model and explicit classes but rather rely on mandatory request hooks
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

import FlaskSimpleAuth as auth
auth.setConfig(app, get_user_password, user_in_group)
```

Then the module can be used to retrieve the authenticated user with `get_user`.
This functions raises `AuthException` on failures.

A good practice (IMHO) is to use a before request hook to set a global variable
with the value and warrant that the authentication is always checked.

Some path may require to skip authentication, for instance registering a new user.
This can be achieved simply by checking `request.path`.

```Python
LOGIN: Optional[str] = None

def set_login():
    global LOGIN
    LOGIN = None      # not really needed, but this is safe
    if request.path == "/register":
        return
    try:
        LOGIN = auth.get_user()
    except auth.AuthException as e:
        # before request hooks can return an alternate response
        return Response(e.message, e.status)

app.before_request(set_login)
```

### Using Authentication and Authorization

Then all route functions can take advantage of this information to check for
authorizations with a decorator:

```Python
@app.route("/somewhere", methods=["POST"])
@auth.authorize("posters")
def post_somewhere():
    …
```

Note that more advanced permissions (eg users can edit themselves) will
still require manual permission checks at the beginning of the function.

An opened route for user registration could look like that:

```Python
@app.route("/register", methods=["POST"])
def post_register():
    assert LOGIN is None
    params = request.values if request.json is None else request.json
    if "user" not in params or "pass" not in params:
        return "missing parameter", 404
    # FIXME should handle an existing user and respond appropriately
    add_new_user_with_hashed_pass(params["user"], auth.hash_password(params["pass"]))
    return "", 201
```

For `token` authentication, a token can be created on a path authenticated
by one of the other methods. The code for that would be as simple as:

```Python
# token creation route
@app.route("/login", methods=["GET"])
def get_login():
    return jsonify(auth.create_token(LOGIN)), 200
```

The client application will return the token as a parameter for
authenticatiing later requests, till it expires.

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
The token syntax is: `<realm>:<user>:<limit>:<signature>`,
for instance: `kiva:calvin:20210221160258:4ee89cd4cc7afe0a86b26bdce6d11126`.
The time limit is an easily parsable UTC timestamp *YYYYMMDDHHmmSS* so that
it can be checked easily by the application client.

The following configuration directives are available:

 - `FSA_TOKEN_REALM` realm of token.
   Default is the simplified lower case application name.
 - `FKA_TOKEN_NAME` name of parameter holding the auth token.
   Default is `auth`.
 - `FSA_TOKEN_SECRET` secret string used for signing tokens.
   Default is a system-generated random string containing 128 bits.
   This default with only work with itself, as it is not shared
   across server instances or processes. Set to `None` to disable tokens.
 - `FSA_TOKEN_DELAY` number of minutes of token validity.
   Default is *60* minutes. 
 - `FSA_TOKEN_GRACE` number of minutes of grace time for token validity.
   Default is *0* minutes.
 - `FSA_TOKEN_HASH` hash algorithm used to sign the token.
   Default is `blake2s`.
 - `FSA_TOKEN_LENGTH` number of hash bytes kept for token signature.
   Default is *16*.

Function `create_token(user)` creates a token for the user.

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
This function must be provided by the application.

The following configuration directives are available to configure
`passlib` password checks:

 - `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
   Default is `bcrypt`. See [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
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

The decorator expects a list or possibly one group identifier.
A group identifier can be either a name or a number.
When several groups are specified, any will allow the operation to proceed.

```Python
# group ids
ADMIN, WRITE, READ = 1, 2, 3

@app.route("/some/place", methods=["POST"])
@auth.authorize([ ADMIN, WRITE ])
def post_some_place():
    …
```

The check will call `user_in_group(user, group)` function to check whether the
authenticated user belongs to any of the authorized groups.

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-operation authorization will still be needed.


## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth).

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
 - add support for JWT?

Implementation
 - should it be an object instead of a flat module?
 - expand tests

How not to forget autorizations?
 - set a `autorization_checked` variable to False before the request
 - reset it to True when autorization is checked
 - check whether it was done and possibly abort after the request

