# Flask Simple Auth

Simple authentication for [Flask](https://flask.palletsprojects.com/),
which is controled from Flask configuration.

## Description

Help to manage authentication (*not* autorizations) in a Flask application.

The idea is that the authentication is checked in a `before_request` hook,
and can be made available through some global *à-la-Flask* variable.

The module implements inheriting the web-server authentication,
password authentication (HTTP Basic, or HTTP/JSON parameters),
simple time-limited authentication tokens, and
a fake authentication mode useful for application testing.

It allows to have a login route to generate authentication tokens.
Support functions allow to hash new passwords consistently with password checks.

Compared to [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth),
there is one code in the app which does not need to know about which mode
is being used, so switching between modes only impacts the configuration,
not the application code.

## Example

The application code extract below maintains a `LOGIN` global variable which
holds the authenticated user name for the current request.

There is no clue in the source about what kind of authentication is used,
which is the whole point: authentication methods are managed elsewhere.

```Python
# app is a Flask application…

# initialize module
import FlaskSimpleAuth as auth
auth.setConfig(app, user_to_password_function)

# mandatory authentication
# note: some routes may need to skip this, eg for registering new users.
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

# elsewhere
@app.route("/whatever", methods=["PATCH"])
def patch_whatever():
    # check authorization
    if not can_patch_whatever(LOGIN):
        return "", 403
    # ok to do it
    return "", 201
```

Authentication is manage from the application flask configuration
with `FSA_*` (Flask simple authentication) directives:

```Python
FSA_TYPE = 'httpd'     # inherit web-serveur authentication
# OR others such as:
FSA_TYPE = 'basic'     # HTTP Basic auth
```

Various aspects of the implemented schemes can be configured with other
directives, with reasonable defaults provided so that not much is really
needed beyond choosing the authentication scheme.
See below for details.


## Documentation

### Install

Use `pip install flask-simple-auth` to install the module, or whatever
other installation method.

### Features

This simplistic module allows configurable authentication (`FSA_TYPE`):

- `httpd` web-server checked authentication passed in the request.

- `fake` parameter-based auth for fast and simple testing
  the claimed login is coldly trusted…

- `basic` http basic auth with a function hook for getting
  the password hash. Beware that modern password checking is often pretty
  expensive, so that you do not want to have to use that on
  every request in real life (eg 400 ms for passlib bcrypt 12 rounds,
  although 2 ms for 4 rounds is manageable).

- `param` same with http parameter-provided login/password.

- `token` auth uses a signed parameter to authenticate a
  user in a realm for some limited time. The token can be
  obtained by actually authenticating with previous methods.

I have considered flask\_httpauth obviously, which provides many options,
but I do not want to force their per-route model and explicit classes
but rather rely on mandatory request hooks and have everything managed from
the configuration file to easily switch between schemes.

Note that this is intended for a REST API implementation serving
a remote application. It does not make much sense to "login" and "logout"
to/from a REST API because the point of the API is to serve and collect data
to all who deserve it, i.e. are authorized, unlike a web application
which is served while the client is on the page and should disappear when
disconnected as the web browser page is wiped out. However, there is still
a "login" concept which is only dedicated at obtaining an auth token.

Note that web-oriented flask authentication modules are not really
relevant in the REST API context, were the server does not care about
presenting login forms for instance.

### Initialisation

The module is initialized by calling `setConfig` with two arguments:

 - the Flask application object.
 - a function to retrieve the password hash from the user name.

```Python
# app is already initialized and configured the Flask application

# return password hash if any, or None
def get_user_password(user):
    return …

import FlaskSimpleAuth as auth
auth.setConfig(app, get_user_password)
```

Then the module can be used to retrieve the authenticated user with `get_user`.
This functions raises an `AuthException` exception on failures.

A good practice (IMHO) is to use a before request hook to set a global variable
with the value and warrant that the authentication is always checked.

Some path may require to skip authentication, for instance registering a new user.
This can be achieved simply by checking `request.path`.

```Python
LOGIN: Optional[str] = None

def set_login():
    global LOGIN
    LOGIN = None  # not really needed, but this is safe
    if request.path == "/register":
        return
    try:
        LOGIN = auth.get_user()
    except auth.AuthException as e:
        # before request hooks can return an alternate response
        return Response(e.message, e.status)

app.before_request(set_login)
```

### Using Authentication

Then all route functions can take advantage of this information to check for
autorizations:

```Python
@app.route("/somewhere", methods=["POST"])
def post_somewhere():
    if not can_post_somewhere(LOGIN):
        return "", 403
    # else permissions is granted, do the job!
    …
```

A non authenticated route for user registration could look like that:

```Python
@app.route("/register", methods=["POST"])
def post_register():
    assert LOGIN is None
    params = request.values if request.json is None else request.json
    if "user" not in params or "pass" not in params:
        return "missing parameter", 404
    # FIXME should handle an existing user and respond appropriately
    insert_new_user_with_hashed_pass(params["user"], auth.hash_pass(params["pass"]))
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

The the client application will return the token as a parameter for
authentication later requests, till it expires.

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

HTTP Basic password authentication.

See also Password Authentication below for how the password is retrieved.

### `param` Authentication

HTTP parameter or JSON password authentication.

The following configuration directives are available:

 - `FSA_PARAM_USER` parameter name for the user name.
   Default is `USER`.
 - `FSA_PARAM_PASS` parameter name for the password.
   Default is `PASS`.

See also Password Authentication below for how the password is retrieved.

### `token` Authentication

Only rely on signed tokens for authentication.
A token certifies that a user is authenticated up to some time limit.
The token syntax is: `<realm>:<user>:<limit>:<signature>`

The following configuration directives are available:

 - `FSA_TOKEN_REALM` realm of token.
   Default is the simplified lower case application name.
 - `FKA_TOKEN_NAME` name of parameter holding the auth token.
   Default is `auth`.
 - `FSA_TOKEN_SECRET` secret string used for signing tokens.
   Default is a system-generated random string containing 128 bits.
   This default with only work with itself, as it cannot be shared
   across server instances.
 - `FSA_TOKEN_DELAY` number of minutes a token validity.
   Default is *60* minutes. 
 - `FSA_TOKEN_HASH` hash algorithm used to sign the token.
   Default is `blake2s`.
 - `FSA_TOKEN_LENGTH` number of hash bytes kept for token signature.
   Default is *32*.

Function `create_token(user)` creates a token for the user.

### `fake` Authentication

Trust a parameter for authentication claims.
Only for local tests.

The following configuration directive is available:

 - `FSA_FAKE_LOGIN` name of parameter holding the user name.
   Default is `LOGIN`.

### Password Authentication (`param` or `basic`)

For checking passwords the password (hash) must be retrieved through
`get_user_password(user)`. 
This function must be provided by the application.

The following configuration directives are available to configure
`passlib` password checks:

 - `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
   Default is `bcrypt`.
 - `FSA_PASSWORD_OPTIONS` relevant options (for `passlib.CryptContext`).
   Default is `{'bcrypt__default_rounds': 4}`.

These defaults result in manageable password checks of a few milliseconds.

Function `hash_password(pass)` computes the password salted digest compatible
with the configuration.

## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth).

### 0.9.0

Initial release in beta.

## TODO

Features
 - implement 'password' which does anything with a password?
 - test 'param'?
 - better control which schemes are attempted?

Implementation
 - should it be an object instead of a flat module?
 - expand tests

How not to forget autorizations?
 - set a `autorization_checked` variable to False before the request
 - reset it to True when autorization is checked
 - check whether it was done and possibly abort after the request

