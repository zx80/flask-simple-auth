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
Support functions allow to hash new passwords.

Compared to [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth),
there is one code in the app which does not need to know about which mode
is being used, so switching between modes only impacts the configuration.

## Example

The application code extract below maintains a `LOGIN` global variable which
holds the authenticated user name for the current request.

There is no clue in the source about what kind of authentication is used,
which is the whole point: authentication methods are managed elsewhere.

```Python
# app is a Flask application…

# initialize module
import FlaskSimpleAuth as auth
auth.setConfig(app)

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

# token creation route
@app.route("/login", methods=["GET"])
def get_login():
    return jsonify(auth.create_token(LOGIN)), 200

# elsewhere
@app.route("/whatever", methods=["POST"])
def post_whatever():
    # check authorization
    if not can_post_whatever(LOGIN):
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

# authentication tokens (only SECRET is mandatory, others have defaults)
FSA_TOKEN_REALM = 'fsa-demo'
FSA_TOKEN_SECRET = 'super-secret-string-used-for-signing-tokens'
FSA_TOKEN_DELAY = 10   # token expiration in minutes
```

## Documentation

WORK IN PROGRESS.

## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth).

No initial release yet.

## TODO

Should it be an object instead of a flat module?

How not to forget autorizations?
 - set a `autorization_checked` variable to False before the request
 - reset it to True when autorization is checked
 - check whether it was done and possibly abort after the request
