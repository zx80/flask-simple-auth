# Flask Simple Auth

Simple authentication for [Flask](https://flask.palletsprojects.com/),
which is controled from Flask configuration.

## Description

Help to manage authentication (*not* autorizations) in a Flask application.

The idea is that the authentication is checked in a `before_request` hook,
and can be made available through some global *à-la-Flask* variable.

The module implements password authentication (HTTP Basic, or HTTP/JSON
parameters), simple time-limited authentication tokens, and a fake
authentication mode useful for application testing.

It allows to have a login route to generate authentication tokens.

Compared to [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth),
there is one code in the app which does not need to know about which mode
is being used, so switching between modes only impacts the configuration.

## Example

```Python
# app is a Flask application…

import FlaskSimpleAuth as auth
auth.setConfig(app.config)

# check authentication
LOGIN = None

def set_login():
    global LOGIN
    try:
        LOGIN = auth.get_user()    
    except auth.AuthException as e:
        return Response(e.message, e.status)

app.before_request(set_login)

@app.route("/login", methods=["GET"])
def get_login():
    if LOGIN is None:
        return "", 401
    return jsonify(auth.create_token(LOGIN)), 200
```

## Documentation

## Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth).

No initial release yet.
