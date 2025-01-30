#
# Multi-Factor Authentication
#
# GET /login1 (basic)
# - returns an intermediate short-lived token in realm "mfa"
#
# GET /login2?code (intermediate token)
# - returns a valid application token if the 2nd authentication (code) is ok
# - the route requires the mfa-token returned by the previous route
# - note: the expected code is just the name of the user with -code appended…
#
# GET /test (token)
# - check successful 2-level authentication
#

import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import jsonify, current_app as app

mfa = fsa.Blueprint("mfa", __name__)


@mfa.get("/login1", authz="AUTH", authn="basic")
def get_login1(user: fsa.CurrentUser):
    token = app.create_token(user, realm="mfa", delay=1.0)
    return jsonify(token), 200


@mfa.get("/login2", authz="AUTH", authn="token", realm="mfa")
def get_login2(code: str, user: fsa.CurrentUser):
    if code != f"{user}-code":
        return f"invalid 2nd auth for {user}", 401
    else:
        # YES! generate 2nd level token
        return jsonify(app.create_token(user, realm=app.name)), 200


@mfa.get("/test", authz="AUTH")
def get_test(user: fsa.CurrentUser):
    return f"MFA succeeded for {user}", 200
