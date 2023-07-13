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
from FlaskSimpleAuth import jsonify as json, current_app as app, CurrentUser

mfa = fsa.Blueprint("mfa", __name__)


@mfa.get("/login1", authorize="ALL", auth="basic")
def get_login1(user: CurrentUser):
    token = app.create_token(user, realm="mfa", delay=1.0)
    return json(token), 200


@mfa.get("/login2", authorize="ALL", auth="token", realm="mfa")
def get_login2(code: str, user: CurrentUser):
    if code != f"{user}-code":
        return f"invalid 2nd auth for {user}", 401
    else:
        # YES! generate 2nd level token
        return json(app.create_token(user, realm=app._fsa._realm)), 200


@mfa.get("/test", authorize="ALL")
def get_test(user: CurrentUser):
    return f"MFA succeeded for {user}", 200
