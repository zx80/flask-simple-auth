#
# Multi-Factor Authentication
#
# This MFA implementation is minimal and relies on some FSA internals
# to generate and check an intermediate token.
#
# GET /login1 (basic)
# - returns an intermediate token
#
# GET /login2?secret (intermediate token)
# - returns a valid application token if the 2nd authentication is ok
#
# GET /test (token)
# - check successful 2-level authentication

import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import jsonify as json, current_app as app, CurrentUser

mfa = fsa.Blueprint("mfa", __name__)

REALM = "mfa"
SECRET = "mfa-intermediate-token-secret"


@mfa.get("/login1", authorize="ALL", auth="basic")
def get_login1(user: CurrentUser):
    token = app.create_token(user, REALM, secret=SECRET)
    return json(token), 200


# NOTE this route is falsely open, the intermediate token is checked manually
@mfa.get("/login2", authorize="ANY")
def get_login2(code: str = None):
    # NOTE get_token may raise an error?
    token = app.get_token()
    if not token:
        return "mfa token not found", 401
    user = app.check_token(token, REALM, secret=SECRET)
    if not user:
        return f"invalid token: {token}", 401
    elif code != f"{user}-code":
        return f"invalid 2nd auth for {user}", 401
    else:
        # YES! generate 2nd level token
        return json(app.create_token(user)), 200


@mfa.get("/test", authorize="ALL")
def get_test(user: CurrentUser):
    return f"MFA succeded for {user}", 200
