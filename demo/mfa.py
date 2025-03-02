#
# Multi-Factor Authentication (with Postgres only)
#
# GET /login (password, eg basic or param)
# - returns an intermediate short-lived (1 minute) token in realm "mfa"
#
# POST /code?code=... (intermediate token authn)
# POST /totp?otp=... (intermediate token authn)
# - the route requires the mfa-token returned by the previous route
# - returns a valid application token if the 2nd authentication (code/otp) is ok
#
# GET /test (token)
# - check successful 2-level authentication
#

import os
import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import jsonify, current_app as app
from database import db

mfa = fsa.Blueprint("mfa", __name__)

# code number of digits
DIGITS = int(os.environ.get("OTP_DIGITS", 6))

# 1st stage, authenticated with a password
@mfa.get("/login", authz="AUTH", authn="basic")
def get_login(user: fsa.CurrentUser):
    # MFA CODE: create a <DIGITS> digits temporary random code
    # NOTE one digit per bytes keeps modulo bias very low
    # NOTE do NOT to use a simple pseudo-random generator for security
    rnd = int.from_bytes(os.urandom(DIGITS)) % 10 ** DIGITS
    assert 0 <= rnd < 10 ** DIGITS
    code = str(rnd + 10 ** DIGITS)[1:]
    assert len(code) == DIGITS
    # store the code, including a timestamp to check for expiration
    done = db.set_user_code(login=user, code=code)
    # NOTE may be rejected, eg reset time is too short (5 seconds)
    done or fsa.err("cannot set user code", 400)
    # TODO send to code to the user (SMS, email, app…)
    #      for testing purpose, the code is stored in a tmp file
    with open(f"./{user}_code.txt", "w") as file:
        file.write(code)
    # MFA TOTP: nothing to do or send beyond the temporary token
    return jsonify(app.create_token(user, realm="mfa", delay=1.0)), 200

# 2nd stage with temporary code, authenticated with mfa token
@mfa.post("/code", authz="AUTH", authn="token", realm="mfa")
def post_code(code: str, user: fsa.CurrentUser):
    # NOTE 1 minute expiration is checked by the query
    refcode = db.get_user_code(login=user)
    if refcode is None or code != refcode:
        fsa.err(f"invalid temporary code for {user}", 401)
    # YES! cleanup used code and generate 2nd stage token
    db.reset_user_code(login=user)
    return jsonify(app.create_token(user, realm=app.name)), 200

# 2nd stage with TOTP, authenticated with mfa token
@mfa.post("/totp", authz="AUTH", authn="token", realm="mfa")
def post_totp(otp: str, user: fsa.CurrentUser):
    secret, last_otp = db.get_user_otp_data(login=user)
    if otp == last_otp:
        fsa.err(f"rejected OTP replay attack on {user}", 401)
    import pyotp
    if not pyotp.TOTP(secret, digits=DIGITS).verify(otp, valid_window=1):
        fsa.err(f"invalid OTP code for {user}", 401)
    # YES! keep otp for replay guard and generate 2nd stage token
    db.set_user_otp_last(login=user, last_otp=otp)
    return jsonify(app.create_token(user, realm=app.name)), 200

# check final token validity
@mfa.get("/test", authz="AUTH", authn="token")
def get_test(user: fsa.CurrentUser):
    return f"MFA succeeded for {user}!", 200
