#
# AUTH self-care
#
# not a clean REST API because "scare" is relative to the current user…
#

import FlaskSimpleAuth as fsa
from FlaskSimpleAuth import Blueprint, jsonify as json, current_app as app
from database import db

scare = Blueprint("scare", __name__)


# GET /scare: consult one's data
@scare.get("/scare", authorize="ALL")
def get_scare():
    return json(db.get_user_data(login=app.get_user())), 200


# GET /scare/token: return a token for current user
@scare.get("/scare/token", authorize="ALL", auth="basic")
def get_scare_token():
    return json(app.create_token()), 200


# GET /scare/token2: MFA token for current user, basic + code
@scare.get("/scare/token2", authorize="ALL", auth="basic")
def get_scare_token2(code: str, user: fsa.CurrentUser):
    if code != user + ":42":
        return f"invalid validation code for {user}", 400
    return json(app.create_token(user)), 200


# POST /scare (login, pass): register a new user, or 500 if already exists
@scare.post("/scare", authorize="ANY")
def post_scare(login: str, email: str, _pass: str):
    res = db.add_user(login=login, email=email, upass=app.hash_password(_pass), admin=False)
    app.password_uncache(login)  # needed, because previous failures are cached…
    return json(res), 201


# PATCH /scare (opass, npass): change one's password
@scare.patch("/scare", authorize="ALL")
def patch_scare(opass: str, npass: str):
    login = app.get_user()
    res = db.get_user_data(login=login)
    assert res  # ok because authorize did authenticate user
    if not app.check_password(opass, res[2]):
        return "invalid password provided", 403
    db.upd_user_password(login=login, upass=app.hash_password(npass))
    # manual cache cleanup
    app.password_uncache(login)
    app.password_uncache(res[1])  # emails as a login
    return "", 204


# DELETE /scare: unregister
@scare.delete("/scare", authorize="ALL")
def delete_scare():
    login = app.get_user()
    res = db.get_user_data(login=login)
    db.del_user_login(login=login)
    # manual cache cleanup
    app.auth_uncache(login)
    app.auth_uncache(res[1])  # email as a login
    return "", 204
