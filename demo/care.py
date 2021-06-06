#
# AUTH self-care
#
# not a clean REST API because "self" is relative to the current user…
#

from FlaskSimpleAuth import Blueprint, jsonify as json, current_app as app
from database import db

care = Blueprint("care", __name__)

# GET /self: consult one's data
@care.get("/self", authorize="ALL")
def get_self():
    return json(db.get_user_data(login=app.get_user())), 200

# GET /self/token: return a token for current user
@care.get("/self/token", authorize="ALL")
def get_self_token():
    return json(app.create_token()), 200

# POST /self (login, upass): register a new user, or 500 if already exists
@care.post("/self", authorize="ANY")
def post_self(login: str, upass: str):
    db.add_user(login=login, upass=app.hash_password(upass), admin=False)
    app.clear_caches()
    return "", 201

# PATCH /self (opass, npass): change one's password
@care.patch("/self", authorize="ALL")
def patch_self(opass: str, npass: str):
    login = app.get_user()
    res = db.get_user_data(login=login)
    assert res
    if not app.check_password(opass, res[1]):
        return "invalid password provided", 403
    db.upd_user_password(login=login, upass=app.hash_password(npass))
    app.clear_caches()
    return "", 204

# DELETE /self: unregister
@care.delete("/self", authorize="ALL")
def delete_self():
    db.del_user_login(login=app.get_user())
    app.clear_caches()
    return "", 204
