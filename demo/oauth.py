#
# JWT authorization, relative to current user.
#

from FlaskSimpleAuth import Blueprint, jsonify as json, current_app as app
from database import db

oauth = Blueprint("oauth", __name__)


# GET /oauth
@oauth.get("/oauth", authorize="read", auth="oauth")
def get_oauth():
    return json(db.get_user_data(login=app.get_user())), 200


# PATCH /oauth (email): update user email
@oauth.patch("/oauth", authorize="write", auth="oauth")
def patch_oauth(email: str):
    db.upd_user_email(login=app.get_user(), email=email)
    return "", 204


# DELETE /oauth: unregister
@oauth.delete("/oauth", authorize="delete", auth="oauth")
def delete_oauth():
    db.del_user_login(login=app.get_user())
    app.clear_caches()  # BAD, should wait for cache expiration
    return "", 204
