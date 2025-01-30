#
# JWT authorization, relative to current user.
#

from FlaskSimpleAuth import Blueprint, CurrentUser, jsonify as json, current_app as app
from database import db

oauth = Blueprint("oauth", __name__)


# GET /oauth
@oauth.get("/oauth", authz="read", authn="oauth")
def get_oauth(login: CurrentUser):
    return json(db.get_user_data(login=login)), 200


# PATCH /oauth (email): update user email
@oauth.patch("/oauth", authz="write", authn="oauth")
def patch_oauth(email: str, login: CurrentUser):
    db.upd_user_email(login=login, email=email)
    return "", 204


# DELETE /oauth: unregister
@oauth.delete("/oauth", authz="delete", authn="oauth")
def delete_oauth(login: CurrentUser):
    db.del_user_login(login=login)
    app.clear_caches()  # VERY BAD, should wait for cache expiration
    return "", 204
