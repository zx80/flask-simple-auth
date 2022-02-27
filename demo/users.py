#
# AUTH management for ADMIN
#

from FlaskSimpleAuth import Blueprint, current_app as app, jsonify as json
from database import db

users = Blueprint("users", __name__)


# GET /users: get all users data
@users.get("/users", authorize="ADMIN")
def get_users():
    return json(db.get_user_all()), 200


# GET /users/<login>: get this user data
@users.get("/users/<login>", authorize=("users", "login"))
def get_users_login(login: str):
    res = db.get_user_data(login=login)
    return (json(res), 200) if res else ("", 404)


# POST /users (login, pass, admin): add a new user
@users.post("/users", authorize="ADMIN")
def post_users(login: str, email: str, _pass: str, admin: bool = False):
    res = db.add_user(login=login, email=email, upass=app.hash_password(_pass), admin=admin)
    # NOTE bad, should rather wait for cache expiration
    app.clear_caches()
    return json(res), 201


# PATCH /users/<login> (pass?, email? admin?): update user data
@users.patch("/users/<login>", authorize="ADMIN")
def patch_users_login(login: str, email: str = None,
                      _pass: str = None, admin: bool = None):
    if _pass is not None:
        db.upd_user_password(login=login, upass=app.hash_password(_pass))
    if email is not None:
        db.upd_user_email(login=login, email=email)
    if admin is not None:
        db.upd_user_admin(login=login, admin=admin)
    # NOTE bad, should rather wait for cache expiration
    app.clear_caches()
    return "", 204


# DELETE /users/<login>: delete this user
@users.delete("/users/<login>", authorize=("users", "login"))
def delete_users_login(login: str):
    res = db.get_user_data(login=login)
    if not res:
        return "", 404
    db.del_user_login(login=login)
    # NOTE bad, should rather wait for cache expiration
    app.clear_caches()
    return "", 204
