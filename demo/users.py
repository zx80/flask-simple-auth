#
# AUTH management for ADMIN
#
# this version attempts to get cache invalidation right, what a pain.
# it should be waiting for the TTL.

from FlaskSimpleAuth import Blueprint, current_app as app, jsonify as json, err as error
from database import db

users = Blueprint("users", __name__)


# GET /users: get all users data
@users.get("/users", authz="ADMIN")
def get_users():
    return json(db.get_user_all()), 200


# GET /users/<login>: get this user data
@users.get("/users/<login>", authz=("users", "login"))
def get_users_login(login: str):
    res = db.get_user_data(login=login)
    _ = res or error(f"no such login: {login}", 404)
    return json(res), 200


# POST /users (login, pass, admin): add a new user
@users.post("/users", authz="ADMIN")
def post_users(login: str, email: str, _pass: str, secret: str, admin: bool = False):
    res = db.add_user(login=login, email=email, upass=app.hash_password(_pass), admin=admin, secret=secret)
    app.password_uncache(login)  # needed?
    app.password_uncache(email)  # needed?
    return json(res), 201


# PATCH /users/<login> (pass?, email? admin?, secret?): update user data
@users.patch("/users/<login>", authz="ADMIN")
def patch_users_login(login: str, email: str|None = None,
                      _pass: str|None = None, admin: bool|None = None,
                      secret: str|None = None):
    old = db.get_user_data(login=login)
    assert old is not None
    # FIXME patching on /users/<email> will fail
    if _pass is not None:
        db.upd_user_password(login=login, upass=app.hash_password(_pass))
        app.password_uncache(login)
        app.password_uncache(old[1])  # email as a login
    if email is not None:
        db.upd_user_email(login=login, email=email)
        app.password_uncache(old[1])
    if admin is not None:
        db.upd_user_admin(login=login, admin=admin)
        app.group_uncache(login, "ADMIN")
        app.group_uncache(old[1], "ADMIN")
    if secret is not None:
        db.upd_user_secret(login=login, secret=secret)
    return "", 204


# DELETE /users/<login>: delete this user
@users.delete("/users/<login>", authz=("users", "login"))
def delete_users_login(login: str):
    data = db.get_user_data(login=login)
    _ = data or error(f"no such login: {login}", 404)
    db.del_user_login(login=login)
    app.auth_uncache(data[0])
    app.auth_uncache(data[1])  # email as a login
    return "", 204
