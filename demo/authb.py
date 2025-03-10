#
# AUTH management for ADMIN
#
# this version attempts to get cache invalidation right, what a pain.
# it should be waiting for the TTL.

from FlaskSimpleAuth import Blueprint, current_app as app, jsonify as json, err as error
from database import db
from model import User

authb = Blueprint("auth", __name__)

# NOTE
#
# - this could be done directly by the database driver eg with connection option
#   row_factory=psycopg.rows.dict_row or conn.row_factory = sqlite3.Row.
# - this is done explicitely at the app level so as to ease
#   sqlite3/psycopg code compatibility which is a feature of this demo.
# - the generated dict is consistent with the User class.
#
def tup2dict(u):
    assert isinstance(u, (list, tuple)) and len(u) == 6  # sanity check
    return {"aid": u[0], "login": u[1], "email": u[2], "upass": u[3], "admin": u[4], "secret": u[5]}

# GET /auth: get all auth data
@authb.get("/auth", authz="ADMIN")
def get_auth():
    return json(map(tup2dict, db.get_auth_all())), 200


# GET /auth/<login>: get this user data
@authb.get("/auth/<login>", authz="ADMIN")
def get_auth_login(login: str):
    res = db.get_auth_login(login=login)
    _ = res or error(f"no such login: {login}", 404)
    return tup2dict(res), 200


# POST /auth (login, email, pass, admin): add a new user
@authb.post("/auth", authz="ADMIN")
def post_auth(user: User):
    user.upass = app.hash_password(user.upass)  # hash clear text password!
    aid = db.add_auth(a=user)
    app.auth_uncache(user.login)
    app.auth_uncache(user.email)
    return {"aid": aid}, 201


# PUT /auth/<aid> (user): update user data
@authb.put("/auth/<aid>", authz="ADMIN")
def put_auth_aid(aid: int, user: User):
    _ = aid == user.aid or error("inconsistent aid", 400)
    user.upass = app.hash_password(user.upass)  # hash clear text password!
    res = db.get_auth_aid(aid=aid)  # FIXME FOR UPDATE…
    _ = res or error(f"no such aid: {aid}", 404)
    prev = User(**tup2dict(res))
    db.change_auth(a=user)
    # user *previous* data may have changed
    app.auth_uncache(prev.login)
    app.auth_uncache(prev.email)
    return "", 204


# DELETE /auth/<login>: delete this user
@authb.delete("/auth/<login>", authz="ADMIN")
def delete_auth_login(login: str):
    data = db.get_user_data(login=login)
    _ = data or error(f"no such login: {login}", 404)
    db.del_user_login(login=login)
    app.auth_uncache(data[0])
    app.auth_uncache(data[1])  # email as a login
    return "", 204
