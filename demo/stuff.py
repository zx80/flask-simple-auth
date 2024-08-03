#
# STUFF are managed by all AUTH-enticated users
#

from FlaskSimpleAuth import Blueprint, jsonify as json, err as error
from database import db

stuff = Blueprint("stuff", __name__)


# GET /stuff: get all stuff
@stuff.get("/stuff", authorize="AUTH")
def get_stuff(pattern: str|None = None):
    res = db.get_stuff_like(pattern=pattern) if pattern else db.get_stuff_all()
    return json(res), 200


# POST /stuff: add new stuff
@stuff.post("/stuff", authorize="AUTH")
def post_stuff(sname: str):
    res = db.add_stuff(sname=sname)
    return json(res), 201


# GET /stuff/<sid>: get this stuff
@stuff.get("/stuff/<sid>", authorize="AUTH")
def get_stuff_sid(sid: int):
    res = db.get_stuff_sid(sid=sid)
    _ = res or error(f"no such sid: {sid}", 404)
    return json(res), 200


# DELETE /stuff/<sid>: delete this stuff
@stuff.delete("/stuff/<sid>", authorize="AUTH")
def delete_stuff_sid(sid: int):
    db.del_stuff_sid(sid=sid)
    return "", 204


# PATCH /stuff/<sid>: update this stuff
@stuff.patch("/stuff/<sid>", authorize="AUTH")
def patch_stuff_sid(sid: int, sname: str):
    res = db.upd_stuff_sid(sid=sid, sname=sname)
    _ = res or error(f"no such sid: {sid}", 404)
    return "", 204
