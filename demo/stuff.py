#
# STUFF are managed by all AUTH-enticated users
#

from FlaskSimpleAuth import Blueprint, jsonify as json
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
    return (json(res), 200) if res else ("", 404)


# DELETE /stuff/<sid>: delete this stuff
@stuff.delete("/stuff/<sid>", authorize="AUTH")
def delete_stuff_sid(sid: int):
    db.del_stuff_sid(sid=sid)
    return "", 204


# PATCH /stuff/<sid>: update this stuff
@stuff.patch("/stuff/<sid>", authorize="AUTH")
def patch_stuff_sid(sid: int, sname: str):
    # FIXME should be FOR UPDATE, but sqlite does not support that,
    # or check that update below did something
    if not db.get_stuff_sid(sid=sid):
        return "", 404
    db.upd_stuff_sid(sid=sid, sname=sname)
    return "", 204
