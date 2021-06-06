#
# DATABASE CONNECTION AND QUERIES
#

from anodb import DB  # type: ignore
from FlaskSimpleAuth import Reference, Flask, Response
db = Reference()

def db_commit(res: Response):
    db.commit()
    return res

def init_app(app: Flask):
    conf = app.config
    db.set(DB(conf["DB_TYPE"], conf["DB_CONN"], conf["DB_SQL"], conf["DB_OPTIONS"]))
    app.after_request(db_commit)
