#
# DATABASE CONNECTION AND QUERIES
#

from anodb import DB  # type: ignore
from FlaskSimpleAuth import Reference, Flask, Response

# this reference will behave as a DB
db = Reference()

def db_commit(res: Response):
    db.commit()
    return res

# module initialization
def init_app(app: Flask):
    cf = app.config
    db.set(DB(cf["DB_TYPE"], cf["DB_CONN"], cf["DB_SQL"], cf["DB_OPTIONS"]))
    app.after_request(db_commit)
