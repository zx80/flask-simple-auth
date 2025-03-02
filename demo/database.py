#
# DATABASE CONNECTION AND QUERIES
#

from typing import Any
from anodb import DB  # type: ignore
from FlaskSimpleAuth import Reference, Flask, Response  # type: ignore

# this reference will behave as a DB
db: Any = Reference()


# NOTE this is simplistic!
def db_commit(res: Response):
    """Close current transation."""
    if res.status_code < 400:
        db.commit()
    else:
        db.rollback()
    return res


def init_app(app: Flask):
    """Database stuff initialization."""
    db.set_fun(lambda i: DB(**app.config["DATABASE"]))
    app.after_request(db_commit)
