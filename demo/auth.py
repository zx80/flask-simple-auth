#
# AUTHENTICATION HOOKS
#

from FlaskSimpleAuth import Flask
from database import db

def get_user_pass(login: str):
    res = db.get_user_data(login=login)
    return res[1] if res else None

def user_in_group(login: str, group: str):
    res = db.get_user_data(login=login)
    return bool(res[2]) if res and group == "ADMIN" else res is not None

def init_app(app: Flask):
    app.get_user_pass(get_user_pass)
    app.user_in_group(user_in_group)