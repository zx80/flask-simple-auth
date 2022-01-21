#
# AUTHENTICATION AND AUTHORIZATION HOOKS
#

from typing import Optional
from FlaskSimpleAuth import Flask
from database import db


def get_user_pass(login: str) -> Optional[str]:
    res = db.get_user_data(login=login)
    return res[1] if res else None


def user_in_group(login: str, group: str) -> bool:
    res = db.get_user_data(login=login)
    return bool(res[2]) if res and group == "ADMIN" else res is not None


def check_user_access(login: str, oid: str, mode) -> bool:
    return user_in_group(login, "ADMIN") or login == oid


# module initialization
def init_app(app: Flask):
    app.get_user_pass(get_user_pass)
    app.user_in_group(user_in_group)
    app.register_object_perms("user", check_user_access)
