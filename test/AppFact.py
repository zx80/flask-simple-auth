# test factory pattern

from FlaskSimpleAuth import Flask, ALL, jsonify as json

from Auth import get_user_pass, user_in_group, ADMIN, UP
from SubApp import subapp

import Shared
from Shared import something

def create_app(**config):
    app = Flask("4ops")
    app.config.update(FSA_AUTH="fake", FSA_MODE="always", FSA_GET_USER_PASS=get_user_pass, FSA_USER_IN_GROUP=user_in_group)
    app.config.update(**config)
    app.register_blueprint(subapp, url_prefix="/b")

    # self permission
    def check_users_access(user, val, mode):
        return user == val if val in UP else None

    app.register_object_perms("users", check_users_access)

    # shared stuff
    Shared.init_app(something="AppFact")

    @app.get("/mul", authorize=ALL)
    def get_mul(i: int, j: int):
        return str(i * j), 200

    @app.get("/add", authorize=ALL)
    def get_add(i: int, j: int):
        return str(i + j), 200

    @app.get("/div", authorize=ALL)
    def get_div(i: int, j: int):
        return str(i // j), 200

    @app.get("/sub", authorize=ALL)
    def get_sub(i: int, j: int):
        return str(i - j), 200

    @app.get("/something", authorize=ALL)
    def get_something():
        return str(something), 200

    @app.get("/admin", authorize=ADMIN)
    def get_admin():
        return "admin!", 200

    @app.get("/self/<login>", authorize=("users", "login"))
    def get_self_login(login: str):
        return f"hello: {login}", 200

    @app.get("/hits", authorize=ADMIN)
    def get_hits():
        return json((len(app._fsa._cache), app._fsa._cache.hits())), 200

    return app
