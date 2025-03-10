# test factory pattern

from FlaskSimpleAuth import Flask, jsonify as json

from Auth import get_user_pass, user_in_group, ADMIN, UP
from SubApp import subapp

import Shared
from Shared import something

def create_app(**config):
    app = Flask("4ops", debug=True)
    app.config.update(
        FSA_AUTH=["fake", "oauth", "basic", "param", "none"],
        FSA_TOKEN_TYPE="jwt",
        FSA_TOKEN_ISSUER="god",
        FSA_GET_USER_PASS=get_user_pass,
        FSA_USER_IN_GROUP=user_in_group)
    app.config.update(**config)
    app.register_blueprint(subapp, url_prefix="/b")

    # self permission
    def check_users_access(user, val, mode):
        return user == val if val in UP else None

    app.object_perms("users", check_users_access)

    # shared stuff
    Shared.init_app(something="AppFact")

    @app.get("/mul", authz="AUTH")
    def get_mul(i: int, j: int):
        return str(i * j), 200

    @app.get("/add", authz="AUTH")
    def get_add(i: int, j: int):
        return str(i + j), 200

    @app.get("/div", authz="AUTH")
    def get_div(i: int, j: int):
        return str(i // j), 200

    @app.get("/sub", authz="AUTH")
    def get_sub(i: int, j: int):
        return str(i - j), 200

    @app.get("/something", authz="AUTH")
    def get_something():
        return str(something), 200

    @app.get("/admin", authz=ADMIN)
    def get_admin():
        return "admin!", 200

    @app.get("/self/<login>", authz=("users", "login"))
    def get_self_login(login: str):
        return f"hello: {login}", 200

    @app.get("/hits", authz=ADMIN)
    def get_hits():
        return json((len(app._fsa._cm._cache), app._fsa._cm._cache.hits())), 200

    # OAuth 2.0
    if app._fsa._am._tm and app._fsa._am._tm._token == "jwt":
        @app.get("/perm/jwt-authz", authz="character", authn="oauth")
        def get_perm_jwt_authz():
            return f"jwt-authz: {app.get_user()}", 200

    return app
