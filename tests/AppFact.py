# test factory pattern

from shared_auth import get_user_pass, user_in_group
from FlaskSimpleAuth import Flask, ALL

def create_app(**config):
    app = Flask("4ops")
    app.config.update(FSA_TYPE="fake", FSA_GET_USER_PASS=get_user_pass, FSA_USER_IN_GROUP=user_in_group)
    app.config.update(**config)

    @app.route("/mul", methods=["GET"], authorize=ALL)
    def get_mul(i: int, j: int):
        return str(i * j), 200

    @app.route("/add", methods=["GET"], authorize=ALL)
    def get_add(i: int, j: int):
        return str(i + j), 200

    @app.route("/div", methods=["GET"], authorize=ALL)
    def get_div(i: int, j: int):
        return str(i // j), 200

    @app.route("/sub", methods=["GET"], authorize=ALL)
    def get_sub(i: int, j: int):
        return str(i - j), 200

    return app
