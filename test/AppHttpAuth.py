# test factory pattern for http auth authentication

from FlaskSimpleAuth import Flask

import Auth

def create_app_basic(**config):
    app = Flask("http-basic-auth")
    app.config.update(FSA_AUTH="http-basic", FSA_GET_USER_PASS=Auth.get_user_pass)
    app.config.update(**config)

    @app.route("/basic", methods=["GET"], authz="AUTH")
    def get_basic():
        return app.get_user(), 200

    return app

def create_app_digest(**config):
    app = Flask("http-digest-auth")
    app.config.update(FSA_AUTH="http-digest")
    app.get_user_pass(Auth.UP.get)
    app.user_in_group(lambda _u, _g: True)
    app.user_in_group(None)
    app.config.update(**config)

    @app.route("/digest", methods=["GET"], authz="AUTH")
    def get_digest():
        return app.get_user(), 200

    return app

def create_app_token(**config):
    app = Flask("http-token-auth")
    app.config.update(FSA_AUTH="http-token", FSA_GET_USER_PASS=Auth.get_user_pass)
    app.config.update(**config)

    @app.route("/token", methods=["GET"], authz="AUTH")
    def get_token():
        return app.get_user(), 200

    return app
