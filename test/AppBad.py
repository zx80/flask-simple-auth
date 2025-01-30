from FlaskSimpleAuth import Flask

import logging
log = logging.getLogger("bad")

# generic authentication scheme test
def create_app(auth=None, **config):
    app = Flask("bad")
    if auth:
        app.config.update(FSA_AUTH=[auth])
    app.config.update(**config)

    # next definition may raise an Exception
    @app.route("/misc", methods=["GET"], authz="AUTH", authn=auth)
    def get_misc():
        return "may get there, depending", 200

    return app

# failing pass
def create_badapp_2(**config):
    app = Flask("bad 2")
    app.config.update(**config, FSA_AUTH="param")

    @app.get_user_pass
    def get_user_bad_pass(login: str):
        log.warning(f"intentional get_user_pass failure on {login}")
        raise Exception(f"get_user_pass failed for {login}")

    @app.get("/any", authz="OPEN")
    def get_any():
        return "any ok", 200

    @app.get("/all", authz="AUTH")
    def get_all():
        return "should not get there!", 418

    return app

# failing group
def create_badapp_3(**config):
    app = Flask("bad 3")
    app.config.update(**config, FSA_AUTH="fake")

    @app.user_in_group
    def user_in_bad_group(login: str, group: str):
        log.warning(f"intentional user_in_group failure on {login}/{group}")
        raise Exception(f"user_in_group failed for {login}/{group}")

    @app.get("/any", authz="ANY")
    def get_any():
        return "any is ok", 200

    @app.get("/all", authz="ALL")
    def get_all():
        return "all is ok", 200

    @app.get("/fail", authz="FAIL")
    def get_fail():
        return "should not get there!", 418

    return app

# failing path
def create_badapp_4(**config):
    app = Flask("bad 4", FSA_AUTH="none")
    app.config.update(**config)

    @app.get("/ok", authz="OPEN")
    def get_ok():
        return "ok is ok!", 200

    @app.get("/any", authz="OPEN")
    def get_any():
        raise Exception("intended exception on get_any!")

    return app

# mandatory path parameter
def create_badapp_5(**config):
    app = Flask("bad 5", FSA_AUTH="none")
    app.config.update(**config)

    @app.get("/hello/<name>", authz="OPEN")
    def get_hello_name(name: str = "Calvin"):
        return f"Bonjour {name} !", 200

    return app

# missing path parameter
def create_badapp_6(**config):
    app = Flask("bad 6", FSA_AUTH="none")
    app.config.update(**config)

    @app.get("/hello/<missing>", authz="OPEN")
    def get_hello_missing():
         return "Bonsoir <missing> !", 200

    return app

# inconsistent path parameter types
def create_badapp_7(**config):
    app = Flask("bad 7", FSA_AUTH="none")
    app.config.update(**config)

    @app.get("/hello/<int:bad>", authz="OPEN")
    def get_hello_missing(bad: float):
         return f"Salut {bad} !", 200

    return app

# again
def create_badapp_8(**config):
    app = Flask("bad 8", FSA_AUTH="none")
    app.config.update(**config)

    @app.get("/hello/<unknown:bad>", authz="OPEN")
    def get_hello_missing(bad: int):
         return f"Salut {bad} !", 200

    return app
