from FlaskSimpleAuth import Flask

# test a bad authentication scheme
def create_app(auth=None, **config):
    app = Flask("bad")
    app.config.update(**config)

    # next definition may raise an Exception
    @app.route("/misc", methods=["GET"], authorize="ALL", auth=auth)
    def get_misc():
        return "never get there", 200

    return app
