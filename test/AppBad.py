from FlaskSimpleAuth import Flask

# generic authentication scheme test
def create_app(auth=None, **config):
    app = Flask("bad")
    app.config.update(**config)

    # next definition may raise an Exception
    @app.route("/misc", methods=["GET"], authorize="ALL", auth=auth)
    def get_misc():
        return "may get there, depending", 200

    return app
