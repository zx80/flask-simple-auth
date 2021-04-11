from FlaskSimpleAuth import Flask

# test a bad authentication scheme
def create_app(**config):
    app = Flask("misc")
    app.config.update(FSA_AUTH="fake")
    app.config.update(**config)

    # next definition must raise an Exception
    @app.route("/misc", methods=["GET"], authorize="ALL", auth="bad")
    def get_misc():
        return "never get there", 200

    return app
