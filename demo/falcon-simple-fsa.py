# FlaskSimpleAuth version of Falcon simple example
#
# https://falcon.readthedocs.io/en/stable/user/quickstart.html
#
# for plain Flask, just remove the "authorize" parameter.

import FlaskSimpleAuth as fsa

app = fsa.Flask(__name__)

@app.get("/things", authorize="ANY")
def get_things():
    return fsa.Response(
        "\n"
        "Two things awe me most, the starry sky above me and the moral law within me.\n"
        "\n"
        "    ~ Immanuel Kant\n\n", 200, mimetype="text/plain")
