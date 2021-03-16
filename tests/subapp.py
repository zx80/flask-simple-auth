from FlaskSimpleAuth import Blueprint, ALL

subapp = Blueprint("subapp", __name__)

#@subapp.route("/words/<word>", methods=["GET"], authorize=ALL)
@subapp.route("/words/<word>", methods=["GET"])
def get_blue(word: str, n: int = 1):
    return str('_'.join([word] * n)), 200
