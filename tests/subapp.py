from FlaskSimpleAuth import Blueprint, ALL

subapp = Blueprint("subapp", __name__)

@subapp.route("/words/<word>", methods=["GET"], authorize=ALL)
def get_words_word(word: str, n: int = 1):
    return str('_'.join([word] * n)), 200

# missing authorize
@subapp.route("/blue", methods=["GET"])
def get_blue():
    return "", 200
