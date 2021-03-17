# also works: from flask import Blueprint
from FlaskSimpleAuth import Blueprint, ALL
from Shared import something

subapp = Blueprint("subapp", __name__)

@subapp.route("/words/<word>", methods=["GET"], authorize=ALL)
def get_words_word(word: str, n: int = 1):
    return str('_'.join([word] * n)), 200

@subapp.route("/something", methods=["GET"], authorize=ALL)
def get_something():
    return str(something), 200

# missing authorize
@subapp.route("/blue", methods=["GET"])
def get_blue():
    return "", 200
