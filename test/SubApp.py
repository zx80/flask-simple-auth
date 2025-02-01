# also works: from flask import Blueprint
from FlaskSimpleAuth import Blueprint
from Shared import something

subapp = Blueprint("subapp", __name__)

@subapp.get("/words/<word>", authz="AUTH")
def get_words_word(word: str, n: int = 1):
    return str('_'.join([word] * n)), 200

@subapp.get("/something", authz="AUTH")
def get_something():
    return str(something), 200

# missing authz
@subapp.get("/blue")
def get_blue():
    return "", 200
