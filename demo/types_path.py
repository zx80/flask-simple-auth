#
# Types demo
#
from FlaskSimpleAuth import Blueprint, JsonData

types = Blueprint("types", __name__)


@types.get("/scalars", authorize="ANY")
def get_scalars(i: int = 0, f: float = 0.0, b: bool = False, s: str = ""):
    return f"i={i}, f={f}, b={b}, s={s}", 200


@types.get("/json", authorize="ANY")
def get_json(j: JsonData):
    return f"{type(j).__name__}: {j}", 200
