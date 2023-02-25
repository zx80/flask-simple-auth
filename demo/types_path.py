#
# Types demo
#
from FlaskSimpleAuth import Blueprint, JsonData, jsonify as json
import pydantic as pyda

types = Blueprint("types", __name__)


@types.get("/scalars", authorize="ANY")
def get_scalars(i: int = 0, f: float = 0.0, b: bool = False, s: str = ""):
    return f"i={i}, f={f}, b={b}, s={s}", 200


@types.get("/json", authorize="ANY")
def get_json(j: JsonData):
    return f"{type(j).__name__}: {j}", 200


# define a constrained int type
class nat(int):
    def __new__(cls, val):
        if val < 0:
            raise ValueError(f"nat value must be positive: {val}")
        return super().__new__(cls, val)


@types.get("/nat", authorize="ANY")
def get_nat(i: nat, j: nat):
    return json(i + j), 200


class Character(pyda.BaseModel):
    name: str
    age: int


@pyda.dataclasses.dataclass
class Personnage:
    name: str
    # age: nat  # DOES NOT WORK
    age: int


@types.post("/char", authorize="ANY")
def post_char(char: Character):
    return {"name": char.name, "age": char.age}, 201


@types.post("/pers", authorize="ANY")
def post_pers(pers: Personnage):
    return {"name": pers.name, "age": pers.age}, 201
