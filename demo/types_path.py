#
# Types demo
#
from FlaskSimpleAuth import Blueprint, JsonData, jsonify as json
import pydantic as pyda

types = Blueprint("types", __name__)


@types.get("/scalars", authz="OPEN")
def get_scalars(i: int = 0, f: float = 0.0, b: bool = False, s: str = ""):
    return f"i={i}, f={f}, b={b}, s={s}", 200


@types.get("/json", authz="OPEN")
def get_json(j: JsonData):
    return f"{type(j).__name__}: {j}", 200


# define a constrained int type
class nat(int):
    def __new__(cls, val):
        if val < 0:
            raise ValueError(f"nat value must be positive: {val}")
        return super().__new__(cls, val)


@types.get("/nat", authz="OPEN")
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


@types.post("/char", authz="OPEN")
def post_char(char: Character):
    return {"name": char.name, "age": char.age}, 201


@types.post("/pers", authz="OPEN")
def post_pers(pers: Personnage):
    return {"name": pers.name, "age": pers.age}, 201


class ListOfStr(list):
    """A list of strings."""
    def __init__(self, ls: list[str]):
        if not isinstance(ls, list) or not all(isinstance(i, str) for i in ls):
            raise ValueError("expecting list[str]")
        super().__init__(ls)


@types.get("/ls", authz="OPEN")
def post_ls(ls: ListOfStr):
    return {"len": len(ls), "all": "/".join(ls)}, 200
