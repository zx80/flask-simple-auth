import pydantic

@pydantic.dataclasses.dataclass
class User:
    login: str
    email: str
    upass: str
    admin: bool
    aid: int|None = None  # empty on POST
