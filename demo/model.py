import pydantic

# this also works with standard dataclasses and pydantic objects
@pydantic.dataclasses.dataclass
class User:
    login: str
    email: str
    upass: str
    admin: bool
    aid: int|None = None  # empty on POST
