# FlaskSimpleAuth version of FastAPI Oauth2+JWT Code Example from
#
# https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
#
# About 50 lines to get there, half FastAPI version!
#

import logging
from pydantic import BaseModel
from typing import Any
import FlaskSimpleAuth as fsa

json = fsa.jsonify
logging.basicConfig()
log = logging.getLogger("demo")

app = fsa.Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

fake_users_db: dict[str, dict[str, Any]] = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": app.hash_password("secret"),
        "disabled": False,
    }
}


class User(BaseModel):
    username: str
    email: str|None = None
    full_name: str|None = None
    disabled: bool|None = None  # I'm afraid that None means enabled


# set parameter type User to trigger building a User instance
def get_user(db: dict[str, dict[str, Any]], username: str|None) -> User|None:
    if not username or username not in db:
        return None
    return User(**db[username])

app.special_parameter(User, lambda _: get_user(fake_users_db, app.get_user()))

# password and group hooks
@app.get_user_pass
def get_user_pass(login: str) -> str|None:
    if login not in fake_users_db:
        return None  # 401
    return fake_users_db[login]["hashed_password"]

# NOTE disabled is None semantics is doubtful
@app.group_check("ENABLED")
def user_is_enabled(login: str) -> bool:
    return login in fake_users_db and not fake_users_db[login]["disabled"]

# from a REST perspective, it should really be GET…
# however OAuth web-oriented view prescribes POST on "username" and "password"
@app.post("/token", authorize="ALL", auth="param")
def post_token(user: fsa.CurrentUser):
    return {"access_token": app.create_token(user), "token_type": "bearer"}, 200

@app.get("/users/me", authorize="ENABLED")
def read_users_me(user: User):
    return json(user), 200

@app.get("/users/me/items", authorize="ENABLED")
def get_users_me_items(user: User):
    return json([{"item_id": "Foo", "owner": user.username}]), 200
