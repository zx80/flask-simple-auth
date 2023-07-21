# FlaskSimpleAuth version of FastAPI Oauth2+JWT Code Example from
#
# https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
#
# Hey, about 50 lines to get there!
#

import logging
from pydantic import BaseModel
import FlaskSimpleAuth as fsa

json = fsa.jsonify
logging.basicConfig()
log = logging.getLogger("demo")

app = fsa.Flask("demo")
app.config.from_envvar("DEMO_CONFIG")

# user db: johndoe:secret
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class User(BaseModel):
    username: str
    email: str|None = None
    full_name: str|None = None
    disabled: bool|None = None


def get_user(db, username: str):
    if username in db:
        return User(**db[username])

# parameter type User triggers building a User instance
app.special_parameter(User, lambda _: get_user(fake_users_db, app.current_user()))

@app.get_user_pass
def get_user_pass(login: str):
    if login in fake_users_db:
       return fake_users_db[login]["hashed_password"]
    # else None, 401

@app.user_in_group
def user_in_group(login: str, group: str):
    if login in fake_users_db and group == "ENABLED":
       return not fake_users_db[login]["disabled"]
    return False

# from a REST perspective, it should be GET…
# however OAuth seems to prescribe POST on "username" and "password"
@app.post("/token", authorize="ALL", auth="param")
def post_token(user: fsa.CurrentUser):
    return {"access_token": app.create_token(user), "token_type": "bearer"}, 200

@app.get("/users/me", authorize="ENABLED")
def read_users_me(user: User):
    return json(user), 200

@app.get("/users/me/items", authorize="ENABLED")
def get_users_me_items(user: User):
    return json([{"item_id": "Foo", "owner": user.username}]), 200
