import pytest

from typing import Dict, Any

# minimal Flask-looking class 
class Flask:
    def __init__(self, name: str = "app", config: Dict[str, Any] = {}):
        self.name = name
        self.config = config
    def after_request(self, hook):
        pass

app = Flask('Test', { 'FSA_TYPE': 'fake' })

AUTH = {'calvin': 'hello world!', 'hobbes': 'bonjour tout le monde !'}

is_in_group = lambda u, g: u == "calvin"

import FlaskSimpleAuth as auth
auth.setConfig(app, AUTH.get, is_in_group)

def test_sanity():
    assert auth.REALM == "test"
    assert 'FSA_TYPE' in auth.CONF

def test_token():
    calvin_token = auth.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
    assert auth.get_token_auth(calvin_token) == "calvin"

def test_password_check():
    try:
        ref = auth.hash_password(AUTH['calvin'])
        auth.check_password('calvin', AUTH['calvin'], ref)
        assert True, "password check succeeded"
    except:
        assert False, "password check failed"

def test_authorize():
    assert is_in_group("calvin", "admin")
    @auth.authorize("admin")
    def stuff():
        return "", 200
    auth.USER = "calvin"
    _, status = stuff()
    assert status == 200
    auth.USER = "hobbes"
    _, status = stuff()
    assert status == 403
