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

def test_expired_token():
    hobbes_token = auth.create_token("hobbes")
    grace, auth.GRACE = auth.GRACE, -100
    try:
        user = auth.get_token_auth(hobbes_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401
    auth.GRACE = grace

def test_invalid_token():
    susie_token = auth.create_token("susie")
    susie_token = susie_token[:-1] + "z"
    try:
        user = auth.get_token_auth(susie_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401

def test_wrong_token():
    realm, auth.REALM = auth.REALM, "elsewhere"
    moe_token = auth.create_token("moe")
    auth.REALM = realm
    try:
        user = auth.get_token_auth(moe_token)
        assert False, "token should be invalid"
    except auth.AuthException as e:
        assert e.status == 401

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
