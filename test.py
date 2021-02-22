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

AUTH = {'calvin': 'hello world!'}

import FlaskSimpleAuth as auth
auth.setConfig(app, AUTH.get)

print(f"REALM: {auth.REALM}")

def test_sanity():
    assert auth.REALM == "test"
    assert 'FSA_TYPE' in auth.CONF
    calvin_token = auth.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
    try:
        ref = auth.hash_password(AUTH['calvin'])
        auth.check_password('calvin', AUTH['calvin'], ref)
        assert True, "password check succeeded"
    except:
        assert False, "password check failed"
