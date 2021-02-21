import pytest

from typing import Dict, Any

# minimal Flask-looking class 
class Flask:
    def __init__(self, name: str = "app", config: Dict[str, Any] = {}):
        self.name = name
        self.config = config
app = Flask('Test', { 'FSA_TYPE': 'fake' })

import FlaskSimpleAuth as auth
auth.setConfig(app)

print(f"REALM: {auth.REALM}")

def test_sanity():
    assert auth.REALM == "test"
    assert 'FSA_TYPE' in auth.CONF
    calvin_token = auth.create_token("calvin")
    assert calvin_token[:12] == "test:calvin:"
