# tests with flask

import pytest

import app

def test_sanity():
    assert app.app is not None and app.auth is not None
    assert app.app.name == "Test_Application"
    assert app.auth.REALM == "test"
