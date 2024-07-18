import pytest

from arcpy_auth_manager import manager

def test_storage():
    mg = manager.TokenManager()
    mg.store('my_test_user', 'my_test_token')