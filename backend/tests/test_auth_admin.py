from app import auth_admin


def test_create_and_verify_admin_token_roundtrip(monkeypatch):
    monkeypatch.setattr(auth_admin, "_jwt_secret", "unit-test-secret-unit-test-secret-1234")
    token = auth_admin.create_admin_token("alice")
    payload = auth_admin.verify_token(token)
    assert payload["sub"] == "alice"


def test_reset_token_is_one_time_use():
    token = auth_admin.create_reset_token()
    assert auth_admin.validate_reset_token(token) is True
    assert auth_admin.validate_reset_token(token) is False
