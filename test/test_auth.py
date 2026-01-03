from jwt_fastapi_auth.auth import JWTAuth


def test_jwt():
    auth = JWTAuth(secret_key="TEST_KEY", expire_minutes=10)
    token = auth.create_access_token({"sub": "1"})
    payload = auth.verify_token(token)
    assert payload["sub"] == "1"
