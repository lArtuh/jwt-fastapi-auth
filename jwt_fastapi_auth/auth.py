from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from functools import wraps


class JWTAuth:
    def __init__(
        self,
        secret_key: str | None = None,
        algorithm: str = "HS256",
        expire_minutes: int = 60,
        token_url: str = "/auth/login"
    ):
        self.secret_key = secret_key or getattr(self, "secret_key", None)
        if not self.secret_key:
            raise ValueError("Secret key is required")

        self.ALGORITHM = algorithm
        self.EXPIRE_MINUTES = expire_minutes
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url)

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=self.EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.ALGORITHM)

    def verify_token(self, token: str):
        try:
            payload = jwt.decode(token, self.secret_key,
                                 algorithms=[self.ALGORITHM])
            return payload
        except JWTError:
            raise HTTPException(
                status_code=401, detail="Invalid or expired token")
