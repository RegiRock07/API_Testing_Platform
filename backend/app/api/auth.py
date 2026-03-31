# backend/app/api/auth.py
#
# JWT authentication utilities and FastAPI dependencies.

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt as PyJWT
from fastapi import HTTPException, Header, Query


ALGORITHM = "HS256"


def JWT_SECRET() -> str:
    return os.getenv("JWT_SECRET", "dev-secret-change-in-prod")


def JWT_EXPIRY_DAYS() -> int:
    return int(os.getenv("JWT_EXPIRY_DAYS", "7"))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token with sub (user_id), email, and exp claims."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=JWT_EXPIRY_DAYS()))
    to_encode.update({"exp": expire})
    return PyJWT.encode(to_encode, JWT_SECRET(), algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT. Returns the payload dict or None on failure."""
    try:
        return PyJWT.decode(token, JWT_SECRET(), algorithms=[ALGORITHM])
    except PyJWT.PyJWTError:
        return None


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None, alias="token"),
) -> dict:
    """
    FastAPI dependency that authenticates the request.

    Super-user mode:
      If SENTINEL_API_KEY is set and the X-API-Key header matches it,
      return a dict with user_id="super" and is_super=True.

    JWT mode:
      Extract the Bearer token from the Authorization header (or ?token= query param),
      decode it, look up the user by id, and return the user dict.
      The query param fallback allows export endpoints to work with window.open().
      Raises 401 if the token is missing/invalid or the user is not found.
    """
    sentinel_api_key = os.getenv("SENTINEL_API_KEY", "")

    # Super-user bypass via X-API-Key header
    if sentinel_api_key:
        if authorization and authorization.startswith("ApiKey "):
            key = authorization[len("ApiKey "):]
            if key == sentinel_api_key:
                return {"id": "super", "email": "super@api-sentinel", "is_super": True}

    # JWT Bearer token flow — header takes priority, then query param fallback
    jwt_token = None
    if authorization and authorization.startswith("Bearer "):
        jwt_token = authorization[len("Bearer "):]
    elif token:
        jwt_token = token  # query param fallback for export endpoints

    if not jwt_token:
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    payload = decode_token(jwt_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    from app.database import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def get_current_user_optional(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    """
    Like get_current_user but returns None instead of raising 401 when no
    valid credentials are present.
    """
    if not authorization:
        return None

    sentinel_api_key = os.getenv("SENTINEL_API_KEY", "")

    # Super-user bypass
    if sentinel_api_key:
        if authorization.startswith("ApiKey "):
            key = authorization[len("ApiKey "):]
            if key == sentinel_api_key:
                return {"id": "super", "email": "super@api-sentinel", "is_super": True}

    # JWT flow
    if authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
        payload = decode_token(token)
        if payload:
            user_id = payload.get("sub")
            if user_id:
                from app.database import get_user_by_id
                return get_user_by_id(user_id)

    return None