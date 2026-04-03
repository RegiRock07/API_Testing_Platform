# backend/app/api/firebase_auth.py
#
# Firebase Admin SDK token verification.
# Every protected endpoint calls get_current_user() as a dependency.
#
# Setup:
#   1. Download service account JSON from Firebase Console
#      Project Settings → Service Accounts → Generate new private key
#   2. Set FIREBASE_CREDENTIALS env var to the path of that JSON file
#      OR set FIREBASE_CREDENTIALS_JSON to the raw JSON string
#      (use the raw JSON string on Render — easier than file paths)

import os
import json
import logging
from functools import lru_cache
from typing import Optional

from fastapi import HTTPException, Header

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_firebase_app():
    """
    Initialise Firebase Admin SDK once and cache it.
    Supports both file path and raw JSON string credentials.
    """
    import firebase_admin
    from firebase_admin import credentials

    # Already initialised (e.g. during hot reload)
    if firebase_admin._apps:
        return firebase_admin.get_app()

    # Option 1: raw JSON string in env var (recommended for Render)
    creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON", "")
    if creds_json:
        try:
            cred_dict = json.loads(creds_json)
            cred      = credentials.Certificate(cred_dict)
            return firebase_admin.initialize_app(cred)
        except Exception as e:
            logger.error(f"[Firebase] Failed to init from JSON string: {e}")
            raise

    # Option 2: path to JSON file
    creds_path = os.getenv("FIREBASE_CREDENTIALS", "")
    if creds_path and os.path.exists(creds_path):
        try:
            cred = credentials.Certificate(creds_path)
            return firebase_admin.initialize_app(cred)
        except Exception as e:
            logger.error(f"[Firebase] Failed to init from file: {e}")
            raise

    raise RuntimeError(
        "Firebase credentials not configured. "
        "Set FIREBASE_CREDENTIALS_JSON (raw JSON) or "
        "FIREBASE_CREDENTIALS (file path) environment variable."
    )


def verify_firebase_token(token: str) -> dict:
    """
    Verify a Firebase ID token and return the decoded claims.
    Raises HTTPException 401 on any failure.
    """
    try:
        from firebase_admin import auth as firebase_auth
        _get_firebase_app()
        decoded = firebase_auth.verify_id_token(token)
        return decoded
    except Exception as e:
        logger.warning(f"[Firebase] Token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(
    authorization: Optional[str] = Header(default=None)
) -> dict:
    """
    FastAPI dependency — extracts and verifies the Firebase Bearer token.

    Dev mode bypass:
      If FIREBASE_CREDENTIALS_JSON and FIREBASE_CREDENTIALS are both unset,
      AND SENTINEL_API_KEY matches the X-API-Key header (or is blank),
      we skip Firebase and return a dev user.
      This keeps local dev working without a service account.
    """
    sentinel_key = os.getenv("SENTINEL_API_KEY", "")
    has_firebase = bool(
        os.getenv("FIREBASE_CREDENTIALS_JSON") or
        os.getenv("FIREBASE_CREDENTIALS")
    )

    # ── Dev mode: no Firebase configured ─────────────────────────
    if not has_firebase:
        # If SENTINEL_API_KEY is set, still check it
        if sentinel_key:
            if not authorization or not authorization.startswith("ApiKey "):
                raise HTTPException(
                    status_code=401,
                    detail="Missing X-API-Key header (dev mode)"
                )
            key = authorization[len("ApiKey "):]
            if key != sentinel_key:
                raise HTTPException(status_code=401, detail="Wrong API key")
        # Return a dev user
        return {
            "uid":   "dev-user",
            "email": "dev@localhost",
            "name":  "Dev User",
            "is_dev": True,
        }

    # ── Production mode: Firebase token required ──────────────────
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization header must be 'Bearer <token>'"
        )

    token   = authorization[len("Bearer "):]
    decoded = verify_firebase_token(token)

    return {
        "uid":   decoded.get("uid"),
        "email": decoded.get("email", ""),
        "name":  decoded.get("name", ""),
        "picture": decoded.get("picture", ""),
    }


# FastAPI Depends shorthand
from fastapi import Depends
AuthDep = Depends(get_current_user)