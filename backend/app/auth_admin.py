"""JWT helpers for admin authentication and reset confirmation tokens."""

from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import config, vault_client

logger = logging.getLogger("hpe.auth_admin")

_jwt_secret: str | None = None
_pending_reset_tokens: Dict[str, float] = {}
_bearer_scheme = HTTPBearer(auto_error=False)


def _fallback_secret() -> str:
    return os.getenv("ADMIN_SECRET", "hpe-dev-admin-secret-change-this-value")


def load_jwt_secret() -> str:
    """Load JWT signing secret from Vault when available, otherwise fallback."""
    global _jwt_secret

    secret = None
    try:
        if vault_client.is_connected() and getattr(vault_client, "_client", None):
            response = vault_client._client.secrets.kv.v2.read_secret_version(  # noqa: SLF001
                path=config.ADMIN_JWT_VAULT_PATH,
                raise_on_deleted_version=False,
            )
            data = response.get("data", {}).get("data", {})
            secret = (
                data.get("jwt_secret")
                or data.get("signing_key")
                or data.get("secret")
                or data.get("key")
            )
    except Exception as e:
        logger.warning(f"Failed to load admin JWT secret from Vault: {e}")

    if not secret:
        secret = _fallback_secret()
    _jwt_secret = str(secret)
    return _jwt_secret


def _get_jwt_secret() -> str:
    return _jwt_secret or load_jwt_secret()


def create_admin_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=config.ADMIN_JWT_TTL_MINUTES),
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def verify_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, _get_jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(401, "Token expired") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, "Invalid token") from e


def get_current_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(401, "Missing bearer token")
    return verify_token(credentials.credentials)


def create_reset_token() -> str:
    token = secrets.token_urlsafe(24)
    _pending_reset_tokens[token] = time.time() + config.ADMIN_RESET_TOKEN_TTL_SECONDS
    return token


def validate_reset_token(token: str) -> bool:
    expiry = _pending_reset_tokens.pop(token, None)
    return bool(expiry and time.time() <= expiry)
