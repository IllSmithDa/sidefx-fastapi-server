# app/core/auth.py

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Cookie, Depends, Header, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models
from app.core.auth_config import (
    ACCESS_COOKIE,
    ACCESS_TOKEN_SECONDS,
    REFRESH_TOKEN_SECONDS,
)
from app.db import get_db
from app.util.security import hash_email, verify_password


SECRET_KEY = os.getenv("JWT_SECRET", "dev-only-secret-change-me")
ALGORITHM = "HS256"

RECENT_AUTH_COOKIE = "germfx_recent_auth"
RECENT_AUTH_TOKEN_TYPE = "recent_auth"
RECENT_AUTH_TOKEN_SECONDS = int(
    os.getenv("RECENT_AUTH_TOKEN_SECONDS", "600")
)


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    exp = now + (expires_delta or timedelta(seconds=ACCESS_TOKEN_SECONDS))
    to_encode.update({"exp": exp, "iat": now, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=REFRESH_TOKEN_SECONDS)
    to_encode = data.copy()
    to_encode.update({"exp": exp, "iat": now, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_recent_auth_token(
    *,
    user_id: int | str,
    token_version: int,
    provider: str,
) -> str:
    """
    Create a short-lived proof that an already-authenticated user recently
    confirmed their identity through a supported authentication provider.

    This token is NOT an access token and must never be accepted as one.
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=RECENT_AUTH_TOKEN_SECONDS)

    payload = {
        "sub": str(user_id),
        "tv": int(token_version),
        "provider": str(provider).strip().lower(),
        "iat": now,
        "exp": exp,
        "type": RECENT_AUTH_TOKEN_TYPE,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def verify_recent_auth_for_user(
    token: str | None,
    *,
    user: models.User,
    allowed_providers: set[str] | None = None,
) -> dict:
    """
    Verify a recent-auth proof against the currently authenticated GermFx user.

    The proof must:
    - be a recent_auth JWT,
    - belong to this exact user,
    - carry the user's current token_version,
    - optionally use one of the allowed providers.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Please verify your identity before continuing.",
                "code": "RECENT_AUTH_REQUIRED",
            },
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": (
                    "Your recent identity verification is invalid or has expired. "
                    "Please verify again."
                ),
                "code": "RECENT_AUTH_INVALID",
            },
        ) from exc

    if payload.get("type") != RECENT_AUTH_TOKEN_TYPE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Invalid recent identity verification.",
                "code": "RECENT_AUTH_INVALID",
            },
        )

    if str(payload.get("sub") or "") != str(user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Recent identity verification does not match this account.",
                "code": "RECENT_AUTH_USER_MISMATCH",
            },
        )

    try:
        token_version = int(payload.get("tv"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Invalid recent identity verification.",
                "code": "RECENT_AUTH_INVALID",
            },
        ) from exc

    if token_version != int(user.token_version):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Recent identity verification has been revoked.",
                "code": "RECENT_AUTH_REVOKED",
            },
        )

    provider = str(payload.get("provider") or "").strip().lower()

    if allowed_providers is not None and provider not in allowed_providers:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "This identity verification method cannot be used here.",
                "code": "RECENT_AUTH_PROVIDER_INVALID",
            },
        )

    ensure_user_can_authenticate(user)

    return payload


def verify_token(token: str, token_type: str = "access") -> dict:
    """
    Decodes and validates the token and enforces the expected token type.

    token_type: "access" or "refresh"
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_payload_type = payload.get("type")

        if token_payload_type != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "message": "Invalid token type.",
                    "code": "INVALID_TOKEN_TYPE",
                },
            )

        return payload
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid or expired token.",
                "code": "INVALID_OR_EXPIRED_TOKEN",
            },
        )


def ensure_user_can_authenticate(user: models.User) -> None:
    """
    Blocks suspended, deactivated, and inactive accounts.

    Keep this shared so login, refresh, and authenticated route dependencies all
    enforce the same account-status rules.
    """
    account_status = getattr(user, "account_status", None)

    if bool(user.is_active) and account_status != "suspended":
        return

    if account_status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "This account has been suspended. Please contact support.",
                "code": "ACCOUNT_SUSPENDED",
            },
        )

    if account_status == "deactivated":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "This account is deactivated. You can reactivate it.",
                "code": "ACCOUNT_DEACTIVATED",
            },
        )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "message": "This account is inactive.",
            "code": "ACCOUNT_INACTIVE",
        },
    )


def verify_user(identifier: str, password: str, db: Session) -> models.User:
    """
    Verify that the user exists by either email or username, and that their
    password matches.
    """
    identifier = identifier.strip()
    is_email = bool(re.match(r"[^@]+@[^@]+\.[^@]+", identifier))

    if is_email:
        email_hash = hash_email(identifier)
        query = select(models.User).where(models.User.email_hash == email_hash)
    else:
        query = select(models.User).where(models.User.username == identifier)

    user = db.execute(query).scalars().first()

    if (
        not user
        or not user.password_hash
        or not verify_password(password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid username/email or password.",
                "code": "INVALID_CREDENTIALS",
            },
        )

    return user


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None

    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        return None

    return token.strip()


def get_authenticated_user(
    access_token: str | None = Cookie(default=None, alias=ACCESS_COOKIE),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Supports both:
    - Web auth via HttpOnly access-token cookie
    - Mobile auth via Authorization: Bearer <access_token>
    """
    bearer_token = _extract_bearer_token(authorization)
    token = bearer_token or access_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Not authenticated.",
                "code": "NOT_AUTHENTICATED",
            },
        )

    payload = verify_token(token, token_type="access")
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid token.",
                "code": "INVALID_TOKEN",
            },
        )

    user = db.get(models.User, int(user_id))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "User not found.",
                "code": "USER_NOT_FOUND",
            },
        )

    token_version = payload.get("tv")

    try:
        token_version = int(token_version)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid token.",
                "code": "INVALID_TOKEN",
            },
        )

    if token_version != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Token revoked.",
                "code": "TOKEN_REVOKED",
            },
        )

    ensure_user_can_authenticate(user)

    return user


def get_optional_user(
    access_token: Optional[str] = Cookie(default=None, alias=ACCESS_COOKIE),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> models.User | None:
    try:
        return get_authenticated_user(
            access_token=access_token,
            authorization=authorization,
            db=db,
        )
    except HTTPException:
        return None
