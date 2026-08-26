# app/routes/auth.py

from __future__ import annotations

import os
from typing import List

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models
from app.core.auth import (
    RECENT_AUTH_COOKIE,
    _extract_bearer_token,
    create_access_token,
    create_refresh_token,
    ensure_user_can_authenticate,
    get_authenticated_user,
    verify_recent_auth_for_user,
    verify_token,
    verify_user,
)
from app.core.auth_config import (
    ACCESS_COOKIE,
    ACCESS_TOKEN_SECONDS,
    COOKIE_PATH,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    REFRESH_COOKIE,
    REFRESH_TOKEN_SECONDS,
)
from app.core.users import create_user_in_db
from app.db import get_db
from app.email_secure import (
    generate_email_change_token,
    generate_email_token,
    verify_email_change_token,
)
from app.emailer import (
    change_email_verification_html,
    send_email,
    verification_email_html,
)
from app.models import User
from app.schemas.users import (
    ChangeEmailRequest,
    ChangePasswordRequest,
    ChangeUsernameRequest,
    SetPasswordRequest,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.scripts.validator import (
    validate_new_email,
    validate_new_password,
    validate_username,
)
from app.services.request_cooldowns import enforce_and_mark_user_cooldown
from app.services.subscriptions import serialize_user_subscription
from app.services.turnstile import verify_turnstile_token
from app.util.security import (
    canonicalize_email,
    decrypt_email,
    encrypt_email,
    hash_email,
    hash_password,
    verify_password,
)


router = APIRouter()

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
CLIENT_BASE_URL = os.getenv("CLIENT_BASE_URL", "http://localhost:3000")


def _email_change_verification_link(token: str) -> str:
    return f"{CLIENT_BASE_URL}/verify-email-change?token={token}"


def _verification_link(token: str) -> str:
    return f"{API_BASE_URL}/api/auth/verify?token={token}"


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    verify_turnstile_token(
        token=payload.turnstile_token,
        request=request,
        action="register",
    )

    created_user = create_user_in_db(payload, db)

    try:
        decrypted_email = canonicalize_email(decrypt_email(created_user.email_enc))
        token = generate_email_token(created_user.id, decrypted_email)
        link = _verification_link(token)
        html = verification_email_html(link)

        background.add_task(
            send_email,
            decrypted_email,
            "Welcome to GermFx — verify your email",
            html,
        )
    except Exception:
        # Account creation should not fail just because the welcome email failed.
        pass

    return created_user


@router.post("/login")
def login_user(
    payload: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticate a user by identifier (email or username) + password,
    issue JWTs, and set HttpOnly cookies.
    """

    verify_turnstile_token(
        token=payload.turnstile_token,
        request=request,
        action="login",
    )

    # verify_user already handles email OR username
    user = verify_user(payload.identifier, payload.password, db)

    if not user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Please verify your email before logging in.",
                "code": "EMAIL_NOT_VERIFIED",
            },
        )

    # Blocks suspended/deactivated/inactive users before issuing new tokens.
    ensure_user_can_authenticate(user)

    access_token = create_access_token(
        {
            "sub": str(user.id),
            "tv": user.token_version,
        }
    )
    refresh_token = create_refresh_token(
        {
            "sub": str(user.id),
            "tv": user.token_version,
        }
    )

    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_TOKEN_SECONDS,
        path=COOKIE_PATH,
    )
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=REFRESH_TOKEN_SECONDS,
        path=COOKIE_PATH,
    )

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "is_active": user.is_active,
            "is_email_verified": user.is_email_verified,
            "account_status": getattr(user, "account_status", None),
            "created_at": user.created_at,
            "has_password": bool(user.password_hash),
            "oauth_providers": _oauth_providers_for_user(
                db,
                user.id,
            ),
        },
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh_access_token(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    authorization: str | None = Header(default=None),
):
    bearer_refresh_token = _extract_bearer_token(authorization)
    token = bearer_refresh_token or refresh_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Refresh token missing.",
                "code": "REFRESH_TOKEN_MISSING",
            },
        )

    payload = verify_token(token, token_type="refresh")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid refresh token.",
                "code": "INVALID_REFRESH_TOKEN",
            },
        )

    user = db.execute(
        select(models.User).where(models.User.id == int(user_id))
    ).scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "User not found.",
                "code": "USER_NOT_FOUND",
            },
        )

    # Blocks suspended/deactivated/inactive users before issuing refreshed tokens.
    ensure_user_can_authenticate(user)

    token_version = payload.get("tv")
    try:
        token_version = int(token_version)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid refresh token.",
                "code": "INVALID_REFRESH_TOKEN",
            },
        )

    if token_version != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Refresh token revoked.",
                "code": "REFRESH_TOKEN_REVOKED",
            },
        )

    new_access = create_access_token(
        {
            "sub": str(user.id),
            "tv": user.token_version,
        }
    )
    new_refresh = create_refresh_token(
        {
            "sub": str(user.id),
            "tv": user.token_version,
        }
    )

    response.set_cookie(
        key=ACCESS_COOKIE,
        value=new_access,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_TOKEN_SECONDS,
        path=COOKIE_PATH,
    )
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=new_refresh,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=REFRESH_TOKEN_SECONDS,
        path=COOKIE_PATH,
    )

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


def _oauth_providers_for_user(
    db: Session,
    user_id: int,
) -> list[str]:
    providers = db.execute(
        select(models.UserOAuthIdentity.provider).where(
            models.UserOAuthIdentity.user_id == user_id
        )
    ).scalars().all()

    return sorted(
        {
            str(provider).strip().lower()
            for provider in providers
            if provider
        }
    )


@router.get("/me")
def me(
    current_user: models.User = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
):
    email = None

    try:
        if current_user.email_enc:
            email = canonicalize_email(decrypt_email(current_user.email_enc))
    except Exception:
        email = None

    subscription = serialize_user_subscription(current_user)

    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": email,
        "is_active": current_user.is_active,
        "is_email_verified": current_user.is_email_verified,
        "account_status": getattr(current_user, "account_status", None),
        "created_at": current_user.created_at,
        "role": current_user.role,
        "has_password": bool(current_user.password_hash),
        "oauth_providers": _oauth_providers_for_user(
            db,
            current_user.id,
        ),
        "subscription": subscription,
        "is_plus": subscription["is_plus"],
        "subscription_plan": subscription["plan"],
        "subscription_status": subscription["status"],
    }


@router.get("/", response_model=List[UserOut])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
):
    refresh_token = request.cookies.get(REFRESH_COOKIE)

    if refresh_token:
        try:
            payload = verify_token(refresh_token, token_type="refresh")
            user_id = payload.get("sub")

            if user_id:
                user = db.execute(
                    select(models.User).where(models.User.id == int(user_id))
                ).scalars().first()

                if user:
                    user.token_version += 1
                    db.commit()

        except Exception:
            # Expired/invalid refresh token should not prevent logout.
            pass

    response.delete_cookie(
        key=ACCESS_COOKIE,
        path=COOKIE_PATH,
    )
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=COOKIE_PATH,
    )
    return


def _verify_account_setting_identity(
    *,
    current_user: models.User,
    current_password: str | None,
    recent_auth_token: str | None,
) -> str:
    """
    Verify a sensitive account-settings action.

    Returns the verification method used: "password" or "google".

    If the caller explicitly supplies a password, that password must be
    correct. We do not silently fall back to an existing recent-auth cookie
    after an incorrect password attempt.
    """
    supplied_password = (
        current_password.strip()
        if isinstance(current_password, str)
        else ""
    )

    if supplied_password:
        if not current_user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": (
                        "This account does not have a GermFx password. "
                        "Verify your identity with Google instead."
                    ),
                    "code": "PASSWORD_NOT_SET",
                },
            )

        if not verify_password(
            supplied_password,
            current_user.password_hash,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Current password is incorrect.",
                    "code": "CURRENT_PASSWORD_INCORRECT",
                },
            )

        return "password"

    verify_recent_auth_for_user(
        recent_auth_token,
        user=current_user,
        allowed_providers={"google"},
    )

    return "google"


def _clear_recent_auth_cookie(
    response: Response,
) -> None:
    response.delete_cookie(
        key=RECENT_AUTH_COOKIE,
        path=COOKIE_PATH,
    )


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    recent_auth_token: str | None = Cookie(
        default=None,
        alias=RECENT_AUTH_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_authenticated_user),
):
    """
    Change an existing GermFx password.

    A password-only user verifies with their current password.
    A user who also has a linked Google identity may instead complete recent
    Google reauthentication and omit current_password.
    """
    if not current_user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "This account does not currently have a GermFx password. "
                    "Use Set Password instead."
                ),
                "code": "PASSWORD_NOT_SET",
            },
        )

    _verify_account_setting_identity(
        current_user=current_user,
        current_password=payload.current_password,
        recent_auth_token=recent_auth_token,
    )

    password_error = validate_new_password(payload.new_password)
    if password_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_error,
        )

    if verify_password(
        payload.new_password,
        current_user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "New password must be different from your current password."
                ),
                "code": "PASSWORD_UNCHANGED",
            },
        )

    enforce_and_mark_user_cooldown(
        db=db,
        user_id=current_user.id,
        action_key="change_password",
        cooldown_seconds=300,
        message="Please wait before changing your password again.",
        commit=False,
    )

    current_user.password_hash = hash_password(
        payload.new_password
    )
    current_user.token_version += 1

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    # token_version changed, so every existing auth token is revoked. Clear the
    # browser copies too, including recent-auth.
    response.delete_cookie(
        key=ACCESS_COOKIE,
        path=COOKIE_PATH,
    )
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=COOKIE_PATH,
    )
    _clear_recent_auth_cookie(response)

    return {
        "message": "Password changed successfully. Please log in again.",
        "code": "PASSWORD_CHANGED",
    }


@router.post("/set-password", status_code=status.HTTP_200_OK)
def set_password(
    payload: SetPasswordRequest,
    response: Response,
    recent_auth_token: str | None = Cookie(
        default=None,
        alias=RECENT_AUTH_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_authenticated_user),
):
    """
    Add the first GermFx password to an OAuth-only account.

    This endpoint cannot change an existing password. The user must prove
    ownership through recent Google reauthentication.
    """
    if current_user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": (
                    "This account already has a GermFx password. "
                    "Use Change Password instead."
                ),
                "code": "PASSWORD_ALREADY_SET",
            },
        )

    verify_recent_auth_for_user(
        recent_auth_token,
        user=current_user,
        allowed_providers={"google"},
    )

    password_error = validate_new_password(
        payload.new_password
    )
    if password_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_error,
        )

    enforce_and_mark_user_cooldown(
        db=db,
        user_id=current_user.id,
        action_key="change_password",
        cooldown_seconds=300,
        message="Please wait before changing your password again.",
        commit=False,
    )

    current_user.password_hash = hash_password(
        payload.new_password
    )
    current_user.token_version += 1

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    response.delete_cookie(
        key=ACCESS_COOKIE,
        path=COOKIE_PATH,
    )
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=COOKIE_PATH,
    )
    _clear_recent_auth_cookie(response)

    return {
        "message": (
            "GermFx password set successfully. "
            "Please log in again."
        ),
        "code": "PASSWORD_SET",
    }


@router.post("/change-username", response_model=UserOut, status_code=status.HTTP_200_OK)
def change_username(
    payload: ChangeUsernameRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_authenticated_user),
):
    new_username = payload.new_username.strip()

    username_error = validate_username(new_username)
    if username_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=username_error,
        )

    if new_username.lower() == current_user.username.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New username must be different from your current username",
        )

    existing_user = db.execute(
        select(models.User).where(func.lower(models.User.username) == new_username.lower())
    ).scalars().first()

    if existing_user and existing_user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    enforce_and_mark_user_cooldown(
        db=db,
        user_id=current_user.id,
        action_key="change_username",
        cooldown_seconds=300,
        message="Please wait before changing your username again.",
        commit=False,
    )

    current_user.username = new_username
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return current_user


@router.post("/change-email", status_code=status.HTTP_200_OK)
def request_email_change(
    payload: ChangeEmailRequest,
    response: Response,
    background: BackgroundTasks,
    recent_auth_token: str | None = Cookie(
        default=None,
        alias=RECENT_AUTH_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_authenticated_user),
):
    """
    Request an email change after fresh identity verification.

    Password accounts may use their current GermFx password. Google-only
    accounts, and dual-auth users who choose Google, may use a valid recent
    Google reauthentication cookie instead.
    """
    new_email = canonicalize_email(
        payload.new_email
    )

    _verify_account_setting_identity(
        current_user=current_user,
        current_password=payload.current_password,
        recent_auth_token=recent_auth_token,
    )

    email_error = validate_new_email(new_email)
    if email_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=email_error,
        )

    try:
        current_email = canonicalize_email(
            decrypt_email(
                current_user.email_enc
            )
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to verify current email",
        )

    if current_email == new_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New email must be different from your current email",
        )

    new_email_hash = hash_email(new_email)

    existing_user = db.execute(
        select(models.User).where(
            models.User.email_hash
            == new_email_hash
        )
    ).scalars().first()

    if (
        existing_user
        and existing_user.id
        != current_user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already in use",
        )

    enforce_and_mark_user_cooldown(
        db=db,
        user_id=current_user.id,
        action_key="change_email",
        cooldown_seconds=300,
        message=(
            "Please wait before requesting "
            "another email change."
        ),
        commit=True,
    )

    token = generate_email_change_token(
        user_id=current_user.id,
        current_email_hash=current_user.email_hash,
        new_email=new_email,
    )

    link = _email_change_verification_link(
        token
    )
    html = change_email_verification_html(
        link,
        new_email,
    )

    background.add_task(
        send_email,
        new_email,
        "Confirm your GermFx email change",
        html,
    )

    # Consume the browser copy of recent Google verification after a successful
    # email-change request. Password verification is unaffected by this.
    _clear_recent_auth_cookie(response)

    return {
        "message": (
            "Verification email sent. Please check your new email address "
            "to complete the change."
        ),
        "code": "EMAIL_CHANGE_VERIFICATION_SENT",
    }


@router.post("/verify-email-change", status_code=status.HTTP_200_OK)
def verify_email_change(
    payload: dict = Body(...),
    response: Response = None,
    db: Session = Depends(get_db),
):
    token = str(payload.get("token") or "").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing email change verification token.",
        )

    try:
        token_payload = verify_email_change_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    user_id = token_payload["uid"]
    token_current_email_hash = token_payload["current_email_hash"]
    new_email = canonicalize_email(token_payload["new_email"])

    user = db.execute(
        select(models.User).where(models.User.id == int(user_id))
    ).scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.email_hash != token_current_email_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email change link is no longer valid.",
        )

    email_error = validate_new_email(new_email)
    if email_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=email_error,
        )

    new_email_hash = hash_email(new_email)

    existing_user = db.execute(
        select(models.User).where(models.User.email_hash == new_email_hash)
    ).scalars().first()

    if existing_user and existing_user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already in use",
        )

    user.email_hash = new_email_hash
    user.email_enc = encrypt_email(new_email)
    user.is_email_verified = True
    user.token_version += 1

    db.add(user)
    db.commit()
    db.refresh(user)

    if response:
        response.delete_cookie(
            key=ACCESS_COOKIE,
            path=COOKIE_PATH,
        )
        response.delete_cookie(
            key=REFRESH_COOKIE,
            path=COOKIE_PATH,
        )
        _clear_recent_auth_cookie(response)

    return {
        "message": "Email changed successfully. Please log in again with your new email.",
    }