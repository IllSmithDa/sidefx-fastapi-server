from __future__ import annotations

import secrets
from typing import Optional

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from pydantic import (
    BaseModel,
    Field,
)

from app.core.auth import (
    RECENT_AUTH_COOKIE,
    RECENT_AUTH_TOKEN_SECONDS,
    create_access_token,
    create_recent_auth_token,
    create_refresh_token,
    get_optional_user,
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
from app import models
from app.core.users import create_google_user_in_db
from app.db import get_db
from app.schemas.users import GoogleRegistrationComplete
from app.services.google_auth import (
    GOOGLE_LOGIN_INTENT,
    GOOGLE_REACTIVATE_INTENT,
    GOOGLE_REAUTH_INTENT,
    GOOGLE_REGISTRATION_TOKEN_MAX_AGE_SECONDS,
    GoogleOAuthError,
    build_google_authorization_url,
    handle_google_callback,
    is_google_oauth_configured,
    normalize_google_oauth_intent,
    resolve_existing_google_user,
    resolve_mobile_google_user,
    verify_google_registration_token,
)
from app.services.turnstile import verify_turnstile_token


router = APIRouter(prefix="", tags=["google-auth"])

GOOGLE_OAUTH_STATE_COOKIE = "germfx_google_oauth_state"
GOOGLE_OAUTH_INTENT_COOKIE = "germfx_google_oauth_intent"
GOOGLE_REGISTRATION_COOKIE = "germfx_google_registration"

GOOGLE_OAUTH_STATE_MAX_AGE_SECONDS = 600
GOOGLE_OAUTH_COOKIE_PATH = "/api/auth/google"


def _issue_user_session(user, response: Response) -> tuple[str, str]:
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

    return access_token, refresh_token


def _google_oauth_http_exception(exc: GoogleOAuthError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={
            "message": exc.message,
            "code": exc.code,
        },
    )


def _delete_temporary_oauth_cookies(response: Response) -> None:
    for key in (
        GOOGLE_OAUTH_STATE_COOKIE,
        GOOGLE_OAUTH_INTENT_COOKIE,
    ):
        response.delete_cookie(
            key=key,
            path=GOOGLE_OAUTH_COOKIE_PATH,
            secure=COOKIE_SECURE,
            httponly=True,
            samesite="lax",
        )


def _delete_registration_cookie(response: Response) -> None:
    response.delete_cookie(
        key=GOOGLE_REGISTRATION_COOKIE,
        path=GOOGLE_OAUTH_COOKIE_PATH,
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


def _serialize_user(
    user,
    db: Session,
) -> dict:
    providers = db.execute(
        select(models.UserOAuthIdentity.provider).where(
            models.UserOAuthIdentity.user_id == user.id
        )
    ).scalars().all()

    return {
        "id": user.id,
        "username": user.username,
        "is_active": user.is_active,
        "is_email_verified": user.is_email_verified,
        "account_status": getattr(user, "account_status", None),
        "created_at": user.created_at,
        "has_password": bool(user.password_hash),
        "oauth_providers": sorted(
            {
                str(provider).strip().lower()
                for provider in providers
                if provider
            }
        ),
    }


@router.get("/status")
def google_auth_status():
    return {
        "enabled": is_google_oauth_configured(),
        "provider": "google",
    }

@router.post("/mobile")
def google_mobile_login(
    payload:
        GoogleMobileLoginRequest,

    response:
        Response,

    db:
        Session = Depends(
            get_db
        ),
):
    """
    Authenticate an existing GermFx account using a Google
    ID token obtained by the native mobile application.

    Unlike the browser OAuth flow, this route does not depend
    on OAuth state cookies or the browser callback.

    React Native receives GermFx access and refresh tokens
    directly in the JSON response and uses them as Bearer tokens.
    """
    try:
        user = resolve_mobile_google_user(
            db,
            raw_id_token=
                payload.id_token,
        )

    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(
            exc
        ) from exc

    access_token, refresh_token = (
        _issue_user_session(
            user,
            response,
        )
    )

    return {
        "user": {
            "id":
                user.id,

            "username":
                user.username,

            "is_active":
                user.is_active,

            "is_email_verified":
                user.is_email_verified,

            "account_status":
                getattr(
                    user,
                    "account_status",
                    None,
                ),

            "created_at":
                user.created_at,

            "has_password":
                bool(
                    user.password_hash
                ),

            # A successful request here guarantees that this
            # GermFx account is linked to Google.
            "oauth_providers": [
                "google"
            ],
        },

        "access_token":
            access_token,

        "refresh_token":
            refresh_token,

        "token_type":
            "bearer",

        "provider":
            "google",

        "action":
            "authenticated",
    }

@router.get("/login")
def google_login(
    intent: str = Query(default=GOOGLE_LOGIN_INTENT),
):
    if not is_google_oauth_configured():
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={
                "detail": {
                    "message": "Google OAuth is not configured yet.",
                    "code": "GOOGLE_OAUTH_NOT_CONFIGURED",
                },
                "provider": "google",
                "enabled": False,
            },
        )

    try:
        normalized_intent = normalize_google_oauth_intent(intent)
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    state = secrets.token_urlsafe(32)

    try:
        auth_url = build_google_authorization_url(
            state,
            intent=normalized_intent,
        )
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    redirect = RedirectResponse(
        url=auth_url,
        status_code=status.HTTP_302_FOUND,
    )

    redirect.set_cookie(
        key=GOOGLE_OAUTH_STATE_COOKIE,
        value=state,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=GOOGLE_OAUTH_STATE_MAX_AGE_SECONDS,
        path=GOOGLE_OAUTH_COOKIE_PATH,
    )

    redirect.set_cookie(
        key=GOOGLE_OAUTH_INTENT_COOKIE,
        value=normalized_intent,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=GOOGLE_OAUTH_STATE_MAX_AGE_SECONDS,
        path=GOOGLE_OAUTH_COOKIE_PATH,
    )

    return redirect


@router.get("/callback")
def google_callback(
    response: Response,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    expected_state: Optional[str] = Cookie(
        default=None,
        alias=GOOGLE_OAUTH_STATE_COOKIE,
    ),
    oauth_intent: Optional[str] = Cookie(
        default=None,
        alias=GOOGLE_OAUTH_INTENT_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(
        get_optional_user
    ),
):
    if error:
        message = error_description or "Google sign in was cancelled or denied."

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": message,
                "code": "GOOGLE_OAUTH_DENIED",
            },
        )

    try:
        result = handle_google_callback(
            code=code,
            state=state,
            expected_state=expected_state,
            intent=oauth_intent,
            db=db,
            current_user=current_user,
        )
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    _delete_temporary_oauth_cookies(response)

    if result.action == "reactivated":
        if not result.user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "message": (
                        "Google account reactivation completed without a user."
                    ),
                    "code": "GOOGLE_REACTIVATION_USER_MISSING",
                },
            )

        # A recovered account gets a completely fresh normal GermFx session.
        # A recent-auth proof is not needed after account recovery itself.
        response.delete_cookie(
            key=RECENT_AUTH_COOKIE,
            path=COOKIE_PATH,
        )
        _delete_registration_cookie(response)

        access_token, refresh_token = _issue_user_session(
            result.user,
            response,
        )

        return {
            "user": _serialize_user(
                result.user,
                db,
            ),
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "provider": "google",
            "action": "reactivated",
            "reactivated": True,
        }

    if result.action == "reauthenticated":
        if not result.user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "message": "Google reauthentication completed without a user.",
                    "code": "GOOGLE_REAUTH_USER_MISSING",
                },
            )

        recent_auth_token = create_recent_auth_token(
            user_id=result.user.id,
            token_version=result.user.token_version,
            provider="google",
        )

        response.set_cookie(
            key=RECENT_AUTH_COOKIE,
            value=recent_auth_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            max_age=RECENT_AUTH_TOKEN_SECONDS,
            path=COOKIE_PATH,
        )

        return {
            "provider": "google",
            "action": "reauthenticated",
            "reauthenticated": True,
            "expires_in": RECENT_AUTH_TOKEN_SECONDS,
        }

    if result.action == "registration_required":
        if not result.registration_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "message": "Unable to start Google registration.",
                    "code": "GOOGLE_REGISTRATION_START_FAILED",
                },
            )

        response.set_cookie(
            key=GOOGLE_REGISTRATION_COOKIE,
            value=result.registration_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=GOOGLE_REGISTRATION_TOKEN_MAX_AGE_SECONDS,
            path=GOOGLE_OAUTH_COOKIE_PATH,
        )

        return {
            "provider": "google",
            "action": "registration_required",
            "registration_required": True,
            # This email is safe display data. The authoritative identity
            # remains in the signed HttpOnly registration cookie.
            "email": result.verified_email,
        }

    if not result.user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "message": "Google authentication completed without a user.",
                "code": "GOOGLE_AUTH_USER_MISSING",
            },
        )

    _delete_registration_cookie(response)

    access_token, refresh_token = _issue_user_session(
        result.user,
        response,
    )

    return {
        "user": _serialize_user(result.user, db),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "provider": "google",
        "action": "authenticated",
    }


@router.get("/register/pending")
def google_registration_pending(
    registration_token: Optional[str] = Cookie(
        default=None,
        alias=GOOGLE_REGISTRATION_COOKIE,
    ),
):
    try:
        identity = verify_google_registration_token(
            registration_token
        )
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    return {
        "provider": "google",
        "email": identity.verified_email,
        "registration_pending": True,
    }


@router.post("/register/complete")
def complete_google_registration(
    payload: GoogleRegistrationComplete,
    request: Request,
    response: Response,
    registration_token: Optional[str] = Cookie(
        default=None,
        alias=GOOGLE_REGISTRATION_COOKIE,
    ),
    db: Session = Depends(get_db),
):
    try:
        identity = verify_google_registration_token(
            registration_token
        )
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    verify_turnstile_token(
        token=payload.turnstile_token,
        request=request,
        action="register",
    )

    # A user could create/link an account in another tab while this pending
    # Google registration is open. Resolve that case before inserting.
    try:
        existing_user = resolve_existing_google_user(
            db,
            provider_subject=identity.provider_subject,
            verified_email=identity.verified_email,
        )
    except GoogleOAuthError as exc:
        raise _google_oauth_http_exception(exc) from exc

    if existing_user:
        user = existing_user
        action = "authenticated_existing"
    else:
        user = create_google_user_in_db(
            payload,
            db,
            verified_email=identity.verified_email,
            provider_subject=identity.provider_subject,
        )
        action = "registered"

    _delete_registration_cookie(response)

    access_token, refresh_token = _issue_user_session(
        user,
        response,
    )

    return {
        "user": _serialize_user(user, db),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "provider": "google",
        "action": action,
    }
