from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlencode

import requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.core.auth import (
    ALGORITHM,
    SECRET_KEY,
    ensure_user_can_authenticate,
)
from app.services.account_recovery import (
    AccountReactivationError,
    reactivate_user_account,
)
from app.util.security import canonicalize_email, hash_email


GOOGLE_PROVIDER = "google"
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = ("openid", "email", "profile")

GOOGLE_LOGIN_INTENT = "login"
GOOGLE_REGISTER_INTENT = "register"
GOOGLE_REAUTH_INTENT = "reauth"
GOOGLE_REACTIVATE_INTENT = "reactivate"

GOOGLE_ALLOWED_INTENTS = {
    GOOGLE_LOGIN_INTENT,
    GOOGLE_REGISTER_INTENT,
    GOOGLE_REAUTH_INTENT,
    GOOGLE_REACTIVATE_INTENT,
}

GOOGLE_REGISTRATION_TOKEN_TYPE = "google_registration"
GOOGLE_REGISTRATION_TOKEN_MAX_AGE_SECONDS = 15 * 60


class GoogleOAuthError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str = "GOOGLE_OAUTH_ERROR",
        status_code: int = 400,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class GoogleCallbackResult:
    action: Literal[
        "authenticated",
        "registration_required",
        "reauthenticated",
        "reactivated",
    ]
    user: models.User | None = None
    registration_token: str | None = None
    verified_email: str | None = None


@dataclass(frozen=True)
class GoogleRegistrationIdentity:
    provider_subject: str
    verified_email: str


def normalize_google_oauth_intent(intent: str | None) -> str:
    normalized = str(intent or GOOGLE_LOGIN_INTENT).strip().lower()

    if normalized not in GOOGLE_ALLOWED_INTENTS:
        raise GoogleOAuthError(
            "Invalid Google OAuth intent.",
            code="GOOGLE_OAUTH_INTENT_INVALID",
            status_code=400,
        )

    return normalized


def _google_client_id() -> str:
    return (os.getenv("GOOGLE_CLIENT_ID") or "").strip()


def _google_client_secret() -> str:
    return (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()


def _google_redirect_uri() -> str:
    return (os.getenv("GOOGLE_REDIRECT_URI") or "").strip()


def is_google_oauth_configured() -> bool:
    return bool(
        _google_client_id()
        and _google_client_secret()
        and _google_redirect_uri()
    )


def build_google_authorization_url(
    state: str,
    *,
    intent: str = GOOGLE_LOGIN_INTENT,
) -> str:
    if not is_google_oauth_configured():
        raise GoogleOAuthError(
            "Google OAuth is not configured yet.",
            code="GOOGLE_OAUTH_NOT_CONFIGURED",
            status_code=501,
        )

    if not state:
        raise GoogleOAuthError(
            "Missing Google OAuth state.",
            code="GOOGLE_OAUTH_STATE_MISSING",
            status_code=400,
        )

    normalized_intent = normalize_google_oauth_intent(intent)

    params = {
        "client_id": _google_client_id(),
        "redirect_uri": _google_redirect_uri(),
        "response_type": "code",
        "scope": " ".join(GOOGLE_SCOPES),
        "state": state,
        "access_type": "online",
        "include_granted_scopes": "true",
    }

    # Google OAuth does not expose a generic "force password" prompt. For
    # sensitive-action reauthentication, always require an explicit account
    # selection step and then verify the immutable Google sub against the
    # identity already linked to the signed-in GermFx user.
    if normalized_intent in {
        GOOGLE_REAUTH_INTENT,
        GOOGLE_REACTIVATE_INTENT,
    }:
        params["prompt"] = "select_account"

    return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(params)}"


def _validate_callback_state(
    state: str | None,
    expected_state: str | None,
) -> None:
    if not state or not expected_state:
        raise GoogleOAuthError(
            "Google OAuth state is missing or expired. Please try signing in again.",
            code="GOOGLE_OAUTH_STATE_INVALID",
            status_code=400,
        )

    if not secrets.compare_digest(state, expected_state):
        raise GoogleOAuthError(
            "Google OAuth state did not match. Please try signing in again.",
            code="GOOGLE_OAUTH_STATE_INVALID",
            status_code=400,
        )


def _exchange_code_for_tokens(code: str) -> dict[str, Any]:
    try:
        response = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": _google_client_id(),
                "client_secret": _google_client_secret(),
                "redirect_uri": _google_redirect_uri(),
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise GoogleOAuthError(
            "Unable to contact Google to complete sign in.",
            code="GOOGLE_TOKEN_EXCHANGE_FAILED",
            status_code=502,
        ) from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise GoogleOAuthError(
            "Google returned an invalid token response.",
            code="GOOGLE_TOKEN_EXCHANGE_FAILED",
            status_code=502,
        ) from exc

    if not response.ok:
        provider_error = payload.get("error_description") or payload.get("error")
        raise GoogleOAuthError(
            (
                f"Google token exchange failed: {provider_error}"
                if provider_error
                else "Google token exchange failed."
            ),
            code="GOOGLE_TOKEN_EXCHANGE_FAILED",
            status_code=400,
        )

    if not isinstance(payload, dict):
        raise GoogleOAuthError(
            "Google returned an invalid token response.",
            code="GOOGLE_TOKEN_EXCHANGE_FAILED",
            status_code=502,
        )

    return payload


def _verify_google_id_token(raw_id_token: str) -> dict[str, Any]:
    try:
        claims = google_id_token.verify_oauth2_token(
            raw_id_token,
            GoogleAuthRequest(),
            _google_client_id(),
            # Google and the application server can occasionally differ by a
            # second or two. This keeps strict token verification while
            # tolerating a very small clock difference.
            clock_skew_in_seconds=5,
        )
    except Exception as exc:
        print(
            "Google ID token verification failed: "
            f"{type(exc).__name__}: {exc}"
        )

        raise GoogleOAuthError(
            "Google identity verification failed.",
            code="GOOGLE_ID_TOKEN_INVALID",
            status_code=401,
        ) from exc

    return dict(claims)


def _claim_is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return str(value or "").strip().lower() in {"true", "1", "yes"}


def _extract_verified_identity(
    token_payload: dict[str, Any],
) -> tuple[str, str]:
    raw_id_token = token_payload.get("id_token")

    if not isinstance(raw_id_token, str) or not raw_id_token:
        raise GoogleOAuthError(
            "Google did not return an identity token.",
            code="GOOGLE_ID_TOKEN_MISSING",
            status_code=400,
        )

    claims = _verify_google_id_token(raw_id_token)

    provider_subject = str(claims.get("sub") or "").strip()
    email = canonicalize_email(str(claims.get("email") or ""))

    if not provider_subject:
        raise GoogleOAuthError(
            "Google did not return a valid account identifier.",
            code="GOOGLE_SUBJECT_MISSING",
            status_code=400,
        )

    if not email:
        raise GoogleOAuthError(
            "Google did not provide an email address.",
            code="GOOGLE_EMAIL_MISSING",
            status_code=400,
        )

    if not _claim_is_true(claims.get("email_verified")):
        raise GoogleOAuthError(
            "Your Google email address must be verified before it can be used to sign in.",
            code="GOOGLE_EMAIL_NOT_VERIFIED",
            status_code=403,
        )

    return provider_subject, email


def _get_user_for_linked_identity(
    db: Session,
    provider_subject: str,
):
    identity = db.execute(
        select(models.UserOAuthIdentity).where(
            models.UserOAuthIdentity.provider == GOOGLE_PROVIDER,
            models.UserOAuthIdentity.provider_subject == provider_subject,
        )
    ).scalars().first()

    if not identity:
        return None

    user = db.execute(
        select(models.User).where(
            models.User.id == identity.user_id
        )
    ).scalars().first()

    if not user:
        raise GoogleOAuthError(
            "The Google identity is linked to a GermFx account that no longer exists.",
            code="GOOGLE_LINKED_USER_NOT_FOUND",
            status_code=401,
        )

    ensure_user_can_authenticate(user)
    return user


def _find_user_by_verified_email(
    db: Session,
    verified_email: str,
):
    return db.execute(
        select(models.User).where(
            models.User.email_hash == hash_email(verified_email)
        )
    ).scalars().first()


def _link_google_identity_to_user(
    db: Session,
    *,
    user: models.User,
    provider_subject: str,
):
    ensure_user_can_authenticate(user)

    existing_provider_link = db.execute(
        select(models.UserOAuthIdentity).where(
            models.UserOAuthIdentity.user_id == user.id,
            models.UserOAuthIdentity.provider == GOOGLE_PROVIDER,
        )
    ).scalars().first()

    if existing_provider_link:
        if existing_provider_link.provider_subject == provider_subject:
            return user

        raise GoogleOAuthError(
            "This GermFx account is already linked to a different Google account.",
            code="GOOGLE_ACCOUNT_ALREADY_LINKED",
            status_code=409,
        )

    identity = models.UserOAuthIdentity(
        user_id=user.id,
        provider=GOOGLE_PROVIDER,
        provider_subject=provider_subject,
    )

    # Google has verified the exact email used to locate this account.
    if not user.is_email_verified:
        user.is_email_verified = True

    db.add(identity)
    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        linked_user = _get_user_for_linked_identity(
            db,
            provider_subject,
        )

        if linked_user:
            return linked_user

        raise GoogleOAuthError(
            "Unable to link this Google account to GermFx.",
            code="GOOGLE_ACCOUNT_LINK_FAILED",
            status_code=409,
        ) from exc

    db.refresh(user)
    return user


def resolve_existing_google_user(
    db: Session,
    *,
    provider_subject: str,
    verified_email: str,
):
    """
    Resolve an already-linked Google subject first. If it is new, apply the
    existing Option-A behavior: verified Google email may link to an existing
    GermFx account.

    Returns None only when there is genuinely no GermFx account yet.
    """
    linked_user = _get_user_for_linked_identity(
        db,
        provider_subject,
    )

    if linked_user:
        return linked_user

    email_user = _find_user_by_verified_email(
        db,
        verified_email,
    )

    if not email_user:
        return None

    return _link_google_identity_to_user(
        db,
        user=email_user,
        provider_subject=provider_subject,
    )


def resolve_google_reactivation_user(
    db: Session,
    *,
    provider_subject: str,
) -> models.User:
    """
    Resolve account recovery exclusively through an already-linked immutable
    Google subject.

    There is intentionally NO verified-email fallback here. Account recovery
    must never create or relink an OAuth identity.
    """
    identity = db.execute(
        select(models.UserOAuthIdentity).where(
            models.UserOAuthIdentity.provider == GOOGLE_PROVIDER,
            models.UserOAuthIdentity.provider_subject == provider_subject,
        )
    ).scalars().first()

    if not identity:
        raise GoogleOAuthError(
            (
                "No GermFx account is linked to this Google account. "
                "Try another Google account or use password recovery."
            ),
            code="GOOGLE_REACTIVATION_ACCOUNT_NOT_FOUND",
            status_code=404,
        )

    user = db.execute(
        select(models.User).where(
            models.User.id == identity.user_id
        )
    ).scalars().first()

    if not user:
        raise GoogleOAuthError(
            "The linked GermFx account could not be found.",
            code="GOOGLE_LINKED_USER_NOT_FOUND",
            status_code=404,
        )

    return user


def verify_google_reauthentication(
    db: Session,
    *,
    current_user: models.User,
    provider_subject: str,
) -> models.User:
    """
    Confirm that Google returned the exact immutable subject already linked to
    the currently authenticated GermFx user.

    Reauthentication intentionally does NOT:
    - link by email,
    - create identities,
    - switch GermFx accounts.
    """
    ensure_user_can_authenticate(current_user)

    identity = db.execute(
        select(models.UserOAuthIdentity).where(
            models.UserOAuthIdentity.user_id == current_user.id,
            models.UserOAuthIdentity.provider == GOOGLE_PROVIDER,
        )
    ).scalars().first()

    if not identity:
        raise GoogleOAuthError(
            "This GermFx account is not linked to Google.",
            code="GOOGLE_REAUTH_NOT_LINKED",
            status_code=403,
        )

    linked_subject = str(
        identity.provider_subject or ""
    ).strip()

    if (
        not linked_subject
        or not secrets.compare_digest(
            linked_subject,
            provider_subject,
        )
    ):
        raise GoogleOAuthError(
            (
                "The Google account you selected does not match the Google "
                "account linked to this GermFx account."
            ),
            code="GOOGLE_REAUTH_ACCOUNT_MISMATCH",
            status_code=403,
        )

    return current_user


def create_google_registration_token(
    *,
    provider_subject: str,
    verified_email: str,
) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(
        seconds=GOOGLE_REGISTRATION_TOKEN_MAX_AGE_SECONDS
    )

    return jwt.encode(
        {
            "type": GOOGLE_REGISTRATION_TOKEN_TYPE,
            "provider": GOOGLE_PROVIDER,
            "provider_subject": provider_subject,
            "email": canonicalize_email(verified_email),
            "iat": now,
            "exp": expires_at,
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def verify_google_registration_token(
    token: str | None,
) -> GoogleRegistrationIdentity:
    if not token:
        raise GoogleOAuthError(
            "Your Google registration session is missing or has expired.",
            code="GOOGLE_REGISTRATION_SESSION_INVALID",
            status_code=401,
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise GoogleOAuthError(
            "Your Google registration session is invalid or has expired.",
            code="GOOGLE_REGISTRATION_SESSION_INVALID",
            status_code=401,
        ) from exc

    if payload.get("type") != GOOGLE_REGISTRATION_TOKEN_TYPE:
        raise GoogleOAuthError(
            "Invalid Google registration session.",
            code="GOOGLE_REGISTRATION_SESSION_INVALID",
            status_code=401,
        )

    if payload.get("provider") != GOOGLE_PROVIDER:
        raise GoogleOAuthError(
            "Invalid Google registration provider.",
            code="GOOGLE_REGISTRATION_SESSION_INVALID",
            status_code=401,
        )

    provider_subject = str(
        payload.get("provider_subject") or ""
    ).strip()
    verified_email = canonicalize_email(
        str(payload.get("email") or "")
    )

    if not provider_subject or not verified_email:
        raise GoogleOAuthError(
            "Google registration identity is incomplete.",
            code="GOOGLE_REGISTRATION_SESSION_INVALID",
            status_code=401,
        )

    return GoogleRegistrationIdentity(
        provider_subject=provider_subject,
        verified_email=verified_email,
    )


def handle_google_callback(
    *,
    code: str | None,
    state: str | None,
    expected_state: str | None,
    intent: str | None,
    db: Session,
    current_user: models.User | None = None,
) -> GoogleCallbackResult:
    if not is_google_oauth_configured():
        raise GoogleOAuthError(
            "Google OAuth is not configured yet.",
            code="GOOGLE_OAUTH_NOT_CONFIGURED",
            status_code=501,
        )

    if not code:
        raise GoogleOAuthError(
            "Missing Google OAuth authorization code.",
            code="GOOGLE_AUTHORIZATION_CODE_MISSING",
            status_code=400,
        )

    normalized_intent = normalize_google_oauth_intent(intent)

    _validate_callback_state(
        state=state,
        expected_state=expected_state,
    )

    token_payload = _exchange_code_for_tokens(code)
    provider_subject, verified_email = _extract_verified_identity(
        token_payload
    )

    if normalized_intent == GOOGLE_REACTIVATE_INTENT:
        reactivation_user = resolve_google_reactivation_user(
            db,
            provider_subject=provider_subject,
        )

        try:
            reactivation_result = reactivate_user_account(
                db,
                reactivation_user,
            )
        except AccountReactivationError as exc:
            raise GoogleOAuthError(
                exc.message,
                code=exc.code,
                status_code=exc.status_code,
            ) from exc

        if reactivation_result.already_active:
            # The user proved ownership of an already-active Google-linked
            # account. Treat this as an ordinary authenticated result.
            ensure_user_can_authenticate(
                reactivation_result.user
            )

            return GoogleCallbackResult(
                action="authenticated",
                user=reactivation_result.user,
                verified_email=verified_email,
            )

        return GoogleCallbackResult(
            action="reactivated",
            user=reactivation_result.user,
            verified_email=verified_email,
        )

    if normalized_intent == GOOGLE_REAUTH_INTENT:
        if current_user is None:
            raise GoogleOAuthError(
                "You must be signed in before verifying your identity.",
                code="GOOGLE_REAUTH_AUTH_REQUIRED",
                status_code=401,
            )

        reauthenticated_user = verify_google_reauthentication(
            db,
            current_user=current_user,
            provider_subject=provider_subject,
        )

        return GoogleCallbackResult(
            action="reauthenticated",
            user=reauthenticated_user,
            verified_email=verified_email,
        )

    existing_user = resolve_existing_google_user(
        db,
        provider_subject=provider_subject,
        verified_email=verified_email,
    )

    if existing_user:
        return GoogleCallbackResult(
            action="authenticated",
            user=existing_user,
            verified_email=verified_email,
        )

    if normalized_intent == GOOGLE_LOGIN_INTENT:
        raise GoogleOAuthError(
            (
                "No existing GermFx account matches this Google email. "
                "Create a GermFx account first, then try Google sign in again."
            ),
            code="GOOGLE_ACCOUNT_NOT_FOUND",
            status_code=404,
        )

    registration_token = create_google_registration_token(
        provider_subject=provider_subject,
        verified_email=verified_email,
    )

    return GoogleCallbackResult(
        action="registration_required",
        registration_token=registration_token,
        verified_email=verified_email,
    )