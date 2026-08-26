# app/routes/account_danger.py
from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Response,
    status,
)
from sqlalchemy.orm import Session

from app import models
from app.core.auth import (
    RECENT_AUTH_COOKIE,
    get_authenticated_user,
    verify_recent_auth_for_user,
)
from app.core.auth_config import (
    ACCESS_COOKIE,
    COOKIE_PATH,
    REFRESH_COOKIE,
)
from app.db import get_db
from app.schemas.users import (
    ConfirmPasswordRequest,
    DeleteAccountRequest,
)
from app.util.security import verify_password


router = APIRouter(tags=["account-danger"])


def _verify_sensitive_action_auth(
    *,
    current_user: models.User,
    current_password: str | None,
    recent_auth_token: str | None,
) -> None:
    """
    Require a fresh proof of identity before a destructive account action.

    A user may satisfy this requirement with either:
    - their current GermFx password, or
    - a valid short-lived recent-auth token issued after Google
      reauthentication.

    If a password value is explicitly supplied, it is treated as the chosen
    verification method and must be valid. We do not silently fall back to a
    recent-auth cookie after an incorrect password attempt.
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

        return

    # No password was supplied, so require recent OAuth reauthentication.
    verify_recent_auth_for_user(
        recent_auth_token,
        user=current_user,
        allowed_providers={"google"},
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        key=ACCESS_COOKIE,
        path=COOKIE_PATH,
    )
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=COOKIE_PATH,
    )
    response.delete_cookie(
        key=RECENT_AUTH_COOKIE,
        path=COOKIE_PATH,
    )


@router.post(
    "/deactivate-account",
    status_code=status.HTTP_200_OK,
)
def deactivate_account(
    payload: ConfirmPasswordRequest,
    response: Response,
    recent_auth_token: str | None = Cookie(
        default=None,
        alias=RECENT_AUTH_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        get_authenticated_user
    ),
):
    _verify_sensitive_action_auth(
        current_user=current_user,
        current_password=payload.current_password,
        recent_auth_token=recent_auth_token,
    )

    if hasattr(current_user, "is_active"):
        current_user.is_active = False

    if hasattr(current_user, "deactivated_at"):
        current_user.deactivated_at = datetime.now(
            timezone.utc
        )

    if hasattr(current_user, "account_status"):
        current_user.account_status = "deactivated"

    if hasattr(current_user, "suspension_reason"):
        current_user.suspension_reason = None

    if hasattr(current_user, "suspended_at"):
        current_user.suspended_at = None

    if hasattr(current_user, "token_version"):
        # Invalidates access, refresh, and recent-auth tokens carrying the
        # previous token version.
        current_user.token_version += 1

    db.add(current_user)
    db.commit()

    _clear_auth_cookies(response)

    return {
        "message": "Account deactivated successfully."
    }


@router.delete(
    "/delete-account",
    status_code=status.HTTP_200_OK,
)
def delete_account(
    payload: DeleteAccountRequest,
    response: Response,
    recent_auth_token: str | None = Cookie(
        default=None,
        alias=RECENT_AUTH_COOKIE,
    ),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        get_authenticated_user
    ),
):
    # The destructive confirmation is independent of authentication method.
    # Enforce it on the server; frontend validation alone is not sufficient.
    if payload.confirmation_text != "DELETE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": 'You must type "DELETE" exactly to confirm.',
                "code": "DELETE_CONFIRMATION_INVALID",
            },
        )

    _verify_sensitive_action_auth(
        current_user=current_user,
        current_password=payload.current_password,
        recent_auth_token=recent_auth_token,
    )

    if hasattr(current_user, "token_version"):
        current_user.token_version += 1

    db.delete(current_user)
    db.commit()

    _clear_auth_cookies(response)

    return {
        "message": "Account deleted successfully."
    }
