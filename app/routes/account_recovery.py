from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
)
from sqlalchemy.orm import Session

from app import models
from app.core.auth import (
    create_access_token,
    create_refresh_token,
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
from app.db import get_db
from app.schemas.users import ReactivateAccountRequest
from app.services.account_recovery import (
    AccountReactivationError,
    find_user_for_reactivation,
    reactivate_user_account,
)
from app.util.security import verify_password


router = APIRouter(tags=["account-recovery"])


def _issue_user_session(
    user: models.User,
    response: Response,
) -> tuple[str, str]:
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


@router.post(
    "/reactivate-account",
    status_code=status.HTTP_200_OK,
)
def reactivate_account(
    payload: ReactivateAccountRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Password-based account reactivation.

    OAuth-only users intentionally do not pass through this route. They use the
    Google OAuth flow with intent=reactivate so the immutable linked Google sub
    can prove account ownership.
    """
    identifier = payload.identifier.strip()

    user = find_user_for_reactivation(
        db,
        identifier,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "message": "Account not found.",
                "code": "ACCOUNT_NOT_FOUND",
            },
        )

    if not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": (
                    "This account does not have a GermFx password. "
                    "Use Google to reactivate the account."
                ),
                "code": "PASSWORD_NOT_SET",
            },
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Invalid credentials.",
                "code": "INVALID_CREDENTIALS",
            },
        )

    try:
        result = reactivate_user_account(
            db,
            user,
        )
    except AccountReactivationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.message,
                "code": exc.code,
            },
        ) from exc

    if result.already_active:
        return {
            "message": "Account is already active.",
            "code": "ACCOUNT_ALREADY_ACTIVE",
        }

    _issue_user_session(
        result.user,
        response,
    )

    return {
        "message": "Account reactivated successfully.",
        "code": "ACCOUNT_REACTIVATED",
    }
