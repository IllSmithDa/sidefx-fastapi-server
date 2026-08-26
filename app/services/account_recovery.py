from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models
from app.util.security import canonicalize_email, hash_email


class AccountReactivationError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        status_code: int,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class AccountReactivationResult:
    user: models.User
    already_active: bool


def find_user_for_reactivation(
    db: Session,
    identifier: str,
) -> models.User | None:
    """
    Find an account by the same identifier semantics used by the existing
    password reactivation flow: email or username.
    """
    normalized_identifier = str(identifier or "").strip()

    if not normalized_identifier:
        return None

    if "@" in normalized_identifier:
        normalized_email = canonicalize_email(
            normalized_identifier
        )
        email_hash = hash_email(normalized_email)

        return db.execute(
            select(models.User).where(
                models.User.email_hash == email_hash
            )
        ).scalars().first()

    return db.execute(
        select(models.User).where(
            func.lower(models.User.username)
            == normalized_identifier.lower()
        )
    ).scalars().first()


def reactivate_user_account(
    db: Session,
    user: models.User,
) -> AccountReactivationResult:
    """
    Reactivate a user after the caller has already proven account ownership.

    This function deliberately does not perform password or OAuth verification.
    It centralizes only the account-state policy and database mutation so both
    password reactivation and Google reactivation behave identically.
    """
    account_status = getattr(
        user,
        "account_status",
        "active",
    )

    if account_status == "suspended":
        raise AccountReactivationError(
            (
                "This account has been suspended and cannot be "
                "reactivated here."
            ),
            code="ACCOUNT_SUSPENDED",
            status_code=403,
        )

    if bool(user.is_active) and account_status == "active":
        return AccountReactivationResult(
            user=user,
            already_active=True,
        )

    # Current GermFx deactivation writes account_status='deactivated' and
    # deactivated_at. Checking both also keeps older deactivated records
    # recoverable if their status field was not populated correctly.
    is_deactivated = (
        account_status == "deactivated"
        or getattr(user, "deactivated_at", None) is not None
    )

    if not is_deactivated:
        raise AccountReactivationError(
            "This inactive account cannot be reactivated through this flow.",
            code="ACCOUNT_REACTIVATION_NOT_ALLOWED",
            status_code=403,
        )

    user.is_active = True

    if hasattr(user, "account_status"):
        user.account_status = "active"

    if hasattr(user, "deactivated_at"):
        user.deactivated_at = None

    if hasattr(user, "suspended_at"):
        user.suspended_at = None

    if hasattr(user, "suspension_reason"):
        user.suspension_reason = None

    if hasattr(user, "token_version"):
        # Any tokens issued before deactivation/recovery remain invalid.
        user.token_version += 1

    db.add(user)
    db.commit()
    db.refresh(user)

    return AccountReactivationResult(
        user=user,
        already_active=False,
    )