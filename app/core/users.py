from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from app import models
from app.util.security import (
  hash_email,
  encrypt_email,
  hash_password,
  canonicalize_email,
)

from app.scripts.validator import (
    validate_new_email,
    validate_new_password,
    validate_username
)
from app.schemas.users import GoogleRegistrationComplete, UserCreate

def create_user_in_db(payload: UserCreate, db: Session) -> models.User:
    username = payload.username.strip()
    email = canonicalize_email(payload.email)
    password = payload.password

    # 1. Backend validation
    username_error = validate_username(username)
    if username_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=username_error,
        )

    password_error = validate_new_password(password)
    if password_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_error,
        )

    # 2. Normalize + secure email fields
    email_hash = hash_email(email)
    email_enc = encrypt_email(email)

    # 3. Check uniqueness
    existing = db.execute(
        select(models.User).where(
            (func.lower(models.User.username) == username.lower())
            | (models.User.email_hash == email_hash)
        )
    ).scalars().first()

    if existing:
        if existing.username.lower() == username.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already taken",
            )

        if existing.email_hash == email_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            )

    # 4. Hash password
    pwd_hash = hash_password(password)

    # 5. Create user
    user = models.User(
        username=username,
        email_hash=email_hash,
        email_enc=email_enc,
        password_hash=pwd_hash,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

def create_google_user_in_db(
    payload: GoogleRegistrationComplete,
    db: Session,
    *,
    verified_email: str,
    provider_subject: str,
) -> models.User:
    """
    Create a brand-new GermFx account from a verified Google identity.

    Security boundary:
    - username / accepted / Turnstile come from the browser payload.
    - verified_email and provider_subject MUST come from the server-verified
      Google registration token, never from browser-controlled fields.

    The User and UserOAuthIdentity are committed in the same transaction so
    GermFx never creates an OAuth-only user without its Google identity link.
    """
    username = payload.username.strip()
    email = canonicalize_email(verified_email)
    provider_subject = str(provider_subject or "").strip()

    username_error = validate_username(username)
    if username_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=username_error,
        )

    if not payload.accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must agree to the Terms of Service and Privacy Policy",
        )

    if not email or not provider_subject:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google registration identity is incomplete.",
        )

    email_hash = hash_email(email)
    email_enc = encrypt_email(email)

    existing_user = db.execute(
        select(models.User).where(
            (func.lower(models.User.username) == username.lower())
            | (models.User.email_hash == email_hash)
        )
    ).scalars().first()

    if existing_user:
        if existing_user.username.lower() == username.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already taken",
            )

        if existing_user.email_hash == email_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            )

    existing_identity = db.execute(
        select(models.UserOAuthIdentity).where(
            models.UserOAuthIdentity.provider == "google",
            models.UserOAuthIdentity.provider_subject == provider_subject,
        )
    ).scalars().first()

    if existing_identity:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "This Google account is already linked to GermFx.",
                "code": "GOOGLE_ACCOUNT_ALREADY_REGISTERED",
            },
        )

    user = models.User(
        username=username,
        email_hash=email_hash,
        email_enc=email_enc,
        password_hash=None,
        is_email_verified=True,
    )

    try:
        db.add(user)

        # Obtain user.id without committing yet.
        db.flush()

        identity = models.UserOAuthIdentity(
            user_id=user.id,
            provider="google",
            provider_subject=provider_subject,
        )

        db.add(identity)
        db.commit()
        db.refresh(user)
        return user

    except IntegrityError as exc:
        db.rollback()

        # A uniqueness race can still occur between our pre-check and commit.
        username_exists = db.execute(
            select(models.User).where(
                func.lower(models.User.username) == username.lower()
            )
        ).scalars().first()

        if username_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already taken",
            ) from exc

        email_exists = db.execute(
            select(models.User).where(
                models.User.email_hash == email_hash
            )
        ).scalars().first()

        if email_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            ) from exc

        linked_identity = db.execute(
            select(models.UserOAuthIdentity).where(
                models.UserOAuthIdentity.provider == "google",
                models.UserOAuthIdentity.provider_subject == provider_subject,
            )
        ).scalars().first()

        if linked_identity:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "This Google account is already linked to GermFx.",
                    "code": "GOOGLE_ACCOUNT_ALREADY_REGISTERED",
                },
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Unable to create the Google-linked GermFx account.",
                "code": "GOOGLE_REGISTRATION_CONFLICT",
            },
        ) from exc