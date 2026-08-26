from pydantic import BaseModel, EmailStr, Field, model_validator
from typing import Optional
from app.util.security import canonicalize_email


class UserCreate(BaseModel):
    username: str = Field(min_length=4, max_length=20)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    turnstile_token: str | None = Field(default=None, max_length=2048)

class GoogleRegistrationComplete(BaseModel):
    """
    Final step for a Google-authenticated user who does not yet have a
    GermFx account.

    Email and Google subject are deliberately NOT accepted from the browser.
    They come from the short-lived, signed Google-registration cookie.
    """
    username: str = Field(min_length=4, max_length=20)
    accepted: bool
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def validate_terms_acceptance(self):
        if not self.accepted:
            raise ValueError(
                "You must agree to the Terms of Service and Privacy Policy"
            )
        return self


class UserOut(BaseModel):
    id: int
    username: str
    is_email_verified: bool

    class Config:
        from_attributes = True


class UserDetailOut(BaseModel):
    id: Optional[int]
    username: str
    is_email_verified: Optional[bool] = None
    email: str

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    identifier: str
    password: str
    turnstile_token: str | None = Field(default=None, max_length=2048)


class ChangePasswordRequest(BaseModel):
    # Password users normally send this value. A user who also has a linked
    # Google identity may omit it after completing recent Google reauth.
    current_password: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match")

        if (
            self.current_password
            and self.current_password == self.new_password
        ):
            raise ValueError(
                "New password must be different from current password"
            )

        return self


class SetPasswordRequest(BaseModel):
    """
    Used only when the account does not yet have a GermFx password.

    Identity proof comes from the short-lived recent-auth cookie issued after
    Google reauthentication, never from the browser payload.
    """
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match")

        return self


class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(min_length=4, max_length=20)


class ChangeEmailRequest(BaseModel):
    # Optional because OAuth-only users verify with the short-lived recent-auth
    # cookie instead of a GermFx password.
    current_password: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    new_email: EmailStr
    confirm_new_email: EmailStr

    @model_validator(mode="after")
    def validate_emails(self):
        if (
            canonicalize_email(self.new_email)
            != canonicalize_email(self.confirm_new_email)
        ):
            raise ValueError("New emails do not match")
        return self
    

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    turnstile_token: str | None = Field(default=None, max_length=2048)

class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match")
        return self

class ConfirmPasswordRequest(BaseModel):
    # Password-authenticated users send this value.
    # OAuth-only users may omit it and instead satisfy sensitive-action
    # verification through the short-lived HttpOnly recent-auth cookie.
    current_password: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )


class DeleteAccountRequest(BaseModel):
    # Same authentication rule as ConfirmPasswordRequest. The DELETE text is
    # always required regardless of which authentication method confirms the
    # user's identity.
    current_password: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    confirmation_text: str = Field(min_length=1, max_length=32)

class ReactivateAccountRequest(BaseModel):
    identifier: str = Field(min_length=3)
    password: str = Field(min_length=1)