from __future__ import annotations
from pydantic import BaseModel, Field

class GoogleMobileLoginRequest(
    BaseModel
):
    id_token: str = Field(
        min_length=1,
        max_length=8192,
    )