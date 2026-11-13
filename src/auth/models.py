from datetime import datetime
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

Role = Literal["viewer", "analyst", "admin"]
RESERVED_IDENTITIES = {"system", "copilot", "ai", "ai_copilot", "autonomous", "auto", "bot"}


def username(value):
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.@-]{2,63}", value) or value in RESERVED_IDENTITIES:
        raise ValueError("Use 3–64 letters, numbers, dots, underscores, @ or hyphens for a human account")
    return value


class UserInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: SecretStr
    role: Role = "analyst"

    @field_validator("username")
    @classmethod
    def valid_username(cls, value):
        return username(value)


class Principal(BaseModel):
    username: str
    role: Role
    expires_at: datetime | None = None
    session_hash: str = Field(default="", exclude=True)


class AuthError(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


class AuthStoreUnavailable(RuntimeError):
    pass
