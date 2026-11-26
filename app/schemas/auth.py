from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import Role


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    role: Role
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100, examples=["Paytm-style wallet app (staging)"])


class ApiKeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None


class ApiKeyCreated(ApiKeyRead):
    api_key: str = Field(description="Shown ONCE. Store it safely; we only keep a hash.")
