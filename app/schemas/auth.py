import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.models.enums import IndianState, Role
from app.schemas.common import (
    IndianMobile,
    OptionalMobile,
    SafeText,
    StrictModel,
    city_name,
    person_name,
)

PASSWORD_MIN, PASSWORD_MAX = 8, 64  # an upper bound stops multi-MB "passwords" from tying up Argon2

# Small deny-list of the passwords attackers try first. Matching is case-insensitive and ignores
# trailing digits/symbols, so "Password@123" is caught too.
COMMON_PASSWORDS = {
    "password", "passw0rd", "qwerty", "qwertyuiop", "letmein", "welcome", "admin", "administrator",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "cricket", "india", "bharat",
    "abc", "abcd", "abcdef", "asdf", "zxcvbn", "secret", "changeme", "default", "login", "master",
    "scamshield", "user", "test", "guest",
}
_SEQUENCES = ("0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def strong_password(value: str) -> str:
    problems = []
    if re.search(r"\s", value):
        problems.append("must not contain spaces")
    if not re.search(r"[a-z]", value):
        problems.append("needs a lowercase letter")
    if not re.search(r"[A-Z]", value):
        problems.append("needs an uppercase letter")
    if not re.search(r"\d", value):
        problems.append("needs a digit")
    if not re.search(r"[^A-Za-z0-9\s]", value):
        problems.append("needs a special character (e.g. ! @ # $ %)")
    if re.search(r"(.)\1{3,}", value):
        problems.append("must not repeat the same character 4+ times in a row")
    lower = value.lower()
    if any(seq[i:i + 5] in lower for seq in _SEQUENCES for i in range(len(seq) - 4)):
        problems.append("must not contain an obvious sequence like 12345 or abcde")
    if re.sub(r"[\d\W_]+$", "", lower) in COMMON_PASSWORDS:
        problems.append("is too common")
    if problems:
        raise ValueError("Password " + "; ".join(problems))
    return value


Password = Annotated[str, Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX), AfterValidator(strong_password)]


class UserCreate(StrictModel):
    """Citizen sign-up. Citizens use the account to report scam numbers, UPI IDs and links."""

    full_name: Annotated[str, Field(min_length=2, max_length=100, examples=["Priya Sharma"]),
                         AfterValidator(person_name)]
    email: Annotated[EmailStr, Field(max_length=254, examples=["priya@example.com"])]
    phone: Annotated[IndianMobile, Field(examples=["+91 98765 43210"],
                                         description="Indian mobile number; stored as +91XXXXXXXXXX")]
    password: Annotated[Password, Field(examples=["Str0ng!Pass"],
                                        description="8-64 chars with upper, lower, digit and special character")]
    confirm_password: str = Field(max_length=PASSWORD_MAX)
    state: IndianState = Field(description="State / UT you live in, used to route reports to the right cyber cell")
    city: Annotated[str | None, Field(default=None, min_length=2, max_length=60, examples=["Kochi"]),
                    AfterValidator(city_name)]
    accept_terms: bool = Field(description="Must be true: you agree to the terms and to report only genuine scams")

    @field_validator("email")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def cross_field_checks(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        if not self.accept_terms:
            raise ValueError("You must accept the terms to register")
        pw = self.password.lower()
        local_part = self.email.split("@")[0]
        if len(local_part) >= 4 and local_part in pw:
            raise ValueError("Password must not contain your email address")
        if any(len(part) >= 4 and part.lower() in pw for part in self.full_name.split()):
            raise ValueError("Password must not contain your name")
        if self.phone[-10:] in re.sub(r"\D", "", self.password):
            raise ValueError("Password must not contain your phone number")
        return self


class UserUpdate(StrictModel):
    """Update your own profile. Send only the fields you want to change."""

    full_name: Annotated[str | None, Field(default=None, min_length=2, max_length=100),
                         AfterValidator(lambda v: person_name(v) if v is not None else v)]
    phone: OptionalMobile
    state: IndianState | None = None
    city: Annotated[str | None, Field(default=None, min_length=2, max_length=60), AfterValidator(city_name)]

    @model_validator(mode="after")
    def not_empty(self):
        if not self.model_fields_set:
            raise ValueError("Send at least one field to update")
        for name in ("full_name", "phone", "state"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be cleared")
        return self


class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX)
    new_password: Password
    confirm_new_password: str = Field(max_length=PASSWORD_MAX)

    @model_validator(mode="after")
    def check(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match")
        if self.new_password == self.current_password:
            raise ValueError("New password must be different from the current one")
        return self


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    full_name: str | None
    email: EmailStr
    phone: str | None
    state: IndianState | None
    city: str | None
    role: Role
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Seconds until the token expires")


class ApiKeyCreate(StrictModel):
    name: Annotated[SafeText, Field(min_length=3, max_length=100, examples=["Paytm-style wallet app (staging)"])]


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
