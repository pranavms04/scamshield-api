"""Shared building blocks for strict request validation.

Every request model inherits StrictModel, which:
- rejects unknown fields (so a client can't sneak in e.g. {"role": "admin"}),
- strips surrounding whitespace from strings (so "   " counts as empty).

The validators below also reject NUL / control characters: PostgreSQL refuses NUL bytes in TEXT
columns, so letting one through would turn a bad request into a 500.
"""
import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.models.enums import EntityType
from app.services.normalize import normalize

# Postgres INTEGER is 32-bit; bigger ids would raise a DB error (500) instead of a clean 404/422.
MAX_DB_ID = 2_147_483_647

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]*[A-Za-z.]$")
_CITY_RE = re.compile(r"^[A-Za-z][A-Za-z .\-]*[A-Za-z]$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def no_control_chars(value: str | None) -> str | None:
    if value is not None and _CONTROL_CHARS.search(value):
        raise ValueError("must not contain control characters")
    return value


def collapse_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", value)


def must_have_letters(value: str | None) -> str | None:
    if value is not None and not re.search(r"[A-Za-zऀ-෿]", value):
        raise ValueError("must contain real words, not only numbers or symbols")
    return value


def person_name(value: str) -> str:
    value = collapse_spaces(value)
    if not _NAME_RE.fullmatch(value):
        raise ValueError("may contain only letters, spaces, dots, apostrophes and hyphens")
    return value


def city_name(value: str | None) -> str | None:
    if value is None:
        return None
    value = collapse_spaces(value)
    if not _CITY_RE.fullmatch(value):
        raise ValueError("may contain only letters, spaces, dots and hyphens")
    return value


def _entity(etype: EntityType):
    def check(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize(etype, value)
        if normalized is None:
            raise ValueError(f"is not a valid {_LABELS[etype]}")
        return normalized
    return check


_LABELS = {
    EntityType.phone: "Indian mobile number (10 digits starting with 6-9, optional +91)",
    EntityType.upi: "UPI ID (e.g. name@okaxis)",
    EntityType.url: "link (e.g. example.com/path)",
}

SafeText = Annotated[str, AfterValidator(no_control_chars)]
IndianMobile = Annotated[str, Field(min_length=10, max_length=20), AfterValidator(_entity(EntityType.phone))]
OptionalMobile = Annotated[str | None, Field(default=None, min_length=10, max_length=20),
                           AfterValidator(_entity(EntityType.phone))]
OptionalUpi = Annotated[str | None, Field(default=None, min_length=5, max_length=100),
                        AfterValidator(_entity(EntityType.upi))]
OptionalUrl = Annotated[str | None, Field(default=None, min_length=4, max_length=500),
                        AfterValidator(no_control_chars), AfterValidator(_entity(EntityType.url))]


def entity_value_for(etype: EntityType, value: str) -> str:
    """Normalise a report/lookup value, raising ValueError with a helpful message if it's not valid."""
    return _entity(etype)(value)
