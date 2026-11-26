from datetime import UTC, datetime
from typing import Annotated

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, Form, HTTPException, Path, Request, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.security import create_access_token, generate_api_key, hash_password, verify_password
from app.db.session import get_db
from app.models import ApiKey, User
from app.schemas.auth import (
    PASSWORD_MAX,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRead,
    PasswordChange,
    Token,
    UserCreate,
    UserRead,
    UserUpdate,
)
from app.schemas.common import MAX_DB_ID
from app.services.normalize import normalize_phone

router = APIRouter(prefix="/v1", tags=["auth"])

MAX_ACTIVE_API_KEYS = 10
# Verifying against a throwaway hash when the account doesn't exist keeps response times equal,
# so attackers can't tell registered emails apart by how fast login fails.
_DUMMY_HASH = hash_password("dummy-Password-1!")


def _validation_error(field: str, message: str) -> RequestValidationError:
    """Same 422 shape as schema validation errors (see the handler in app.main)."""
    return RequestValidationError([{"loc": ("body", field), "msg": message, "type": "value_error"}])


async def _ensure_unique(db: AsyncSession, *, email: str | None = None, phone: str | None = None,
                         exclude_id: int | None = None) -> None:
    """Friendly 409s before insert. The DB unique constraints still guard against races."""
    for column, value, label in ((User.email, email, "Email"), (User.phone, phone, "Phone number")):
        if value is None:
            continue
        q = select(User.id).where(column == value)
        if exclude_id is not None:
            q = q.where(User.id != exclude_id)
        if (await db.execute(q)).first():
            raise HTTPException(status.HTTP_409_CONFLICT, f"{label} already registered")


@router.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """Create a citizen account. All fields are validated strictly; see the schema for the rules."""
    await _ensure_unique(db, email=payload.email, phone=payload.phone)
    user = User(email=payload.email, password_hash=hash_password(payload.password), full_name=payload.full_name,
                phone=payload.phone, state=payload.state, city=payload.city, terms_accepted_at=datetime.now(UTC))
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:  # two sign-ups raced past the pre-check; the unique index decides
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email or phone number already registered") from None
    await db.refresh(user)
    return user


def _login_identifier(raw: str) -> tuple[str, str]:
    """Return (column, normalised value). Users may log in with their email or their mobile number."""
    if "@" in raw:
        try:
            return "email", validate_email(raw, check_deliverability=False).normalized.lower()
        except EmailNotValidError:
            raise _validation_error("username", "Enter a valid email address or 10-digit mobile number") from None
    phone = normalize_phone(raw)
    if phone is None:
        raise _validation_error("username", "Enter a valid email address or 10-digit mobile number")
    return "phone", phone


@router.post("/auth/login", response_model=Token)
async def login(
    request: Request,
    username: Annotated[str, Form(min_length=3, max_length=254, description="Email or mobile number")],
    password: Annotated[str, Form(min_length=1, max_length=PASSWORD_MAX)],
    grant_type: Annotated[str | None, Form(pattern="^password$")] = None,
    db: AsyncSession = Depends(get_db),
):
    """OAuth2 password form (works with Swagger's Authorize button). `username` = email or mobile number."""
    column, value = _login_identifier(username.strip())
    guard_keys = (f"acct:{column}:{value}",)
    ip_keys = (f"ip:{request.client.host if request.client else 'unknown'}",)
    request.app.state.login_guard.check(*guard_keys)
    request.app.state.login_ip_guard.check(*ip_keys)

    user = (await db.execute(select(User).where(getattr(User, column) == value))).scalar_one_or_none()
    password_ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not password_ok:
        request.app.state.login_guard.fail(*guard_keys)
        request.app.state.login_ip_guard.fail(*ip_keys)
        # Same message for both cases so attackers can't discover which accounts exist
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email/phone or password",
                            headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:  # only revealed to someone who knows the password
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account has been disabled")
    request.app.state.login_guard.reset(*guard_keys)
    return Token(access_token=create_access_token(user.id, user.role),
                 expires_in=get_settings().access_token_minutes * 60)


@router.get("/auth/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)):
    return user


@router.patch("/auth/me", response_model=UserRead)
async def update_me(payload: UserUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    changes = payload.model_dump(exclude_unset=True)
    await _ensure_unique(db, phone=changes.get("phone"), exclude_id=user.id)
    for field, value in changes.items():
        setattr(user, field, value)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Phone number already registered") from None
    await db.refresh(user)
    return user


@router.post("/auth/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(payload: PasswordChange, user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise _validation_error("current_password", "Current password is incorrect")
    if user.email.split("@")[0] in payload.new_password.lower() and len(user.email.split("@")[0]) >= 4:
        raise _validation_error("new_password", "Password must not contain your email address")
    user.password_hash = hash_password(payload.new_password)
    await db.commit()


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED, tags=["api keys"])
async def create_api_key(payload: ApiKeyCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    active = await db.scalar(select(func.count(ApiKey.id)).where(ApiKey.owner_id == user.id, ApiKey.is_active))
    if active >= MAX_ACTIVE_API_KEYS:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"You already have {MAX_ACTIVE_API_KEYS} active API keys. Revoke one first.")
    duplicate = await db.scalar(select(ApiKey.id).where(
        ApiKey.owner_id == user.id, ApiKey.is_active, func.lower(ApiKey.name) == payload.name.lower()))
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, "You already have an active API key with this name")
    raw, prefix, key_hash = generate_api_key()
    key = ApiKey(owner_id=user.id, name=payload.name, prefix=prefix, key_hash=key_hash)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return ApiKeyCreated(**ApiKeyRead.model_validate(key).model_dump(), api_key=raw)


@router.get("/api-keys", response_model=list[ApiKeyRead], tags=["api keys"])
async def list_api_keys(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(ApiKey).where(ApiKey.owner_id == user.id).order_by(ApiKey.id))).scalars().all()


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["api keys"])
async def revoke_api_key(key_id: Annotated[int, Path(ge=1, le=MAX_DB_ID)], user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if key is None or key.owner_id != user.id:  # 404, not 403: don't reveal other users' key ids
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if not key.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, "API key is already revoked")
    key.is_active = False  # soft-revoke keeps the audit trail
    await db.commit()
