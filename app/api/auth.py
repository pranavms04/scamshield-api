from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import create_access_token, generate_api_key, hash_password, verify_password
from app.db.session import get_db
from app.models import ApiKey, User
from app.schemas.auth import ApiKeyCreate, ApiKeyCreated, ApiKeyRead, Token, UserCreate, UserRead

router = APIRouter(prefix="/v1", tags=["auth"])


@router.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:  # unique email constraint — let the DB enforce it, no race condition
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None
    await db.refresh(user)
    return user


@router.post("/auth/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form.username.lower()))).scalar_one_or_none()
    if user is None or not verify_password(form.password, user.password_hash):
        # Same message for both cases so attackers can't discover which emails exist
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    return Token(access_token=create_access_token(user.id, user.role))


@router.get("/auth/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)):
    return user


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED, tags=["api keys"])
async def create_api_key(payload: ApiKeyCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
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
async def revoke_api_key(key_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if key is None or key.owner_id != user.id:  # 404, not 403: don't reveal other users' key ids
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    key.is_active = False  # soft-revoke keeps the audit trail
    await db.commit()
