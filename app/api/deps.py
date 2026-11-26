from dataclasses import dataclass
from datetime import UTC, datetime

import jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token, hash_api_key
from app.db.session import get_db
from app.models import ApiKey, User
from app.models.enums import Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

UNAUTHORIZED = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing credentials",
                             headers={"WWW-Authenticate": "Bearer"})


async def _user_from_token(token: str, db: AsyncSession) -> User:
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise UNAUTHORIZED from None
    user = await db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise UNAUTHORIZED
    return user


async def get_current_user(token: str | None = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    if not token:
        raise UNAUTHORIZED
    return await _user_from_token(token, db)


def require_role(*roles: Role):
    """Usage: Depends(require_role(Role.moderator, Role.admin))"""
    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission for this action")
        return user
    return checker


@dataclass
class Client:
    """Who is calling /check: a B2B app with an API key, or a logged-in user."""
    id: str
    api_key_id: int | None = None
    user_id: int | None = None


async def get_client(
    request: Request,
    api_key: str | None = Security(api_key_header),
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Client:
    if api_key:
        key = (await db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(api_key)))).scalar_one_or_none()
        if key is None or not key.is_active:
            raise UNAUTHORIZED
        key.last_used_at = datetime.now(UTC)
        await db.commit()
        client = Client(id=f"key:{key.id}", api_key_id=key.id)
    elif token:
        user = await _user_from_token(token, db)
        client = Client(id=f"user:{user.id}", user_id=user.id)
    else:
        raise UNAUTHORIZED
    request.app.state.limiter.hit(client.id)  # 429 if over the limit
    return client
