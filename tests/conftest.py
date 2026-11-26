"""Test setup: a throwaway SQLite DB, the offline 'rules' explainer and hashing embedder,
so tests run in seconds with no Postgres, Ollama or model downloads. CI runs these too."""
import os

os.environ.update({
    "DATABASE_URL": "sqlite+aiosqlite:///./test_scamshield.db",
    "AUTO_CREATE_TABLES": "true", "LLM_PROVIDER": "rules", "EMBEDDER": "hashing",
    "RATE_LIMIT_PER_MINUTE": "1000", "ENVIRONMENT": "test",
})

import asyncio  # noqa: E402
import pathlib  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.models.enums import Role  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
    async def reset():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    asyncio.run(reset())


def pytest_sessionfinish(session, exitstatus):
    pathlib.Path("test_scamshield.db").unlink(missing_ok=True)


def register_and_login(client, email="user@example.com", password="s3cret-pass"):
    client.post("/v1/auth/register", json={"email": email, "password": password})
    r = client.post("/v1/auth/login", data={"username": email, "password": password})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_moderator(client, email="mod@example.com"):
    headers = register_and_login(client, email)
    async def promote():
        async with SessionLocal() as db:
            from sqlalchemy import update
            await db.execute(update(User).where(User.email == email).values(role=Role.moderator))
            await db.commit()
    asyncio.run(promote())
    return headers
