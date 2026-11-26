"""Test setup: a throwaway SQLite DB, the offline 'rules' explainer and hashing embedder,
so tests run in seconds with no Postgres, Ollama or model downloads. CI runs these too."""
import os

os.environ.update({
    "DATABASE_URL": "sqlite+aiosqlite:///./test_scamshield.db",
    "AUTO_CREATE_TABLES": "true", "LLM_PROVIDER": "rules", "EMBEDDER": "hashing",
    "RATE_LIMIT_PER_MINUTE": "1000", "ENVIRONMENT": "test",
})

import asyncio  # noqa: E402
import hashlib  # noqa: E402
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


DEFAULT_PASSWORD = "Str0ng!Pass#9"


def signup_body(email="user@example.com", password=DEFAULT_PASSWORD, **overrides):
    """A valid registration body. Each email gets its own (deterministic) unique mobile number."""
    phone = "9" + str(int(hashlib.sha256(email.encode()).hexdigest(), 16))[-9:]
    body = {"full_name": "Priya Sharma", "email": email, "phone": phone, "password": password,
            "confirm_password": password, "state": "Kerala", "city": "Kochi", "accept_terms": True}
    return {**body, **overrides}


def register_and_login(client, email="user@example.com", password=DEFAULT_PASSWORD):
    r = client.post("/v1/auth/register", json=signup_body(email, password))
    assert r.status_code == 201, r.json()
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
