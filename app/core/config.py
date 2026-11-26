from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Every setting can be overridden by an environment variable of the same name."""

    app_name: str = "ScamShield API"
    environment: Literal["dev", "test", "prod"] = "dev"

    database_url: str = "sqlite+aiosqlite:///./scamshield.db"
    auto_create_tables: bool = True  # dev convenience; prod uses Alembic

    jwt_secret: str = "dev-only-secret-change-me-in-production-please"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60

    embedder: Literal["hashing", "sentence-transformers"] = "hashing"
    embedding_dim: int = 384

    llm_provider: Literal["ollama", "rules"] = "rules"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    llm_timeout_seconds: float = 20.0

    rate_limit_per_minute: int = 60
    check_cache_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def no_default_secret_in_prod(self):
        if self.environment == "prod" and self.jwt_secret.startswith("dev-only"):
            raise ValueError("Set a real JWT_SECRET in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
