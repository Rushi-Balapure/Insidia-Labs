"""Process settings. The well-known dev master key is refused outside dev mode."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from api.crypto.kms import DEV_MASTER_KEY, DEV_TOKEN_PEPPER


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INSIDIA_", extra="ignore")

    dev_mode: bool = False
    dev_endpoints: bool = False
    database_url: str = "postgresql+psycopg://app_api:app_api_dev_only@localhost:5432/insidia"
    keys_database_url: str = (
        "postgresql+psycopg://app_keys:app_keys_dev_only@localhost:5432/insidia"
    )
    worker_database_url: str = (
        "postgresql+psycopg://app_worker:app_worker_dev_only@localhost:5432/insidia"
    )
    migration_database_url: str = (
        "postgresql+psycopg://insidia:insidia_dev_only@localhost:5432/insidia"
    )
    celery_database_url: str = (
        "db+postgresql+psycopg://celery_results:celery_results_dev_only@localhost:5432/insidia"
    )
    broker_url: str = "amqp://guest:guest@localhost:5672//"
    valkey_url: str = "redis://localhost:6379/0"
    master_key: bytes = Field(default=DEV_MASTER_KEY)
    token_pepper: bytes = Field(default=DEV_TOKEN_PEPPER)

    @field_validator("master_key", "token_pepper", mode="before")
    @classmethod
    def _as_bytes(cls, value: object) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            encoded = value.encode()
            if len(encoded) != 32:
                raise ValueError("key material must be 32 bytes")
            return encoded
        raise ValueError("key material must be bytes or a 32-byte string")

    def refuse_dev_secrets_outside_dev(self) -> None:
        if self.dev_mode:
            return
        if self.master_key == DEV_MASTER_KEY or self.token_pepper == DEV_TOKEN_PEPPER:
            raise RuntimeError("dev key material is refused when INSIDIA_DEV_MODE is off")
        if self.dev_endpoints:
            raise RuntimeError("dev endpoints are refused when INSIDIA_DEV_MODE is off")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.refuse_dev_secrets_outside_dev()
    return settings
