from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "LAN Asset Discovery"
    log_level: str = "INFO"
    history_limit: int = 50
    default_timeout_seconds: float = 1.0
    default_max_concurrency: int = 64
    vendor_oui_file: str = "src/data/oui_sample.csv"

    model_config = SettingsConfigDict(env_prefix="LANSCAN_", env_file=".env", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
