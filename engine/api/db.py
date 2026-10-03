from sqlalchemy import Engine, create_engine

from api.settings import Settings


def make_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True)


def engines_from(settings: Settings) -> tuple[Engine, Engine, Engine]:
    return (
        make_engine(settings.database_url),
        make_engine(settings.keys_database_url),
        make_engine(settings.worker_database_url),
    )
