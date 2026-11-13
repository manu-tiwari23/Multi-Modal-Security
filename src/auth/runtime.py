from functools import lru_cache

from src.shared.config import settings
from .repository import MemoryAuthRepository, PostgresAuthRepository
from .service import AuthService


@lru_cache
def get_auth_service():
    repository = (MemoryAuthRepository() if settings.auth_storage_mode == "memory" else
                  PostgresAuthRepository(settings.postgres_url, settings.auth_db_schema, settings.storage_timeout_seconds))
    return AuthService(repository)
