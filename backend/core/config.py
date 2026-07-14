"""
Core Settings — loaded from .env via pydantic-settings
Import `settings` everywhere, never read os.environ directly.
Fixed: env_file path works whether run from project root or backend/.
"""
import os
from pydantic_settings import BaseSettings
from typing import List


# Resolve .env path — works from any working directory
_this_dir = os.path.dirname(os.path.abspath(__file__))   # .../backend/core
_backend_dir = os.path.dirname(_this_dir)                 # .../backend
_env_file = os.path.join(_backend_dir, ".env")


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+psycopg://cyberuser:cyberpass@localhost:5432/cyberplatform"

    # Redis
    REDIS_URL:             str = "redis://localhost:6379/0"
    CELERY_BROKER_URL:     str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # AI — Ollama (primary) + Groq (fallback)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL:    str = "dolphin-llama3"
    GROQ_API_KEY:    str = ""
    GROQ_MODEL:      str = "llama3.1-8b-instant"

    # Storage
    UPLOAD_DIR:       str = "./uploads"
    REPORTS_DIR:      str = "./reports"
    MAX_FILE_SIZE_MB: int = 20

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:8000"

    def get_origins(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    class Config:
        env_file = _env_file
        extra    = "ignore"


settings = Settings()