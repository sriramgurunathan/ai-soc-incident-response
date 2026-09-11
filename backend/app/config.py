import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings:
    PROJECT_NAME: str = "ApexShield AI-SOC Enterprise Defense Platform"
    VERSION: str = "2.0.0"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "apexshield-ultra-secure-jwt-token-secret-key-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8

    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/apexshield_soc.db")

    BURST_WINDOW_SECONDS: int = 15
    BURST_FAILURE_THRESHOLD: int = 5

    HUMAN_WINDOW_SECONDS: int = 180
    HUMAN_FAILURE_LIMIT: int = 4

    PASSWORD_HISTORY_LIMIT: int = 3
    MIN_PASSWORD_LENGTH: int = 8

    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

settings = Settings()
