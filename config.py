# config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_TITLE: str = "PromptRedTeam API"
    API_VERSION: str = "0.1.0"
    
    RATE_LIMIT_ENABLED: bool = False  # Default off for self-hosters
    RATE_LIMIT_PER_MINUTE: int = 60
    MAX_TEXT_LENGTH: int = 100000
    
    CORS_ORIGINS: list = ["*"]
    
    class Config:
        env_file = ".env"

settings = Settings()