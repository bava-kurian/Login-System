from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "mysql://user:password@localhost/db"
    secret_key: str = "changeme"

    class Config:
        env_file = ".env"

settings = Settings()
