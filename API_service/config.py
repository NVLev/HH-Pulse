from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class RunConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8010


class DatabaseConfig(BaseModel):
    user: str
    password: str
    host: str = "pg"
    port: int = 5432
    db: str

    echo: bool = False
    echo_pool: bool = False
    pool_size: int = 5
    max_overflow: int = 10

    @property
    def url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.db}"
        )


class AuthConfig(BaseModel):
    secret_key: str
    algorithm: str = "HS256"
    ACCESS_EXPIRE_MINUTES: int = 15
    REFRESH_EXPIRE_DAYS: int = 7


class HHConfig(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: str
    api_base_url: str = "https://api.hh.ru"
    auth_url: str = "https://hh.ru/oauth/authorize"
    token_url: str = "https://api.hh.ru/token"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env"),
        case_sensitive=False,
        env_nested_delimiter="__",
        env_prefix="APP_CONFIG__",
    )

    run: RunConfig = RunConfig()
    db: DatabaseConfig = DatabaseConfig()
    auth: AuthConfig
    hh: HHConfig


settings = Settings()
