from dotenv import load_dotenv
import os
from pydantic import BaseModel

load_dotenv(override=True)

class DBSettings(BaseModel):
    ENGINE: str = os.getenv('DB_ENGINE')
    NAME: str = os.getenv('DB_NAME')
    USER: str = os.getenv('DB_USER')
    PASSWORD: str = os.getenv('DB_PASSWORD')
    HOST: str = os.getenv('DB_HOST')
    PORT: str = os.getenv('DB_PORT')

    @property
    def CONNECTION_STRING(self) -> str:
        return f"{self.ENGINE}://{self.USER}:{self.PASSWORD}@{self.HOST}:{self.PORT}/{self.NAME}"


class AppSettings(BaseModel):
    NAME: str = "authText"
    VERSION: str = '0.0.1'
    HOST: str = os.getenv("APP_HOST", "localhost")
    PORT: int = int(os.getenv("APP_PORT", 8080))
    ENV: str = os.getenv("APP_ENV", "development")
    SECRET_KEY: str = os.getenv('SECRET_KEY')
    BASE_URL_PREFIX: str = '/develop'

    @property
    def LOGIN_URL(self) -> str:
        return f"{self.BASE_URL_PREFIX}/session"

class TokenSettings(BaseModel):
    ALGORITHM: str = "HS256"
    DEFAULT_EXPIRED: str = 60
    ACCESS_EXPIRED: int = 1
    REFRESH_EXPIRED: int = 7 * 1440

class Settings(BaseModel):
    app: AppSettings = AppSettings()
    db: DBSettings = DBSettings()
    token: TokenSettings = TokenSettings()

settings = Settings()