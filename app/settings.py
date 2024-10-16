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

class Settings(BaseModel):
    db: DBSettings = DBSettings()

settings = Settings()