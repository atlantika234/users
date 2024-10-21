from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class User(BaseModel):
    name: str = Field(min_length=5, max_length=20, example="username")
    email: EmailStr
    password: str = Field(min_length=6, example="password")

    class Config:
        from_attributes = True

class UserModel(BaseModel):
    username: str
    email: EmailStr
    created_at: datetime

class UserResponse(UserModel):
    id: int

    class Config:
        from_attributes = True

class UserCreationModel(BaseModel):
    username: str = Field(min_length=5, max_length=20, example="username")
    email: EmailStr
    password: str = Field(min_length=6)

class TokenLoginResponse(BaseModel):
    access_token: str
    access_expired_at: datetime
    refresh_token: str
    refresh_expired_at: datetime
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class UserInDB(User):
    hashed_password: str