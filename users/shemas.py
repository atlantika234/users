from pydantic import BaseModel, EmailStr, Field


class User(BaseModel):
    name: str = Field(min_length=5, max_length=20, example="username")
    email: EmailStr
    password: str = Field(min_length=6, example="password")

    class Config:
        orm_mode = True