from enum import Enum
from typing import Optional, Callable, List, Annotated
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from users.models import User
from sqlalchemy import or_
from jose import JWTError, jwt
from app.settings import settings
from app.db import Session
from users import shemas
from passlib.context import CryptContext
from datetime import datetime, timedelta
from dataclasses import dataclass
from pytz import UTC

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class TokenScopes(Enum):
    ACCESS = 'access_token'
    REFRESH = 'refresh_token'

class Password:
    def __init__(self, pwd_context: CryptContext):
        self.pwd_context = pwd_context

    def hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify(self, password: str, hash: str) -> bool:
        return self.pwd_context.verify(password, hash)

@dataclass
class TokenCoder:
    encode: Callable[[dict, str, str], str]
    decode: Callable[[str, str, List[str]], dict]
    error: Exception

class Token:
    def __init__(self, secret: str, config: settings.token, coder: TokenCoder) -> None:
        self.config = config
        self.coder = coder
        self.secret = secret

    async def create(self, data: dict, scope: TokenScopes, expires_delta: Optional[float] = None) -> dict:
        to_encode_data = data.copy()
        now = datetime.now(UTC)
        expired = now + timedelta(minutes=expires_delta) if expires_delta else now + timedelta(minutes=self.config.DEFAULT_EXPIRED)
        to_encode_data.update({"iat": now, "exp": expired, "scope": scope.value})
        token = self.coder.encode(to_encode_data, self.secret, algorithm=self.config.ALGORITHM)
        return {"token": token, "expired_at": expired, "scope": scope.value}

    async def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        return await self.create(data=data, scope=TokenScopes.ACCESS, expires_delta=expires_delta or self.config.ACCESS_EXPIRED)

    async def decode(self, token: str, scope: TokenScopes) -> dict:
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.config.ALGORITHM])
            if payload.get("scope") != scope.value:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token scope is invalid"
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

    async def decode_access(self, token: str) -> dict:
        return await self.decode(token, TokenScopes.ACCESS)

class Auth:
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
    invalid_credential_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid username or password')

    def __init__(self, password: Password, token: Token) -> None:
        self.password = password
        self.token = token

    def validate(self, user: Optional[User], credentials: OAuth2PasswordRequestForm) -> bool:
        if user is None:
            return False
        if not self.password.verify(credentials.password, user.password):
            return False
        return True

    async def authenticate(self, credentials: OAuth2PasswordRequestForm, db: Session) -> shemas.TokenLoginResponse:
        user = await self.__get_user(credentials.username, db)
        if not self.validate(user, credentials):
            raise self.invalid_credential_error
        return await self.__generate_tokens(user)

    async def __get_user(self, name: str, db: Session) -> Optional[User]:
        return db.query(User).filter(or_(
            User.email == name,
            User.name == name
        )).first()

    async def __generate_tokens(self, user: User) -> shemas.TokenLoginResponse:
        access_token = await self.token.create_access_token({"email": user.email})

        return shemas.TokenLoginResponse(
            access_token=access_token["token"],
            access_expired_at=access_token["expired_at"],
            token_type="bearer"
        )

auth: Auth = Auth(
    password=Password(CryptContext(schemes=['bcrypt'], deprecated='auto')),
    token=Token(secret=settings.app.SECRET_KEY, config=settings.token, coder=TokenCoder(encode=jwt.encode, decode=jwt.decode, error=JWTError))
)

def get_auth_dep() -> Auth:
    return auth

AuthDep = Annotated[Auth, Depends(get_auth_dep)]
