from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Security, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.db import get_db, DBConnectionDep
from app.services.auth import auth, AuthDep
from users import shemas
from users.controllers import SessionController, ProfileController, UsersController
from users.shemas import TokenLoginResponse ,User as UserDTO

security = HTTPBearer()

UsersControllerDep = Annotated[UsersController, Depends(UsersController)]
SessionControllerDep = Annotated[SessionController, Depends(SessionController)]
ProfileControllerDep = Annotated[ProfileController, Depends(ProfileController)]


user_router = APIRouter(prefix="/users", tags=["users"])
session_router = APIRouter(prefix="/sessions", tags=["sessions"])
profile_router = APIRouter(prefix="/profiles", tags=["profiles"])



@user_router.post('/', response_model=shemas.UserResponse|None)
async def sing_up(controller: SessionControllerDep, db: DBConnectionDep, bg_tasks: BackgroundTasks, request: Request, body: shemas.UserCreationModel):
    exist_user = await controller.get_user(email=body.email, db=db)
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User already exist')
    body.password = auth.password.hash(body.password)
    user = await controller.create_user(body, db)
    return user

@user_router.get('/{id}')
async def get(id: int = None, db: Session = Depends(get_db)):
    return SessionController.get_user(id, db)

@profile_router.put('/{id}')
async def update(id: int = None, data: UserDTO = None, db: Session = Depends(get_db)):
    return ProfileController.update(data, db, id)

@session_router.delete('/{id}')
async def delete(id: int = None, db: Session = Depends(get_db)):
    return ProfileController.remove(db, id)

@session_router.post('/', response_model=shemas.TokenLoginResponse)
async def login(db: DBConnectionDep, body: OAuth2PasswordRequestForm = Depends()):
    if db.query(UserDTO).filter(or_(UserDTO.email == body.username, UserDTO.username == body.username)).first():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User banned')
    result = await auth.authenticate(body, db)
    return result

@session_router.put('/', response_model=shemas.TokenLoginResponse)
async def refresh_token(db: DBConnectionDep, credentials: HTTPAuthorizationCredentials = Security(security)):
    return await auth.refresh_token(credentials.credentials, db)