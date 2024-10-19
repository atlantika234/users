from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.services.auth import auth, AuthDep
from users.controllers import SessionController, ProfileController
from users.shemas import User as UserDTO

user_router = APIRouter(prefix="/users", tags=["users"])
session_router = APIRouter(prefix="/sessions", tags=["sessions"])
profile_router = APIRouter(prefix="/profiles", tags=["profiles"])

@user_router.post('/')
async def sign_up(data: UserDTO = None, db: Session = Depends(get_db)):
    user = SessionController.create_user(data, db)
    access_token_data = {"email": user.email}
    access_token = await auth.token.create_access_token(data=access_token_data)

    return {
        "access_token": access_token["token"],
        "access_expired_at": access_token["expired_at"],
        "token_type": "bearer"
    }

@user_router.get('/{id}')
async def get(id: int = None, db: Session = Depends(get_db)):
    return SessionController.get_user(id, db)

@profile_router.put('/{id}')
async def update(id: int = None, data: UserDTO = None, db: Session = Depends(get_db)):
    return ProfileController.update(data, db, id)

@session_router.delete('/{id}')
async def delete(id: int = None, db: Session = Depends(get_db)):
    return ProfileController.remove(db, id)