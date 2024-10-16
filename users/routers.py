from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db

from users.controllers import SessionController, ProfileController
from users.shemas import User as UserDTO

router = APIRouter(prefix="/users", tags=["users"])

@router.post('/')
async def create_user(data: UserDTO = None, db: Session = Depends(get_db)):
    return SessionController.create_user(data, db)

@router.get('/{id}')
async def get(id: int = None, db: Session = Depends(get_db)):
    return SessionController.get_user(id, db)

@router.put('/{id}')
async def update(id: int = None, data: UserDTO = None, db: Session = Depends(get_db)):
    return ProfileController.update(data, db, id)

@router.delete('/{id}')
async def delete(id: int = None, db: Session = Depends(get_db)):
    return ProfileController.remove(db, id)