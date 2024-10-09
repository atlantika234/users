from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db import get_db

import services
from shemas import User as UserDTO

router = APIRouter()

@router.post('/', tags=['user'])
async def create_user(data: UserDTO = None, db: Session = Depends(get_db)):
    return services.create_user(data, db)

@router.get('/{id}', tags=['user'])
async def get(id: int = None, db: Session = Depends(get_db)):
    return services.get_user(id, db)

@router.put('/{id}', tags=['user'])
async def update(id: int = None, data: UserDTO = None, db: Session = Depends(get_db)):
    return services.update(data, db, id)

@router.delete('/{id}', tags=['user'])
async def delete(id: int = None, db: Session = Depends(get_db)):
    return services.remove(db, id)