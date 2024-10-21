from typing import Optional, List

from app.db import DBConnectionDep
from users.models import User
from sqlalchemy.orm import Session
import users.shemas as shemas



class SessionController:
    def get_user(id: int, db: Session):
        return db.query(User).filter(User.id == id).first()

    def create_user(data: shemas.User, db: Session):

        user = User(name=data.name, email=data.email, password=data.password)

        try:
            db.add(user)
            db.commit()
            db.refresh(user)
        except Exception as e:
            print(e)

        return user


class UsersController:
    base_model = User

    def get_users(self, db: DBConnectionDep) -> Optional[List[User]]:
        return db.query(self.base_model).all()

    def get_user_by_id(self, user_id: int, db: DBConnectionDep) -> User | None:
        return db.query(self.base_model).filter(self.base_model.id == user_id).first()

    def get_user_by_name(self, user_name: str, db: DBConnectionDep) -> User | None:
        return db.query(self.base_model).filter(self.base_model.name == user_name).first()


class ProfileController:
    def update(data: shemas.User, db: Session, id: int):
        user = db.query(User).filter(User.id == id).first()
        if data.name != "username": user.name = data.name
        if data.email != "user@example.com": user.email = data.email
        if data.password != "password": user.password = data.password
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def remove( db: Session, id: int):
        user = db.query(User).filter(User.id == id).delete()
        db.commit()
        return user