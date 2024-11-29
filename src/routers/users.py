# src/routers/users.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.models.user import User  # SQLAlchemy модель
from src.models.schemas import UserBase  # Pydantic модель
from src.database import SessionLocal  # предполагается, что у вас есть функция для получения сессии БД

router = APIRouter()

# Функция для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/users", response_model=list[UserBase])  # Используем Pydantic модель
async def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users
