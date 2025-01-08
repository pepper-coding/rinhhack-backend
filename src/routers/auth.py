from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from faker import Faker
import hashlib
from src.services.jwt import create_access_token, create_refresh_token
from sqlalchemy.orm import Session
from src.database import get_db  # Функция для получения сессии из базы данных
from src.models.user  import User  # Модель User для работы с базой данных

fake = Faker()

router = APIRouter()

class AuthRequest(BaseModel):
    username: str
    password: str


class Employee(BaseModel):
    id: str
    firstName: str
    lastName: str
    email: str
    role: str
    position: str
    department: str



def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Функция для проверки пароля пользователя.
    Сравнивает хэш пароля, который был передан в запросе, с хэшом в базе данных.
    """
    return hashlib.sha256(plain_password.encode('utf-8')).hexdigest() == hashed_password

@router.post("/refresh-token", response_model=dict, summary="Обновить JWT токен", description="Используйте refresh token, чтобы получить новый access token.")
async def refresh_token(refresh_token: str):
    """
    Этот эндпоинт позволяет обновить access token с использованием refresh token.
    """
    # Проверяем, что refresh token валиден
    username = verify_refresh_token(refresh_token)

    if username:
        # Генерируем новый access token
        access_token = create_access_token({"sub": username})
        return {"access_token": access_token}

    raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/login", response_model=dict, summary="Получить JWT токен и данные сотрудника", description="Аутентификация пользователя с получением JWT токена и данных сотрудника.")
async def login(auth_request: AuthRequest, db: Session = Depends(get_db)):
    """
    Этот эндпоинт позволяет пользователю войти в систему, получить токен и данные сотрудника.
    В случае успешной аутентификации возвращается JWT токен, refresh токен и данные сотрудника из базы.
    """
    # Ищем пользователя в базе данных по имени пользователя
    user = db.query(User).filter(User.username == auth_request.username).first()

    if user and verify_password(auth_request.password, user.password_hash):
        # Создание токенов
        access_token = create_access_token({"sub": auth_request.username, "role":user.role})
        refresh_token = create_refresh_token({"sub": auth_request.username, "role":user.role})

        # Возвращаем данные сотрудника из базы данных
        employee = {
            "id": user.id,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "email": user.email,
            "role": user.role,
            "position": user.position,
            "department": user.department
        }

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,  # Добавляем refresh token
            "token_type": "bearer",
            "employee": employee
        }

    raise HTTPException(status_code=401, detail="Invalid credentials")
