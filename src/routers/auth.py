from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from faker import Faker
import hashlib
from src.services.jwt import create_access_token
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


def generate_random_employee() -> Employee:
    employee = Employee(
        id=fake.uuid4(),
        firstName=fake.first_name(),
        lastName=fake.last_name(),
        email=fake.email(),
        role="ADMIN",
        position=fake.job(),
        department=fake.company()
    )
    return employee


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Функция для проверки пароля пользователя.
    Сравнивает хэш пароля, который был передан в запросе, с хэшом в базе данных.
    """
    return hashlib.sha256(plain_password.encode('utf-8')).hexdigest() == hashed_password


@router.post("/login", response_model=dict, summary="Получить JWT токен и данные сотрудника", description="Аутентификация пользователя с получением JWT токена и данных сотрудника.")
async def login(auth_request: AuthRequest, db: Session = Depends(get_db)):
    """
    Этот эндпоинт позволяет пользователю войти в систему, получить токен и данные сотрудника.
    В случае успешной аутентификации возвращается JWT токен и объект Employee с рандомными данными.
    """

    # Ищем пользователя в базе данных по имени пользователя
    user = db.query(User).filter(User.username == auth_request.username).first()

    if user and verify_password(auth_request.password, user.password_hash):
        token = create_access_token({"sub": auth_request.username})
        employee = generate_random_employee()

        return {
            "access_token": token,
            "token_type": "bearer",
            "employee": employee.dict()
        }

    raise HTTPException(status_code=401, detail="Invalid credentials")
