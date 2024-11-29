from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from faker import Faker
from services.jwt import create_access_token


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

@router.post("/login", response_model=dict, summary="Получить JWT токен и данные сотрудника", description="Аутентификация пользователя с получением JWT токена и данных сотрудника.")
async def login(auth_request: AuthRequest):
    """
    Этот эндпоинт позволяет пользователю войти в систему, получить токен и данные сотрудника.
    В случае успешной аутентификации возвращается JWT токен и объект Employee с рандомными данными.
    """
    if auth_request.username == "admin" and auth_request.password == "password":
        token = create_access_token({"sub": auth_request.username})
        employee = generate_random_employee()

        return {
            "access_token": token,
            "token_type": "bearer",
            "employee": employee.dict()
        }

    raise HTTPException(status_code=401, detail="Invalid credentials")
