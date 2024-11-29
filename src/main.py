from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from src.routers import auth, users, excel
import socketio
from sqlalchemy.orm import Session
from src.database import engine
from src.models import user
from src.models.employee import Employee
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from src.models import user
from src.database import Base
from src.models.user import Base, User
from src.database import SessionLocal
import hashlib

def create_user(db: Session, first_name: str, last_name: str, email: str, role: str, position: str, department: str, username: str, password: str):
    # password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # print(password_hash)
    # Создаем нового пользователя
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        role=role,
        position=position,
        department=department,
        username=username,
        password_hash=password  # Сохраняем хэш пароля
    )

    # Добавляем пользователя в базу данных
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def add_sample_users():
    db = SessionLocal()
    db.query(User).delete()  # Очистить таблицу перед добавлением
    db.commit()
    user_data_admin= {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "role": "ADMIN",
        "position": "Developer",
        "department": "IT",
        "username": "johndoe",  # Логин
        "password": "password_test"  # Пароль (он будет захеширован)
    }
    user_data_guest = {
        "first_name": "Maria",
        "last_name": "White",
        "email": "maria.white@example.com",
        "role": "USER",
        "position": "Developer",
        "department": "IT",
        "username": "mariawhite",  # Логин
        "password": "password_test"  # Пароль (он будет захеширован)
    }

    create_user(db, **user_data_admin)
    create_user(db, **user_data_guest)

Base.metadata.create_all(bind=engine)
DATABASE_URL = os.getenv("DATABASE_URL")
# Создаем движок для подключения к базе данных
engine = create_engine(DATABASE_URL)

# Создаем сессию для взаимодействия с базой данных
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Создаем все таблицы, если они еще не созданы
Base.metadata.create_all(bind=engine)
# Инициализация FastAPI с описанием для Swagger UI

add_sample_users()
app = FastAPI(
    title="API для работы с пользователями и Excel",
    description="Этот API позволяет управлять пользователями, аутентификацией через JWT и работать с Excel файлами.",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация Socket.IO
sio = socketio.AsyncServer(async_mode="asgi")
app_sio = socketio.ASGIApp(sio)

# Регистрация роутеров
app.include_router(auth.router, tags=["Auth"], prefix="/auth", responses={404: {"description": "Not found"}})
app.include_router(users.router, tags=["Users"], prefix="/users")
app.include_router(excel.router, tags=["Excel"], prefix="/excel")

@app.get("/", summary="Проверка работоспособности сервера", response_description="Проверка состояния сервера")
async def read_root():
    return {"status": "alive"}

app.mount("/ws", app_sio)
