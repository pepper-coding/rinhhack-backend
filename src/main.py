from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, users, excel
import socketio

# Инициализация FastAPI с описанием для Swagger UI
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

# Интеграция Socket.IO
app.mount("/ws", app_sio)
