from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, users, excel
import socketio

# Инициализация FastAPI
app = FastAPI()

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
app.include_router(auth.router, tags=["Auth"])
app.include_router(users.router, tags=["Users"])
app.include_router(excel.router, tags=["Excel"])

# Интеграция Socket.IO
app.mount("/ws", app_sio)
