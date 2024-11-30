from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, get_db
from src.models.user import User, UserCreate, UserResponse
from src.models.employee import EmployeeResponse
from dotenv import load_dotenv
import os
from jose import JWTError, jwt
import boto3
import random
from fastapi import UploadFile
from src.models.schemas import ExcelFile, add_history_entry
from datetime import datetime
import socketio
import uvicorn
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import StreamingResponse, HTMLResponse
from src.routers import auth, users, excel
import base64
import jwt
import io
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import pandas as pd


load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
engine = create_engine(DATABASE_URL)
s3_client = boto3.client(
    "s3",
    aws_access_key_id="AKIAEXAMPLEKEY123",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY123",
    region_name="us-west-2",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# Функция для получения текущего пользователя из токена
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username  # Возвращаем username как текущего пользователя
    except JWTError:
        raise credentials_exception


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="API для работы с пользователями и Excel",
    description="Этот API позволяет управлять пользователями, аутентификацией через JWT, работать с Excel файлами и подключаться через WebSocket.",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router, tags=["Auth"], prefix="/auth")
app.include_router(users.router, tags=["Users"], prefix="/users")
app.include_router(excel.router, tags=["Excel"], prefix="/excel")


def socketio_mount(
    app: FastAPI,
    async_mode: str = "asgi",
    mount_path: str = "/socket.io/",
    socketio_path: str = "socket.io",
    logger: bool = False,
    engineio_logger: bool = False,
    cors_allowed_origins="*",
    **kwargs,
) -> socketio.AsyncServer:
    """Mounts an async SocketIO app over an FastAPI app."""
    sio = socketio.AsyncServer(
        async_mode=async_mode,
        cors_allowed_origins=cors_allowed_origins,
        logger=logger,
        engineio_logger=engineio_logger,
        **kwargs,
    )

    sio_app = socketio.ASGIApp(sio, socketio_path=socketio_path)

    app.add_route(mount_path, route=sio_app, methods=["GET", "POST"])
    app.add_websocket_route(mount_path, sio_app)

    return sio


sio = socketio_mount(app)
WATCH_DIRECTORY = "src/"

current_file_buffer = None
active_connections = []


class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"File created: {event.src_path}")
            sio.start_background_task(
                sio.emit, "file_event", {"event": "created", "file": event.src_path}
            )

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"File deleted: {event.src_path}")
            sio.start_background_task(
                sio.emit, "file_event", {"event": "deleted", "file": event.src_path}
            )

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            sio.start_background_task(
                sio.emit, "file_event", {"event": "modified", "file": event.src_path}
            )


def start_file_watcher():
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)
    observer.start()
    try:
        while True:
            pass  # Поддерживаем процесс активным
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


threading.Thread(target=start_file_watcher, daemon=True).start()


@app.get(
    "/",
    summary="Проверка состояния сервера",
    response_description="Проверка состояния сервера",
)
async def read_root():
    return {"status": "alive"}


@sio.event
async def connect(sid, environ):
    print(f"Client {sid} connected")


@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")


@sio.event
async def get_file(sid):
    try:
        with open("src/test.xlsx", "rb") as file:
            file_content = file.read()
            encoded_content = base64.b64encode(file_content).decode("utf-8")
            await sio.emit("file_update", {"data": encoded_content}, room=sid)
    except FileNotFoundError:
        await sio.emit("error", {"message": "File not found"}, room=sid)


@sio.event
async def upload_file(sid, data):
    global current_file_buffer
    current_file_buffer = data["data"]
    file_name = data["filename"]

    # Декодируем base64 данные в байты
    file_data = base64.b64decode(current_file_buffer)

    # Создаем байтовый поток для файла
    file_stream = io.BytesIO(file_data)

    # Читаем данные Excel с помощью pandas (можно также использовать openpyxl, если нужно)
    df = pd.read_excel(file_stream)

    # Сохраняем полученные данные в новый файл Excel
    new_file_name = "modified_" + file_name
    df.to_excel(new_file_name, index=False)
    print(f"File saved as {new_file_name}")

    # Отправляем обратно клиенту
    # await sio.emit('file_update', {'data': current_file_buffer}, room=sid)


def create_db_user(db: Session, user: UserCreate):  # Хэшируем пароль
    db_user = User(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        role=user.role,
        position=user.position,
        department=user.department,
        username=user.username,
        password_hash=user.password,  # Сохраняем хэшированный пароль
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")  # Возвращаем имя пользователя из токена
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get(
    "/me",
    response_model=EmployeeResponse,
    summary="Получить данные о текущем пользователе",
    description="Этот эндпоинт возвращает данные о пользователе на основе переданного JWT токена.",
)
async def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Этот эндпоинт возвращает информацию о текущем пользователе, используя его токен.
    """
    username = decode_token(token)
    user = db.query(User).filter(User.username == username).first()

    if user:
        return EmployeeResponse(
            id=user.id,
            firstName=user.first_name,
            lastName=user.last_name,
            email=user.email,
            role=user.role,
            position=user.position,
            department=user.department,
        )

    raise HTTPException(status_code=404, detail="User not found")


@app.get("/excel/excel", summary="Получение всех таблиц", tags=["Excel"])
async def get_all_tables(current_user: str = Depends(get_current_user)):
    """
    Возвращает список всех таблиц.
    """
    return {"message": "Получение всех таблиц."}


@app.get("/excel/user", summary="История изменения", tags=["Excel"])
async def get_all_tables(current_user: str = Depends(get_current_user)):
    """
    Посмотреть историю измнения файла.
    """
    return {
        "message": "Последний измененный файл пользователем",
        "username пользователя": current_user,
        "Последний измененный файл": random.randint(0, 99),
    }


@app.post("/excel/", summary="Создание таблицы", tags=["Excel"])
async def create_table(
    request_body: dict, current_user: str = Depends(get_current_user)
):
    """
    Создает новую таблицу.
    """
    return {"message": "Создание таблицы.", "request_body": request_body}


@app.put("/excel/{table_id}", summary="Обновление таблицы", tags=["Excel"])
async def update_table(
    table_id: int, request_body: dict, current_user: str = Depends(get_current_user)
):
    """
    Обновляет таблицу по ID.
    """
    return {
        "message": f"Обновление таблицы с ID {table_id}.",
        "request_body": request_body,
    }


@app.delete("/excel/{table_id}", summary="Удаление таблицы", tags=["Excel"])
async def delete_table(table_id: int, current_user: str = Depends(get_current_user)):
    """
    Удаляет таблицу по ID.
    """
    return {"message": f"Удаление таблицы с ID {table_id}."}


@app.get(
    "/users/{user_id}", response_model=UserResponse, summary="Получить пользователя"
)
def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(
        id=db_user.id,
        firstName=db_user.first_name,
        lastName=db_user.last_name,
        username=db_user.username,
        email=db_user.email,
        role=db_user.role,
        position=db_user.position,
        department=db_user.department,
    )


@app.post("/users/", response_model=UserResponse, summary="Создать нового пользователя")
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    db_user = create_db_user(db, user=user)
    return UserResponse(
        id=db_user.id,
        firstName=db_user.first_name,
        lastName=db_user.last_name,
        username=db_user.username,
        email=db_user.email,
        role=db_user.role,
        position=db_user.position,
        department=db_user.department,
    )


@app.put(
    "/users/{user_id}", response_model=UserResponse, summary="Обновить пользователя"
)
def update_user(
    user_id: int,
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.first_name = user.first_name
    db_user.last_name = user.last_name
    db_user.email = user.email
    db_user.role = user.role
    db_user.position = user.position
    db_user.department = user.department
    db.commit()
    db.refresh(db_user)
    return UserResponse(
        id=db_user.id,
        firstName=db_user.first_name,
        lastName=db_user.last_name,
        username=db_user.username,
        email=db_user.email,
        role=db_user.role,
        position=db_user.position,
        department=db_user.department,
    )


@app.delete(
    "/users/{user_id}", response_model=UserResponse, summary="Удалить пользователя"
)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return UserResponse(
        id=db_user.id,
        firstName=db_user.first_name,
        lastName=db_user.last_name,
        username=db_user.username,
        email=db_user.email,
        role=db_user.role,
        position=db_user.position,
        department=db_user.department,
    )


@app.post("/join_room")
async def join_room(room_name: str, user_name: str):
    await sio.emit("user_joined", {"user": user_name}, room=room_name)
    return {"status": "joined", "room": room_name}


@sio.event
async def connect(sid, environ):
    print(f"Client {sid} connected")


@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")


@sio.event
async def signal(sid, data):
    target_sid = data["target"]
    message = data["message"]
    await sio.emit("signal", {"message": message, "from": sid}, to=target_sid)


@sio.event
async def user_speaking(sid, user_name):
    await sio.emit("user_speaking", user_name, broadcast=True)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
