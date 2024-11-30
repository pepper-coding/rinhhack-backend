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

from fastapi import UploadFile
from src.models.schemas import ExcelFile, add_history_entry
from datetime import datetime
import socketio
import uvicorn
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import StreamingResponse
from src.routers import auth, users, excel
import base64
import jwt
import io


load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
engine = create_engine(DATABASE_URL)

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
    version="1.0.0"
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
    **kwargs
) -> socketio.AsyncServer:
    """Mounts an async SocketIO app over an FastAPI app."""
    sio = socketio.AsyncServer(
        async_mode=async_mode,
        cors_allowed_origins=cors_allowed_origins,
        logger=logger,
        engineio_logger=engineio_logger,
        **kwargs
    )

    sio_app = socketio.ASGIApp(sio, socketio_path=socketio_path)

    app.add_route(mount_path, route=sio_app, methods=["GET", "POST"])
    app.add_websocket_route(mount_path, sio_app)

    return sio


sio = socketio_mount(app)


current_file_buffer = None
active_connections = []

@app.get("/", summary="Проверка состояния сервера", response_description="Проверка состояния сервера")
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
        with open("src//test.xlsx", "rb") as file:
            file_content = file.read()
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            await sio.emit('file_update', {'data': encoded_content}, room=sid)
    except FileNotFoundError:
        await sio.emit('error', {'message': 'File not found'}, room=sid)


@sio.event
async def file_update(sid, data):
    global current_file_buffer
    current_file_buffer = data['data']
    await sio.emit('file_update', {'data': current_file_buffer}, room=sid)


def create_db_user(db: Session, user: UserCreate):
    db_user = User(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        role=user.role,
        position=user.position,
        department=user.department,
        username=user.username,
        password_hash=user.password,
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

@app.get("/me", response_model=EmployeeResponse, summary="Получить данные о текущем пользователе", description="Этот эндпоинт возвращает данные о пользователе на основе переданного JWT токена.")
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
            department=user.department
        )

    raise HTTPException(status_code=404, detail="User not found")

@app.get("/excel/{file_id}/history/")
def get_file_history(file_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    file = db.query(ExcelFile).filter(ExcelFile.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    return file.history

@app.delete("/excel/delete/{table_name}")
async def delete_excel_table(table_name: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Ищем таблицу в базе данных
    table = db.query(ExcelFile).filter(ExcelFile.file_name == table_name).first()
    if not table:
        return {"error": "Table not found"}

    # Удаляем таблицу
    db.delete(table)
    db.commit()
    return {"message": f"Table '{table_name}' has been successfully deleted."}


@app.post("/excel/upload/")
async def upload_excel(file: UploadFile, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    content = await file.read()
    base64_data = base64.b64encode(content).decode("utf-8")

    new_file = ExcelFile(file_name=file.filename, file_data=base64_data, history=[{
        "action": "created",
        "user": current_user,
        "timestamp": datetime.now().isoformat()
    }])

    db.add(new_file)
    db.commit()
    db.refresh(new_file)
    return {"message": "File uploaded successfully", "file_id": new_file.id}

@app.get("/excel/download/{table_name}")
async def download_excel(table_name: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Ищем таблицу в базе данных
    table = db.query(ExcelFile).filter(ExcelFile.file_name == table_name).first()
    if not table:
        return {"error": "Table not found"}

    # Декодируем содержимое таблицы из base64
    file_content = base64.b64decode(table.file_data)
    file_stream = io.BytesIO(file_content)

    # Возвращаем файл как ответ
    response = StreamingResponse(file_stream, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response.headers["Content-Disposition"] = f"attachment; filename={table_name}.xlsx"
    return response

@app.get("/users/{user_id}", response_model=UserResponse, summary="Получить пользователя")
def read_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@app.post("/users/", response_model=UserResponse, summary="Создать нового пользователя")
def create_user(user: UserCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    db_user = create_db_user(db, user=user)
    return db_user

@app.put("/users/{user_id}", response_model=UserResponse, summary="Обновить пользователя")
def update_user(user_id: int, user: UserCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
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
    return db_user

@app.delete("/users/{user_id}", response_model=UserResponse, summary="Удалить пользователя")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return db_user


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
