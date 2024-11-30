from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
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
from pydantic import BaseModel
import boto3
import random
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
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import pandas as pd
import asyncio


load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION_NAME = os.getenv("REGION_NAME")
ENDPOINT_URL = os.getenv("ENDPOINT_URL")
BUCKET_NAME = os.getenv("BUCKET_NAME")
engine = create_engine(DATABASE_URL)
session = boto3.session.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION_NAME,  # Область для Yandex Cloud
)

# Инициализируем клиент для работы с S3 в Yandex Cloud
s3_client = session.client(
    service_name="s3",
    endpoint_url=ENDPOINT_URL,  # URL для Yandex Cloud S3
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
WATCH_FILE  = "src/test.xlsx"
clients_editing = set()
current_file_buffer = None
active_connections = {}

def read_file(file_path):
    with open(file_path, "rb") as file:
        file_content = file.read()
        encoded_content = base64.b64encode(file_content).decode('utf-8')
    return encoded_content


async def send_updated_file_to_all_clients(filename, skip_sid=None):
    file_content = read_file_from_s3(filename)
    if file_content:
        encoded_content = encode_file(file_content)
        for sid in active_connections:
            if sid != skip_sid:  # Пропускаем клиента, который отправил файл
                await sio.emit('file_update', {'data': encoded_content, 'filename': filename}, room=sid)



class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"Файл {event.src_path} изменен.")
        self.trigger_send_file_update(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"Файл создан: {event.src_path}")
            self.trigger_send_file_update(event.src_path)

    def trigger_send_file_update(self, file_path):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_updated_file_to_all_clients(file_path, None))

def start_file_watcher():
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, os.path.dirname(WATCH_FILE), recursive=False)
    observer.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


threading.Thread(target=start_file_watcher, daemon=True).start()

@sio.event
async def connect(sid, environ, filename):
    print(f"Client {sid} connected with file: {filename}")
    active_connections[sid] = {'file': filename}  # Сохраняем имя файла для этого клиента

    # Загружаем файл из S3
    file_content = read_file_from_s3(filename)

    if file_content:
        await sio.emit('file_update', {'data': encode_file(file_content), 'filename': filename}, room=sid)

@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")
    if sid in active_connections:
        del active_connections[sid]

def get_file_from_storage(filename):
    try:
        s3_client = boto3.client('s3')
        bucket_name = BUCKET_NAME  # Укажите имя вашего бакета
        response = s3_client.get_object(Bucket=bucket_name, Key=filename)
        file_content = response['Body'].read()  # Читаем содержимое файла
        return file_content
    except Exception as e:
        print(f"Ошибка при получении файла из S3: {e}")
        return None

@sio.event
async def get_file(sid, data):
    filename = data.get('filename')  # Получаем имя файла из данных
    if filename is None:
        print(f"Ошибка: Имя файла не передано или оно пустое.")
        await sio.emit('file_update', {'data': None}, room=sid)
        return

    print(f"Получен запрос на файл: {filename}")

    try:
        # Здесь замените на вашу логику получения файла
        file_content = await get_file_from_storage(filename)  # Получаем файл из хранилища

        if file_content is None:
            print(f"Ошибка: Файл {filename} не найден.")
            await sio.emit('file_update', {'data': None}, room=sid)
        else:
            # Кодируем файл в base64 перед отправкой
            encoded_file = base64.b64encode(file_content).decode('utf-8')
            await sio.emit('file_update', {'data': encoded_file}, room=sid)
    except Exception as e:
        print(f"Ошибка при получении файла: {e}")
        await sio.emit('file_update', {'data': None}, room=sid)

@sio.event
async def start_editing(sid, filename):
    print(f"Client {sid} started editing the file {filename}.")
    active_connections[sid] = {"file": filename, "status": "editing"}

@sio.event
async def stop_editing(sid, filename):
    print(f"Client {sid} stopped editing the file {filename}.")
    active_connections[sid] = {"file": filename, "status": None}
    # После завершения редактирования отправляем обновленный файл всем остальным
    await send_updated_file_to_all_clients(filename, skip_sid=sid)


@sio.event
async def upload_file(sid, data):
    # Декодируем файл, полученный от клиента
    file_data = base64.b64decode(data['data'])
    filename = data['filename']  # Получаем имя файла, переданное с клиентом

    # Загружаем файл в хранилище S3
    save_file_to_s3(file_data, filename)

    # После загрузки отправляем обновленный файл всем подключенным клиентам
    await send_updated_file_to_all_clients(filename, skip_sid=sid)

@app.get("/", summary="Проверка состояния сервера", response_description="Проверка состояния сервера")
async def read_root():
    return {"status": "alive"}
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

# @app.get("/excel/excel", summary="Получение всех таблиц", tags=["Excel"])
# async def get_all_tables(current_user: str = Depends(get_current_user)):
#     """
#     Возвращает список всех таблиц.
#     """
#     return {"message": "Получение всех таблиц."}
#
# @app.get("/excel/user", summary="История изменения", tags=["Excel"])
# async def get_all_tables(current_user: str = Depends(get_current_user)):
#     """
#     Посмотреть историю измнения файла.
#     """
#     return {"message": "Последний измененный файл пользователем","username пользователя" : current_user, "Последний измененный файл" : random.randint(0,99)}
#
# @app.post("/excel/", summary="Создание таблицы", tags=["Excel"])
# async def create_table(request_body: dict, current_user: str = Depends(get_current_user)):
#     """
#     Создает новую таблицу.
#     """
#     return {"message": "Создание таблицы.", "request_body": request_body}
#
# @app.put("/excel/{table_id}", summary="Обновление таблицы", tags=["Excel"])
# async def update_table(table_id: int, request_body: dict, current_user: str = Depends(get_current_user)):
#     """
#     Обновляет таблицу по ID.
#     """
#     return {"message": f"Обновление таблицы с ID {table_id}.", "request_body": request_body}
#
# @app.delete("/excel/{table_id}", summary="Удаление таблицы", tags=["Excel"])
# async def delete_table(table_id: int, current_user: str = Depends(get_current_user)):
#     """
#     Удаляет таблицу по ID.
#     """
#     return {"message": f"Удаление таблицы с ID {table_id}."}

@app.get("/users/{user_id}", response_model=UserResponse, summary="Получить пользователя")
def read_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
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
def create_user(user: UserCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
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

@app.delete("/users/{user_id}", response_model=UserResponse, summary="Удалить пользователя")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
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


@app.get("/excel/files", summary="Получить список всех файлов", tags=["Excel"])
async def list_files(current_user: str = Depends(get_current_user)):
    """
    Возвращает список всех файлов в хранилище.
    """
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)  # Укажи имя своего бакета
        files = []
        for obj in response.get('Contents', []):
            files.append({
                "name": obj["Key"],
                "last_modified": obj["LastModified"].strftime("%Y-%m-%d %H:%M:%S"),
                "size": obj["Size"]
            })
        return {"files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при получении списка файлов: {e}")

@app.delete("/excel/delete/{filename}", summary="Удалить файл по названию", tags=["Excel"])
async def delete_file(filename: str, current_user: str = Depends(get_current_user)):
    """
    Удаляет файл по названию из хранилища.
    """
    try:
        s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
        return {"message": f"Файл {filename} успешно удален."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении файла: {e}")

class FileCreateRequest(BaseModel):
    filename: str

@app.post("/excel/create", summary="Создать пустой файл Excel", tags=["Excel"])
async def create_excel_file(file_request: FileCreateRequest, current_user: str = Depends(get_current_user)):
    """
    Создает пустой файл Excel, если файл с таким именем еще не существует.
    """
    try:
        filename = file_request.filename
        # Проверка, существует ли файл
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=filename)
        if 'Contents' in response:
            raise HTTPException(status_code=400, detail="Файл с таким именем уже существует.")

        # Создаем новый пустой файл Excel
        df = pd.DataFrame()  # Пустой DataFrame
        file_path = f"{filename}.xlsx"
        df.to_excel(file_path, index=False)

        # Загружаем файл в S3
        s3_client.upload_file(file_path, BUCKET_NAME, filename)
        os.remove(file_path)
        return {"message": f"Файл {filename} успешно создан и загружен в хранилище."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при создании файла: {e}")

@app.post("/excel/upload", summary="Загрузить файл в хранилище", tags=["Excel"])
async def upload_file(file: UploadFile, current_user: str = Depends(get_current_user)):
    """
    Загрузка файла в хранилище.
    """
    try:
        file_content = await file.read()  # Чтение содержимого файла
        s3_client.put_object(Bucket=BUCKET_NAME, Key=file.filename, Body=file_content)
        return {"message": f"Файл {file.filename} успешно загружен."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при загрузке файла: {e}")

def read_file_from_s3(filename):
    try:
        file_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=filename)
        file_content = file_obj['Body'].read()
        return file_content
    except Exception as e:
        print(f"Ошибка при загрузке файла: {e}")
        return None

def encode_file(file_content):
    return base64.b64encode(file_content).decode('utf-8')

def save_file_to_s3(file_content, filename):
    try:
        s3_client.put_object(Bucket=BUCKET_NAME, Key=filename, Body=file_content)
        print(f"Файл {filename} успешно загружен на сервер.")
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")


@app.get("/excel/file/{filename}", summary="Получить файл по имени", tags=["Excel"])
async def get_excel_file(filename: str, websocket: WebSocket):
    """Получить файл по имени и отправить его через WebSocket."""
    try:
        # Проверяем, существует ли файл в хранилище (Yandex S3)
        file_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=filename)
        file_content = file_obj['Body'].read()

        # Кодируем файл в base64
        encoded_content = base64.b64encode(file_content).decode('utf-8')

        # Отправляем файл через сокет
        await websocket.send_json({'filename': filename, 'data': encoded_content})

        return {"message": f"Файл {filename} отправлен на сокет."}

    except Exception as e:
        raise HTTPException(status_code=404, detail="File not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
