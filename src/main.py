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
import time
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
import pytz


load_dotenv()
msk_timezone = pytz.timezone('Europe/Moscow')

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
    region_name=REGION_NAME,
)


s3_client = session.client(
    service_name="s3",
    endpoint_url=ENDPOINT_URL,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


VERSION_TIME_THRESHOLD = 60
def create_versioned_filename(filename: str, current_user: str) -> str:
    """
    Создает имя для версии файла, добавляя метку времени.
    """
    cur_user=current_user["username"]
    cur_role=current_user["role"]
    timestamp = datetime.now()
    return f"{filename.split('.')[0]}/{filename.split('.')[0]}_{timestamp} by {cur_user}_{cur_role}.xlsx"

def should_create_new_version(last_modified_time: int) -> bool:
    """
    Проверяет, прошло ли более 5 минут с последнего изменения для создания новой версии.
    """

    current_time = int(time.time())
    return current_time - last_modified_time > VERSION_TIME_THRESHOLD


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
        return {"username": username, "role": role}
    except:
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
            if sid != skip_sid:
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
connected_users = {}
@sio.event
async def connect(sid, environ, auth):
    print(f"Client {sid} connected")
    auth_header = auth.get("token")
    if auth_header:
        token = auth_header.split(" ")[1] if auth_header.startswith("Bearer ") else None

        if token:
            try:
                user = get_current_user(token)
                connected_users[sid] = user
            except HTTPException as e:
                print(f"Authorization failed: {e.detail}")
                await sio.disconnect(sid)
                return
        else:
            print("No Bearer token provided")
            await sio.disconnect(sid)
            return
    else:
        print("Authorization header not found")
        await sio.disconnect(sid)
        return
@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")
    if sid in active_connections:
        del active_connections[sid]
        del connected_users[sid]

def get_file_from_storage(filename):
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=filename)
        file_content = response['Body'].read()
        return file_content
    except Exception as e:
        print(f"Ошибка при получении файла из S3: {e}")
        return None

@sio.event
async def get_file(sid, data):
    filename = data.get('filename')
    active_connections[sid] = filename
    if filename is None:
        print(f"Ошибка: Имя файла не передано или оно пустое.")
        await sio.emit('file_update', {'data': None}, room=sid)
        return

    print(f"Получен запрос на файл: {filename}")

    try:
        file_content = get_file_from_storage(filename)

        if file_content is None:
            print(f"Ошибка: Файл {filename} не найден.")
            await sio.emit('file_update', {'data': None}, room=sid)
        else:
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
    await send_updated_file_to_all_clients(filename, skip_sid=sid)


@sio.event
async def upload_file(sid, data):

    file_data = base64.b64decode(data['data'])
    filename = data['filename']

    save_file_to_s3(file_data, filename, sid)

    await send_updated_file_to_all_clients(filename, skip_sid=sid)

@app.get("/", summary="Проверка состояния сервера", response_description="Проверка состояния сервера")
async def read_root():
    return {"status": "alive"}
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
        return payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/me", response_model=EmployeeResponse, summary="Получить данные о текущем пользователе", description="Этот эндпоинт возвращает данные о пользователе на основе переданного JWT токена.", tags=["Users"])
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

@app.get("/users/{user_id}", response_model=UserResponse, summary="Получить пользователя. Нужна роль ADMIN", tags=["Users"])
def read_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user["role"]=="ADMIN":
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
    else:
        raise HTTPException(status_code=402, detail="Wrong role")

@app.post("/users/", response_model=UserResponse, summary="Создать нового пользователя. Нужна роль ADMIN", tags=["Users"])
def create_user(user: UserCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user["role"]=="ADMIN":
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
    else:
        raise HTTPException(status_code=402, detail="Wrong role")

@app.put("/users/{user_id}", response_model=UserResponse, summary="Обновить пользователя. Нужна роль ADMIN", tags=["Users"])
def update_user(user_id: int, user: UserCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user["role"]=="ADMIN":
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
    else:
        raise HTTPException(status_code=402, detail="Wrong role")

@app.delete("/users/{user_id}", response_model=UserResponse, summary="Удалить пользователя. Нужна роль ADMIN", tags=["Users"])
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user["role"]=="ADMIN":
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
    else:
        raise HTTPException(status_code=402, detail="Wrong role")

@app.delete("/excel/backup_files", summary="Удалить ПАПКУ бэкапа по пути. Нужна роль ADMIN", tags=["Excel"])
async def delete_backup(folder_path: str, current_user: str = Depends(get_current_user)):
    if current_user["role"] == "ADMIN":
        """
        Удаляет все файлы в указанной папке (бэкапе).
        """
        try:
            response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=folder_path)
            if 'Contents' not in response:
                raise HTTPException(status_code=404, detail="Папка не найдена или пуста")
            for obj in response['Contents']:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=obj['Key'])

            return {"message": f"Бэкап '{folder_path}' успешно удален."}

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка при удалении бэкапа: {e}")
    else:
        raise HTTPException(status_code=403, detail="Недостаточно прав для удаления бэкапа")

@app.get("/excel/backup_files", summary="Получить бэкапы файлов. Нужна роль ADMIN", tags=["Excel"])
async def list_files(current_user: str = Depends(get_current_user)):
    if current_user["role"] == "ADMIN":
        """
        Возвращает папки для всех бэкапов и все файлы, находящиеся в них.
        """
        try:
            response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
            backup_folders = {}

            for obj in response.get('Contents', []):
                if "/" not in obj['Key']:
                    continue

                folder_name = obj['Key'].split('/')[0]
                if folder_name not in backup_folders:
                    backup_folders[folder_name] = []
                last_modified_utc = obj['LastModified']
                last_modified_msk = last_modified_utc.astimezone(msk_timezone)
                file_url = s3_client.generate_presigned_url('get_object',
                                                           Params={'Bucket': BUCKET_NAME, 'Key': obj['Key']},
                                                           ExpiresIn=3600)
                backup_folders[folder_name].append({
                    "name": obj["Key"],
                    "last_modified": last_modified_msk.strftime("%Y-%m-%d %H:%M:%S"),
                    "size": obj["Size"],
                    "download_link": file_url
                })

            return {"backup_folders": [{"folder_name": folder, "files": files} for folder, files in backup_folders.items()]}

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка при получении списка файлов: {e}")
    else:
        raise HTTPException(status_code=402, detail="Wrong role")



@app.get("/excel/files", summary="Получить список всех файлов", tags=["Excel"])
async def list_files(current_user: str = Depends(get_current_user)):
    """
    Возвращает список всех файлов в хранилище с ссылкой на скачивание, исключая файлы из папок.
    """
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        files = []
        for obj in response.get('Contents', []):
            if "/" in obj['Key']:
                continue
            last_modified_utc = obj['LastModified']
            last_modified_msk = last_modified_utc.astimezone(msk_timezone)
            file_url = s3_client.generate_presigned_url('get_object',
                                                       Params={'Bucket': BUCKET_NAME, 'Key': obj['Key']},
                                                       ExpiresIn=3600)

            files.append({
                "name": obj["Key"],
                "last_modified": last_modified_msk.strftime("%Y-%m-%d %H:%M:%S"),
                "size": obj["Size"],
                "download_link": file_url
            })
        return {"files": files}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при получении списка файлов: {e}")

class RenameFileRequest(BaseModel):
    old_key: str
    new_key: str

def rename_s3_object(old_key: str, new_key: str):
    try:

        s3_client.copy_object(
            Bucket=BUCKET_NAME,
            CopySource={'Bucket': BUCKET_NAME, 'Key': old_key},
            Key=new_key
        )


        s3_client.delete_object(Bucket=BUCKET_NAME, Key=old_key)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при переименовании файла: {e}")

@app.post("/excel/rename_file", summary="Переименовать файл", tags=["Excel"])
async def rename_file(request: RenameFileRequest, current_user: str = Depends(get_current_user)):
    """
    Переименовывает файл в S3 хранилище.

    - **old_key**: старое имя файла в S3
    - **new_key**: новое имя файла в S3

    Ожидается, что файл существует в S3. После успешного выполнения старое имя файла будет удалено.
    Если файла не существует - 500
    """
    rename_s3_object(request.old_key, request.new_key)
    return {"message": f"Файл переименован с {request.old_key} на {request.new_key}"}



@app.delete("/excel/delete/{filename}", summary="Удалить файл по названию", tags=["Excel"])
async def delete_file(filename: str, current_user: str = Depends(get_current_user)):
    """
    Удаляет файл по названию из хранилища.
    """
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=filename)
        if 'Contents' not in response:
            raise HTTPException(status_code=404, detail=f"Файл {filename} не найден.")
        else:
            versioned_filename = create_versioned_filename(filename, current_user)
            s3_client.copy_object(
                Bucket=BUCKET_NAME,
                CopySource={'Bucket': BUCKET_NAME, 'Key': filename},
                Key=versioned_filename
            )
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)

        return {"message": f"Файл был удален."}
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
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=filename)
        if 'Contents' in response:
            raise HTTPException(status_code=400, detail="Файл с таким именем уже существует.")

        df = pd.DataFrame()
        file_path = f"{filename}.xlsx"
        df.to_excel(file_path, index=False)

        s3_client.upload_file(file_path, BUCKET_NAME, filename)
        os.remove(file_path)
        return {"message": f"Файл {filename} успешно создан и загружен в хранилище."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при создании файла: {e}")

@app.post("/excel/upload", summary="Загрузить файл в хранилище", tags=["Excel"])
async def upload_file(file: UploadFile, current_user: str = Depends(get_current_user)):
    """
    Загрузка файла в хранилище с учетом версионности.
    """
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=file.filename)
        if 'Contents' in response:
            file_metadata = response['Contents'][0]
            last_modified = file_metadata['LastModified'].timestamp()

            if should_create_new_version(last_modified):
                versioned_filename = create_versioned_filename(file.filename, current_user)
                s3_client.copy_object(
                    Bucket=BUCKET_NAME,
                    CopySource={'Bucket': BUCKET_NAME, 'Key': file.filename},
                    Key=versioned_filename
                )
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=file.filename)
                s3_client.put_object(Bucket=BUCKET_NAME, Key=file.filename, Body=await file.read())
                return {"message": f"Файл {file.filename} загружен как новая версия."}
            else:
                s3_client.put_object(Bucket=BUCKET_NAME, Key=file.filename, Body=await file.read())
                return {"message": f"Файл {file.filename} успешно обновлен."}
        else:
            s3_client.put_object(Bucket=BUCKET_NAME, Key=file.filename, Body=await file.read())
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

def save_file_to_s3(file_content, filename, sid):
    try:
        user= connected_users[sid]
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=filename)
        if 'Contents' in response:
            file_metadata = response['Contents'][0]
            last_modified = file_metadata['LastModified'].timestamp()
            if should_create_new_version(last_modified):
                versioned_filename = create_versioned_filename(filename, user)
                s3_client.copy_object(
                    Bucket=BUCKET_NAME,
                    CopySource={'Bucket': BUCKET_NAME, 'Key': filename},
                    Key=versioned_filename
                )
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
                s3_client.put_object(Bucket=BUCKET_NAME, Key=filename, Body=file_content)
                return {"message": f"Файл {filename} загружен как новая версия."}
            else:
                s3_client.put_object(Bucket=BUCKET_NAME, Key=filename, Body=file_content)
                return {"message": f"Файл {filename} успешно обновлен."}
        else:
            s3_client.put_object(Bucket=BUCKET_NAME, Key=filename, Body=file_content)
            print(f"Файл {filename} успешно загружен на сервер.")
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
