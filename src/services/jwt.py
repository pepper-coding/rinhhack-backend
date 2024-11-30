from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Dict
from dotenv import load_dotenv
import os
load_dotenv(dotenv_path='E:/Rinh Hackathon/src/.env')

# Подключение к базе данных

SECRET_KEY = os.getenv("SECRET_KEY")
# Секретный ключ и алгоритм
ALGORITHM = "HS256"

# Функция для создания access token
def create_access_token(data: Dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Функция для создания refresh token
def create_refresh_token(data: Dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
