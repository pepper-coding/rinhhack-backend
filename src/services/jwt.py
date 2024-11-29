from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Dict

# Секретный ключ и алгоритм
SECRET_KEY = "pepper-coding"
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
