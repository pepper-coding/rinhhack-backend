# app/models/file_storage.py

from sqlalchemy import Column, Integer, String, BLOB
from app.database import Base  # Импортируем Base из конфигурации базы данных

class FileStorage(Base):
    __tablename__ = 'file_storage'  # Название таблицы в базе данных

    id = Column(Integer, primary_key=True, index=True)  # Первичный ключ
    filename = Column(String, index=True)  # Имя файла
    content = Column(BLOB)  # Содержимое файла (можно использовать String, если кодировка в Base64)
