from sqlalchemy.orm import Session
from src.database import get_db, FileData
from src.models.file_data import FileDataManager
from src.models.file import FileData # Исправлено на импорт правильного класса

def save_file_to_db(file_content: str, db: Session):
    file_data = FileData(content=file_content)  # Создаем объект
    db.add(file_data)  # Добавляем в сессию
    db.commit()  # Сохраняем в базе
