# src/models/schemas.py
from pydantic import BaseModel
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    role: str
    position: str
    department: str

    class Config:
        orm_mode = True  # Это позволяет Pydantic работать с SQLAlchemy объектами
from sqlalchemy import Column, Integer, Text, TIMESTAMP, JSON
from sqlalchemy.sql import func
from src.database import Base

class ExcelFile(Base):
    __tablename__ = "excel_files"
    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(Text, nullable=False)
    file_data = Column(Text, nullable=False)
    uploaded_at = Column(TIMESTAMP, server_default=func.now())
    history = Column(JSON, default=[])

def add_history_entry(db, file_id, action, user):
    file = db.query(ExcelFile).filter(ExcelFile.id == file_id).first()
    if not file:
        raise ValueError("File not found")

    entry = {
        "action": action,
        "user": user,
        "timestamp": func.now()
    }
    file.history.append(entry)
    db.commit()
    db.refresh(file)
    return file
