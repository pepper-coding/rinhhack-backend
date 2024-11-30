import hashlib
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates
from pydantic import BaseModel, Field
from pydantic.alias_generators import to_camel
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    role = Column(String)
    position = Column(String)
    department = Column(String)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)

    @validates('password_hash')
    def hash_password(self, key, password):
        """Хеширование пароля с использованием SHA-256 перед сохранением в базу"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


class UserCreate(BaseModel):
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")
    email: str
    role: str
    position: str
    department: str
    username: str
    password: str

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class UserResponse(BaseModel):
    id: int
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")
    email: str
    role: str
    position: str
    department: str
    username: str

    class Config:
        orm_mode = True  # это позволяет Pydantic работать с SQLAlchemy объектами
        from_attributes = True
