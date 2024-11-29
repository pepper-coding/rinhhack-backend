# src/models/schemas.py
from pydantic import BaseModel

class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    role: str
    position: str
    department: str

    class Config:
        orm_mode = True  # Это позволяет Pydantic работать с SQLAlchemy объектами
