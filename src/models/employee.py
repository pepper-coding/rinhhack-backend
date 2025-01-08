from pydantic import BaseModel

class EmployeeResponse(BaseModel):
    id: int
    firstName: str
    lastName: str
    email: str
    role: str
    position: str
    department: str

    class Config:
        orm_mode = True  # Это нужно, чтобы FastAPI мог автоматически преобразовывать SQLAlchemy модели в Pydantic модели
