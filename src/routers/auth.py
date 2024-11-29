from fastapi import APIRouter, HTTPException
from services.jwt import create_access_token
from pydantic import BaseModel

router = APIRouter()

class AuthRequest(BaseModel):
    username: str
    password: str

@router.post("/login", response_model=dict, summary="Получить JWT токен", description="Аутентификация пользователя с получением JWT токена.")
async def login(auth_request: AuthRequest):
    if auth_request.username == "admin" and auth_request.password == "password":
        token = create_access_token({"sub": auth_request.username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")
