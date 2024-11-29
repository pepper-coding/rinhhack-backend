from fastapi import APIRouter, HTTPException
from typing import List
from models.user import User

router = APIRouter()

fake_users_db = [
    {"id": 1, "username": "user1", "email": "user1@example.com"},
    {"id": 2, "username": "user2", "email": "user2@example.com"},
]

@router.get("/", response_model=List[User], summary="Получить список пользователей", description="Получение всех пользователей из базы данных.")
async def get_users():
    """
    Получение списка всех пользователей.
    """
    return fake_users_db

@router.get("/{user_id}", response_model=User, summary="Получить профиль пользователя", description="Получение профиля пользователя по ID.")
async def get_user_profile(user_id: int):
    """
    Получение профиля пользователя по его ID.
    """
    user = next((user for user in fake_users_db if user["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
