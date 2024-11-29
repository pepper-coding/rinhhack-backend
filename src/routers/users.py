from fastapi import APIRouter, Depends
from typing import List
from models.user import User

router = APIRouter()

fake_users_db = [
    {"id": 1, "username": "user1", "email": "user1@example.com"},
    {"id": 2, "username": "user2", "email": "user2@example.com"},
]

@router.get("/users", response_model=List[User])
async def get_users():
    return fake_users_db

@router.get("/users/{user_id}", response_model=User)
async def get_user_profile(user_id: int):
    user = next((user for user in fake_users_db if user["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
