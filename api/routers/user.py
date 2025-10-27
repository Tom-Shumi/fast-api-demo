from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db
from api.schemas.user import UserCreate, UserRead
from api.cruds.user import create_user as create_user_crud, get_user_by_username

router = APIRouter()

@router.post("/users", response_model=UserRead)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await get_user_by_username(db, user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    db_user = await create_user_crud(
        db,
        username=user.username,
        password=user.password.get_secret_value(),
        roles=user.roles,
        disabled=False
    )
    
    return UserRead.model_validate(db_user, from_attributes=True)
