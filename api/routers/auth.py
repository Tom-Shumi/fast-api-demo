from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas import auth
from api.config.security import (
    oauth2_schema,
    create_access_token,
    decode_token,
    verify_password,
    get_password_hash
)
from api.db import get_db
from api.cruds.user import get_user_by_username

router = APIRouter()

async def authenticate_user(db: AsyncSession, username: str, password: str) -> auth.UserInDB | None:
    user = await get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def require_roles(allowed: list[str]):
    def _dep(current_user: auth.User = Depends(get_current_user)):
        if not any(r in allowed for r in current_user.roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return True
    return _dep

@router.post("/auth/token", response_model=auth.TokenResponse)
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    user = await get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    token = create_access_token(subject=user.username, roles=user.roles)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/auth/token-json", response_model=auth.TokenResponse, tags=["auth"])
async def login_json(body: auth.LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, body.username, body.password)
    if not user or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(subject=user.username, roles=user.roles)
    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_schema), db: AsyncSession = Depends(get_db)) -> auth.User:
    try:
        token_data = decode_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    if not token_data.sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    user = await get_user_by_username(db, token_data.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )
    return auth.User.model_validate(user, from_attributes=True)

@router.get("/me", response_model=auth.User, tags=["me"])
async def read_me(current_user: auth.User = Depends(get_current_user)):
    return current_user

@router.get("/health", tags=["public"])
async def health_check():
    return {"status": "ok"}

@router.get("/admin", dependencies=[Depends(require_roles(["admin"]))])
async def admin_dashboard():
    return {"status": "ok"}
