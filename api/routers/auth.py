from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from api.schemas import auth
from api.config.security import (
    oauth2_schema,
    create_access_token,
    decode_token,
    verify_password,
    get_password_hash
)
from api.stores.user_store import users_db

router = APIRouter()
    
def authenticate_user(username: str, password: str) -> auth.UserInDB | None:
    user = users_db.get(username)
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

@router.post("/auth/token", response_model=auth.Token, tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(subject=user.username, roles=user.roles)
    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_schema)) -> auth.User:
    try:
        token_data = decode_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    if not token_data.sub or token_data.sub not in _users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    user_in_db = _users_db[token_data.sub]

    if user_in_db.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )
    return auth.User(**user_in_db.dict(exclude={"hashed_password"}))

@router.get("/me", response_model=auth.User, tags=["me"])
async def read_me(current_user: auth.User = Depends(get_current_user)):
    return current_user

@router.get("/health", tags=["public"])
async def health_check():
    return {"status": "ok"}

@router.get("/admin", dependencies=[Depends(require_roles(["admin"]))])
async def admin_dashboard():
    return {"status": "ok"}