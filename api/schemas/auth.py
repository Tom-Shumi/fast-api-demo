from pydantic import BaseModel
from typing import Optional, List

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None
    roles: List[str] = []

class User(BaseModel):
    username: str
    full_name: str | None = None
    disabled: bool = False
    roles: List[str] = []

class UserInDB(User):
    hashed_password: str
