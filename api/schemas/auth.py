from pydanic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None

class User(BaseModel):
    username: str
    full_name: str | None = None
    disabled: bool = False

class UserInDB(User):
    hashed_password: str
