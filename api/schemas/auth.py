from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None
    roles: List[str] = []

class User(BaseModel):
    username: str
    disabled: bool = False
    roles: List[str] = []
    model_config = ConfigDict(from_attributes=True)

class UserInDB(User):
    hashed_password: str

class LoginRequest(BaseModel):
    username: str = Field(..., example="admin")
    password: str = Field(..., example="password12345")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"