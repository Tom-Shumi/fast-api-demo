from pydantic import BaseModel, ConfigDict, SecretStr, Field
from typing import List

class UserCreate(BaseModel):
    username: str = Field(..., min_length=1)
    password: SecretStr 
    roles: List[str] = Field(default_factory=list)
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "username": "sampleuser",
            "password": "strongpassword",
            "roles": ["user", "admin"]
        }}
    )

class UserRead(BaseModel):
    id: int
    username: str
    disabled: bool = False
    roles: List[str] = []
    
    model_config = ConfigDict(from_attributes=True)