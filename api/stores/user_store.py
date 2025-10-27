from typing import Dict
from api.schemas import auth as auth_schema

users_db: Dict[str, auth_schema.UserInDB] = {}