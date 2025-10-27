from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean, Integer, JSON
from api.db import Base

class User(Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
