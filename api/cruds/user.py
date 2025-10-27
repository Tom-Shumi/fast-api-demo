from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.models.user import User
from api.schemas import auth as auth_schema
from api.config.security import get_password_hash

async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    return result.scalars().first()

async def create_user(
    db: AsyncSession,
    username: str,
    password: str,
    roles: list[str] | None = None,
    disabled: bool = False
) -> User:
    user = User(
        username=username,
        hashed_password=get_password_hash(password),
        roles=roles or [],
        disabled=disabled
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user