from contextlib import asynccontextmanager
from fastapi import FastAPI

from api.routers import task, done, auth
from api.schemas import auth as auth_schema
from api.config.security import get_password_hash
from api.stores.user_store import users_db
    
def seed_user():
    users_db["admin"] = auth_schema.UserInDB(
        username="admin",
        full_name="Administrator",
        disabled=False,
        roles=["admin"],
        hashed_password=get_password_hash("password12345"),
    )
    
@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_user()
    yield
    
app = FastAPI(lifespan=lifespan)

app.include_router(task.router)
app.include_router(done.router)
app.include_router(auth.router)
