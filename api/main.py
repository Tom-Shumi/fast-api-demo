from contextlib import asynccontextmanager
from fastapi import FastAPI

from api.routers import task, done, auth, user
    
app = FastAPI()

app.include_router(task.router)
app.include_router(done.router)
app.include_router(auth.router)
app.include_router(user.router)