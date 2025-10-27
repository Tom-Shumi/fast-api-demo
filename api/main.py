from fastapi import FastAPI

from api.routers import task, done, auth

app = FastAPI()

app.include_router(task.router)
app.include_router(done.router)
app.include_router(auth.router)
