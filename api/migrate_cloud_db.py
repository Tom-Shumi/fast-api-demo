from sqlalchemy.ext import InternalError, OperationalError
from sqlalchemy import create_engine

from api.models.task import Base as TaskBase
from api.models.user import Base as UserBase
from api.db import DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

DB_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}?charset=utf8mb4"
DEMO_DB_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/demo?charset=utf8mb4"

engine = create_engine(DEMO_DB_URL, echo=True)

def database_exists():
    try:
        engine.connect()
        return True
    except (InternalError, OperationalError) as e:
        print(f"Database connection error: {e}")
        return False

def create_database():
    if not database_exists():
        root = create_engine(DB_URL, echo=True)
        with root.connect() as conn:
            conn.execute("CREATE DATABASE demo CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;")
        print("Database 'demo' created.")
        TaskBase.metadata.create_all(engine)
        UserBase.metadata.create_all(engine)

if __name__ == "__main__":
    create_database()
