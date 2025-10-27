from sqlalchemy import create_engine

from api.models.task import Base as TaskBase
from api.models.user import Base as UserBase

DB_URL = "mysql+pymysql://root@db:3306/demo?charset=utf8mb4"
engine = create_engine(DB_URL, echo=True)

def reset_database():
    TaskBase.metadata.drop_all(engine)
    TaskBase.metadata.create_all(engine)
    UserBase.metadata.drop_all(engine)
    UserBase.metadata.create_all(engine)


if __name__ == "__main__":
    reset_database()
