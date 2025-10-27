import datetime
from pydantic import BaseModel, Field, ConfigDict

class TaskBase(BaseModel):
    title: str | None = Field(
        None,
        json_schema_extra={"example": "クリーニングを取りに行く"},
    )
    due_date: datetime.date | None = Field(
        None,
        json_schema_extra={"example": "2024-12-31"},
    )

class Task(TaskBase):
    id: int
    done: bool = Field(False, description="完了フラグ")
    
    model_config = ConfigDict(from_attributes=True)

class TaskCreate(TaskBase):
    pass

class TaskCreateResponse(TaskCreate):
    id: int
    
    model_config = ConfigDict(from_attributes=True)
