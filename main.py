from fastapi import FastAPI, APIRouter, HTTPException
from database.schemas import all_tasks, all_users
from database.models import Todo, User
from configrations import collection, usertable
from bson.objectid import ObjectId
from datetime import datetime


app = FastAPI()
router = APIRouter()


@router.get("/")
async def get_all_todos():
    data = collection.find()
    return all_tasks(data)


@router.post("/")
async def create_task(new_task: Todo):
    try:
        response = collection.insert_one(dict(new_task))
        return {"Status code": 200, "id": str(response.inserted_id)}
    except Exception as e:

        return HTTPException(status_code=500, detail=f"The Error is: {e}")


@router.put("/{task_id}")
async def update_task(task_id: str, updated_task: Todo):
    try:
        id = ObjectId(task_id)
        existing_data = collection.find_one({"_id": id, "is_deleted": False})
        if not existing_data:
            return HTTPException(status_code=404, detail=f"Task does not exist")
        updated_task.updated_at = datetime.timestamp(datetime.now())
        response = collection.update_one(
            {"_id": id}, {"$set": dict(updated_task)})
        return {"Status code": 200, "message": "task update succesfully"}
    except Exception as e:

        return HTTPException(status_code=500, detail=f"The Error is: {e}")


@router.delete("/{task_id}")
async def delete_task(task_id: str):
    try:
        id = ObjectId(task_id)
        existing_data = collection.find_one({"_id": id, "is_deleted": False})
        if not existing_data:
            return HTTPException(status_code=404, detail=f"Task does not exist")
        response = collection.delete_one({"_id": id})
        return {"Status code": 200, "message": "task delete succesfully"}
    except Exception as e:

        return HTTPException(status_code=500, detail=f"The Error is: {e}")


@router.get("/users")
async def get_all_users():
    data = usertable.find()
    return all_users(data)


@router.post("/create_user")
async def create_user(new_task: User):
    try:
        response = usertable.insert_one(dict(new_task))
        return {"Status code": 200, "id": str(response.inserted_id)}
    except Exception as e:

        return HTTPException(status_code=500, detail=f"The Error is: {e}")


app.include_router(router)
