# from fastapi import FastAPI, APIRouter, HTTPException
# from database.schemas import all_tasks, all_users
# from database.models import Todo, User
# from configrations import collection, usertable
# from bson.objectid import ObjectId
# from datetime import datetime
# from datetime import datetime, timedelta, timezone
# from typing import Annotated
# from fastapi import Depends, FastAPI, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel


# SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30


# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
#         "disabled": False,
#     }
# }


# class Token(BaseModel):
#     access_token: str
#     token_type: str


# class TokenData(BaseModel):
#     username: str | None = None


# class User(BaseModel):
#     username: str
#     email: str | None = None
#     full_name: str | None = None
#     disabled: bool | None = None


# class UserInDB(User):
#     hashed_password: str


# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# app = FastAPI()
# router = APIRouter()


# @router.get("/")
# async def get_all_todos():
#     data = collection.find()
#     return all_tasks(data)


# @router.post("/")
# async def create_task(new_task: Todo):
#     try:
#         response = collection.insert_one(dict(new_task))
#         return {"Status code": 200, "id": str(response.inserted_id)}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")


# @router.put("/{task_id}")
# async def update_task(task_id: str, updated_task: Todo):
#     try:
#         id = ObjectId(task_id)
#         existing_data = collection.find_one({"_id": id, "is_deleted": False})
#         if not existing_data:
#             return HTTPException(status_code=404, detail=f"Task does not exist")
#         updated_task.updated_at = datetime.timestamp(datetime.now())
#         response = collection.update_one(
#             {"_id": id}, {"$set": dict(updated_task)})
#         return {"Status code": 200, "message": "task update succesfully"}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")


# @router.delete("/{task_id}")
# async def delete_task(task_id: str):
#     try:
#         id = ObjectId(task_id)
#         existing_data = collection.find_one({"_id": id, "is_deleted": False})
#         if not existing_data:
#             return HTTPException(status_code=404, detail=f"Task does not exist")
#         response = collection.delete_one({"_id": id})
#         return {"Status code": 200, "message": "task delete succesfully"}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")


# @router.get("/users")
# async def get_all_users():
#     data = usertable.find()
#     return all_users(data)


# @router.post("/create_user")
# async def create_user(new_task: User):
#     try:
#         response = usertable.insert_one(dict(new_task))
#         return {"Status code": 200, "id": str(response.inserted_id)}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)


# def get_password_hash(password):
#     return pwd_context.hash(password)


# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)


# def authenticate_user(fake_db, username: str, password: str):
#     user = get_user(fake_db, username)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user


# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.now(timezone.utc) + expires_delta
#     else:
#         expire = datetime.now(timezone.utc) + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt


# async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except InvalidTokenError:
#         raise credentials_exception
#     user = get_user(fake_users_db, username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user


# async def get_current_active_user(
#     current_user: Annotated[User, Depends(get_current_user)],
# ):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user


# @app.post("/token")
# async def login_for_access_token(
#     form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
# ) -> Token:
#     user = authenticate_user(fake_users_db, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
#     return Token(access_token=access_token, token_type="bearer")


# @app.get("/users/me/", response_model=User)
# async def read_users_me(
#     current_user: Annotated[User, Depends(get_current_active_user)],
# ):
#     return current_user


# @app.get("/users/me/items/")
# async def read_own_items(
#     current_user: Annotated[User, Depends(get_current_active_user)],
# ):
#     return [{"item_id": "Foo", "owner": current_user.username}]


# app.include_router(router)
from pymongo import MongoClient

from datetime import datetime, timedelta, timezone
from typing import Annotated
from database.models import User
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from configrations import usertable, database
from database.schemas import all_users
from bson import ObjectId
from fastapi.middleware.cors import CORSMiddleware

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$kHjF0nYpJOblY7kqU52cF.UjyqPFlULXWD3InZWTb2sAUN6Gqbgxq",
#         "disabled": False,
#     }
# }



class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# class User(BaseModel):
#     username: str
#     email: str | None = None
#     full_name: str | None = None
#     disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# def get_user(db, username: str):
#     user
    # if username in db:
    #     user_dict = db[username]
    #     return UserInDB(**user_dict)

def get_user(username: str):
    user = usertable.find_one({"name":username}) 
    if not user:
        return None
    return user


def authenticate_user(username: str, password: str):
    # user = get_user(usertable, username)
    user = usertable.find_one({"name":username}) 
    if not user:
        return False
    if not verify_password(password, user.get("password")):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    # if current_user.disabled:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:    
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.get("name")}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.get("name")}]


@app.get("/users")
async def get_all_users(page: int = 1, limit: int = 10, current_user: User = Depends(get_current_user)):
    if current_user.get("role") == "admin":    
        data = usertable
        total_count = data.count_documents({})
        total_pages = (total_count + limit - 1) // limit
        all_data = list(data.find({}).sort(
            "_id", -1).skip((page - 1) * limit).limit(limit))
        data_list = []
        for data in all_data:
            data_list.append({
                "_id": str(data["_id"]),
                "name": data.get('name'),
                "role": data.get('role'),
                "password": data.get('password'),
            })
        return {
            "data": data_list,
            "total_pages": total_pages
        }   


@app.post("/create_user/")
async def create_user(user: User, current_user: User = Depends(get_current_user)):
    if current_user.get("role") == "admin":
        # Create the user in the database
        existing_user = usertable.find_one({"name": user.name})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
        hashed_password = get_password_hash(user.password)
        user_data = {
            "name": user.name,
            "password": hashed_password,  # Use hashed password here
            "role": user.role
        }
        print(user_data)
        response = usertable.insert_one(user_data)

        return {"status": "success", "user_id": str(response.inserted_id)}
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

# @app.put("/update_user")
# async def update_user(user: str, updated_user: User,current_user: User = Depends(get_current_user) ):
#     try:
#         existing_data = usertable.find_one({"name": user})
#         if not existing_data:
#             return HTTPException(status_code=404, detail=f"User does not exist")
#         updated_user.updated_at = datetime.timestamp(datetime.now())
#         response = usertable.update_one(
#             {"name": user}, {"$set": dict(updated_user)})
#         return {"Status code": 200, "message": "task update succesfully"}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")

@app.put("/update_user")
async def update_user(id: str, updated_user: User, current_user: User = Depends(get_current_user)):
    try:
        # Convert the id from string to ObjectId if necessary
        if current_user.get("role") == "admin":
            try:
                object_id = ObjectId(id)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid user ID format")

            # Retrieve the existing user data
            existing_data = usertable.find_one({"_id": object_id})
            if not existing_data:
                raise HTTPException(status_code=404, detail="User does not exist")

            # Prepare the update data
            update_data = {}

            # Check if the password field is updated and hash it if so
            if updated_user.password:
                hashed_password = get_password_hash(updated_user.password)
                update_data['password'] = hashed_password
            else:
                # If password is not updated, keep the existing one
                update_data['password'] = existing_data.get('password', '')

            # Check if the name field is updated
            if updated_user.name:
                update_data['name'] = updated_user.name

            # Check if the role field is updated
            if updated_user.role is not None:
                update_data['role'] = updated_user.role

            # Update the timestamp
            update_data['updated_at'] = datetime.timestamp(datetime.now())

            # Perform the update operation
            response = usertable.update_one(
                {"_id": object_id},
                {"$set": update_data}
            )

            if response.matched_count == 0:
                raise HTTPException(status_code=404, detail="User does not exist")

            return {"Status code": 200, "message": "User updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"The Error is: {e}")


    
    
# @app.delete("/delete_user")
# async def delete_task(user: str):
#     try:
        
#         existing_data = usertable.find_one({"name": user})
#         if not existing_data:
#             return HTTPException(status_code=404, detail=f"User does not exist")
#         response = usertable.delete_one({"name": user})
#         return {"Status code": 200, "message": "User delete succesfully"}
#     except Exception as e:

#         return HTTPException(status_code=500, detail=f"The Error is: {e}")    

@app.delete("/delete_user")
async def delete_user(id: str,current_user: User = Depends(get_current_user)):
    try:
        # Convert the id from string to ObjectId if necessary
        if current_user.get("role") == "admin":
            try:
                object_id = ObjectId(id)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid user ID format")

            # Retrieve the existing userdb data
            existing_data = usertable.find_one({"_id": object_id})
            if not existing_data:
                raise HTTPException(status_code=404, detail="User does not exist")

            # Perform the delete operation
            response = usertable.delete_one({"_id": object_id})

            if response.deleted_count == 0:
                raise HTTPException(status_code=404, detail="User does not exist")

            return {"Status code": 200, "message": "User deleted successfully"}
        
    except Exception as e:
            raise HTTPException(status_code=500, detail=f"The Error is: {e}")
    
    
# client = MongoClient("mongodb://localhost:27017")
# db = client["mydatabase"]
# collection = db["yellowpages"]

# @app.get("/get_data")
# async def read_item():
#     try:
#         # Convert the string ID to ObjectId
#         item_id = ObjectId("6679224d8b25b50694e2c9a8")
#         item = collection.find_one({"_id": item_id})
#         if item is None:
#             raise HTTPException(status_code=404, detail="Item not found")
#         return item
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/get_password_hash")
# def get_password_hash(password):
#     return pwd_context.hash(password)

@app.get("/scraper/yellowpages/paginate")
def get_yellowpages_paginate( page: int = 1, limit: int = 10):
    collection = database
    total_count = collection.count_documents({})
    total_pages = (total_count + limit - 1) // limit
    all_data = list(collection.find({}).sort(
        "_id", -1).skip((page - 1) * limit).limit(limit))
    data_list = []
    for data in all_data:
        data_list.append({
            "id": str(data.get('_id')),
            "name": str(data.get('Name', '')),
            "address": str(data.get('Address', '')),
            "phone": str(data.get('Phone', '')),
            "link": str(data.get('Link', '')),
            #
            "email": str(data.get('email', '')),
            "regular_hours": str(data.get('regular_hours', '')),
            "claimed": str(data.get('claimed', '')),
            "general_info": str(data.get('general_info', '')),
            "services_products": str(data.get('services_products', '')),
            "neighborhoods": str(data.get('neighborhoods', '')),
            "amenities": str(data.get('amenities', '')),
            "languages": str(data.get('languages', '')),
            "aka": str(data.get('aka', '')),
            "social_links": str(data.get('social_links', '')),
            "categories": str(data.get('categories', '')),
            "other_info": str(data.get('other_info', '')),
            "other_links": str(data.get('other_links', '')),
            #
            "status": str(data.get('status', '')),
        })
    return {
        "data": data_list,
        "total_pages": total_pages
    }


    