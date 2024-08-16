# # create model for pass data in database
from pydantic import BaseModel
from datetime import datetime

# class Todo(BaseModel):
#     title : str
#     description : str
#     is_completed : bool = False
#     is_deleted : bool = False
#     updated_at : int = int(datetime.timestamp(datetime.now()))
#     creation : int = int(datetime.timestamp(datetime.now()))
    
# class User(BaseModel):
#     name : str
#     description : str
#     password : str
#     updated_at : int = int(datetime.timestamp(datetime.now()))
#     creation : int = int(datetime.timestamp(datetime.now()))
    
class User(BaseModel):
    name : str
    password : str
    role : str = "user"

    
    
# from pydantic import BaseModel

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