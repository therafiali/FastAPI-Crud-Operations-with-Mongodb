from pymongo import MongoClient

MONGO_PORT = 27017
MONGO_DB = "mydatabase"
MONGO_HOST = "mongodb://localhost"

# Create a MongoDB client
client = MongoClient(MONGO_HOST, MONGO_PORT)
db = client[MONGO_DB]
collection = db["todo_data"]
usertable = db["user_data"]