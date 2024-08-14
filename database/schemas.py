# for get date from database
def individual_data(todo):
    return{
        "id" : str(todo["_id"]),
        "title" : todo["title"],
        "description" : todo["description"],
        "status" : todo["is_completed"],
        
    }
    
def all_tasks(todos):
    return [individual_data(todo) for todo in todos]    

def individual_user(user):
    return{
        "id" : str(user["_id"]),
        "name" : user["name"],
        "password" : user["password"],
        "role" : user["role"],
        
    }
    
def all_users(users):
    return [individual_user(user) for user in users]    

