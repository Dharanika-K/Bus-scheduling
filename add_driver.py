from pymongo import MongoClient
from werkzeug.security import generate_password_hash


client = MongoClient("mongodb://localhost:27017/")
db = client["bus_scheduling"]
drivers_collection = db["drivers"]


hashed_password = generate_password_hash(password)


result = drivers_collection.insert_one({"username": username, "password": hashed_password, "status": "Unassigned"})


print("Driver added successfully!")
print("Inserted ID:", result.inserted_id) 
