from pymongo import MongoClient
from werkzeug.security import generate_password_hash

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["bus_scheduling"]
drivers_collection = db["drivers"]


hashed_password = generate_password_hash(password)

# Insert the driver
result = drivers_collection.insert_one({"username": username, "password": hashed_password, "status": "Unassigned"})

# Debugging prints
print("Driver added successfully!")
print("Inserted ID:", result.inserted_id)  # This should print the newly created document ID.
