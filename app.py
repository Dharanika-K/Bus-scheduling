from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId  # To handle MongoDB ObjectIds

app = Flask(__name__, template_folder="templates", static_folder="static")

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")  # Connect to local MongoDB
db = client["bus_scheduling"]  # Database Name
drivers_collection = db["drivers"]  # Collection Name

app.config["TEMPLATES_AUTO_RELOAD"] = True  # Auto-reload templates

# Home Route - Redirects to Scheduling Page
@app.route('/')
def home():
    return redirect(url_for('schedule'))

# Route to show all assigned drivers
@app.route('/scheduling')
def schedule():
    drivers = list(drivers_collection.find())  # Retrieve all drivers
    return render_template('scheduling.html', drivers=drivers)

# Route to show the confirm unassign page
@app.route('/confirm')
def confirm_page():
    return render_template('unscheduling2.html')

# Route to handle unassigning a driver
@app.route('/unassign/<driver_id>')
def unassign_driver(driver_id):
    drivers_collection.update_one({"_id": ObjectId(driver_id)}, {"$set": {"status": "Unassigned"}})
    return redirect(url_for('unassigned_page'))

# Route to show unassigned drivers
@app.route('/unassigned')
def unassigned_page():
    unassigned_drivers = list(drivers_collection.find({"status": "Unassigned"}))
    return render_template('unassigned.html', drivers=unassigned_drivers)

# Route to add a new driver
@app.route('/add_driver', methods=["POST"])
def add_driver():
    if request.method == "POST":
        driver_data = {
            "name": request.form["name"],
            "route": request.form["route"],
            "status": "Assigned"  # Default status
        }
        drivers_collection.insert_one(driver_data)  # Insert into MongoDB
        return redirect(url_for('schedule'))

# Route to delete a driver
@app.route('/delete_driver/<driver_id>')
def delete_driver(driver_id):
    drivers_collection.delete_one({"_id": ObjectId(driver_id)})  # Delete from MongoDB
    return redirect(url_for('schedule'))

# Additional Pages
@app.route('/scheduling2')
def shift_page():
    return render_template('scheduling2.html')

@app.route('/unscheduling')
def unscheduling_page():
    return render_template('unscheduling.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/landing')
def landing_page():
    return render_template('landing.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/signin')
def signin_page():
    return render_template('signin.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
