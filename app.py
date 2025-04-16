from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message  
import re

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "djmadl2025buschedule"  # Required for session management
app.secret_key = 'dharanijoemisiadl'


# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["bus_scheduling"]
drivers_collection = db["drivers"]
assignments_collection = db["assignments"]
collection = db["driver"]
schedules_collection = db["schedules"]


# Configure Flask-Mail for Email Notifications
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '23z317@psgtech.ac.in' 
app.config['MAIL_PASSWORD'] = 'dd.060608'  
app.config['MAIL_DEFAULT_SENDER'] = '23z317@psgtech.ac.in'

mail = Mail(app)

@app.route('/')
def home():
    return redirect(url_for('landing_page'))

@app.route('/schedule')
def schedule():
    drivers = list(drivers_collection.find())
    for driver in drivers:
        driver['_id'] = str(driver['_id'])
    return render_template('scheduling.html', drivers=drivers)

@app.route('/unassigned')
def unassigned_page():
    unassigned_drivers = list(drivers_collection.find({"status": "Unassigned"}))
    for driver in unassigned_drivers:
        driver['_id'] = str(driver['_id'])
    return render_template('unassigned.html', drivers=unassigned_drivers)

@app.route('/assign_driver', methods=['POST'])
def assign_driver():
    driver_id = request.form.get('driver_id')
    shift_time = request.form.get('shift_time')
    bus_route = request.form.get('bus_route')
    date = request.form.get('date')

    if not driver_id:
        return "Driver ID is missing", 400

    # Get driver details including username and password
    driver = drivers_collection.find_one({"_id": ObjectId(driver_id)})

    if not driver:
        return "Driver not found", 404

    # Mark as Assigned
    drivers_collection.update_one({"_id": ObjectId(driver_id)}, {"$set": {"status": "Assigned"}})

    # Include username and password in assignment record
    assignment = {
        "driver_id": ObjectId(driver_id),
        "name": driver.get("name"),
        "username": driver.get("username"),
        "password": driver.get("password"),  # It's hashed
        "shift_time": shift_time,
        "bus_route": bus_route,
        "date": date
    }

    assignments_collection.insert_one(assignment)

    return redirect(url_for('schedule'))


@app.route('/unassign_driver/<driver_id>', methods=['POST'])
def unassign_driver(driver_id):
    drivers_collection.update_one({"_id": ObjectId(driver_id)}, {"$set": {"status": "Unassigned"}})
    return redirect(url_for('unassigned_page'))

@app.route('/add_driver', methods=['GET', 'POST'])
def add_driver():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if name and username and password and email:
            hashed_password = generate_password_hash(password)
            new_driver = {"name": name, "username": username, "password": hashed_password, "email": email, "status": "Unassigned"}
            drivers_collection.insert_one(new_driver)
            return redirect(url_for('schedule'))
    return render_template('add_driver.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = drivers_collection.find_one({"username": username})
        
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['failed_attempts'] = 0  # Reset failed attempts
            return redirect(url_for('dashboard_page'))

        session['failed_attempts'] = session.get('failed_attempts', 0) + 1
        if session['failed_attempts'] >= 3:
            flash("Too many failed attempts! An email has been sent to your registered email.")
            send_security_alert(username)
        else:
            flash("Wrong username or password. Please try again.")
    return render_template('login.html')

@app.route('/driver/profile', methods=['GET', 'POST'])
def driver_profile():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    username = session['username']
    driver = drivers_collection.find_one({'username': username})

    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')

        if not re.match(r'^\S+@\S+\.\S+$', email):
            flash("Invalid email format")
        elif not re.match(r'^\d{10}$', phone):
            flash("Invalid phone number format (should be 10 digits)")
        else:
            drivers_collection.update_one(
                {'username': username},
                {'$set': {'email': email, 'phone': phone}}
            )
            flash("Profile updated successfully!")
            return redirect(url_for('driver_profile'))

    return render_template('driver_profile.html', driver=driver)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login_page'))


@app.route('/dashboard')
def dashboard_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')

@app.route('/shift_page')
def shift_page():
    available_drivers = list(drivers_collection.find({"status": "Unassigned"}))
    routes = ["Route A", "Route B", "Route C"]
    return render_template("shift.html", drivers=available_drivers, routes=routes)

@app.route('/unscheduling')
def unscheduling_page():
    assigned_drivers = list(assignments_collection.find({}))

    for driver in assigned_drivers:
        driver_data = drivers_collection.find_one({"_id": driver["driver_id"]})
        if driver_data:
            driver["driver_name"] = driver_data.get("name", "Unknown")  # Ensure name is retrieved
            driver["route"] = driver_data.get("route", "Not Assigned")  # Ensure route is retrieved

    return render_template("unscheduling.html", assigned_drivers=assigned_drivers)


@app.route('/unschedule_driver/<assignment_id>', methods=['POST'])
def unschedule_driver(assignment_id):
    assignment = assignments_collection.find_one({"_id": ObjectId(assignment_id)})
    
    if assignment:
        driver_id = assignment["driver_id"]
        drivers_collection.update_one({"_id": driver_id}, {"$set": {"status": "Unassigned"}})
        assignments_collection.delete_one({"_id": ObjectId(assignment_id)})

    return redirect(url_for('unscheduling_page'))

@app.route('/unscheduling2')
def unscheduling2_page():
    assigned_drivers = list(assignments_collection.find({}))
    return render_template('unscheduling2.html', assigned_drivers=assigned_drivers)

@app.route('/landing')
def landing_page():
    return render_template('landing.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == "admin" and password == "secure123":
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("❌ Incorrect Username or Password. Please try again.", "danger")

    return render_template('admin.html')

@app.route('/signin')
def signin_page():
    return render_template('signin.html')

@app.route('/filter-search', methods=['GET', 'POST'])
def filter_search():
    results = []
    if request.method == 'POST':
        driver_name = request.form.get('driver_name')
        driver_id = request.form.get('driver_id')

        query = {}
        if driver_name:
            query['name'] = {'$regex': driver_name, '$options': 'i'}
        if driver_id:
            query['driver_id'] = {'$regex': driver_id, '$options': 'i'}

        results = list(collection.find(query))

    return render_template('report_results.html', results=results)

@app.route("/generate_report2", methods=["POST"])
def generate_report2():
    driver_name = request.form["driver_name"].strip()

    now = datetime.now()
    current_month = now.month
    current_year = now.year

    trips = list(trips_collection.find({
        "driver_name": driver_name,
        "date_obj": {
            "$gte": datetime(current_year, current_month, 1),
            "$lt": datetime(current_year, current_month + 1, 1) if current_month < 12 else datetime(current_year + 1, 1, 1)
        }
    }))

    for trip in trips:
        trip["date"] = trip["date_obj"].strftime("%Y-%m-%d")

    return render_template("reports2.html", trips=trips, driver_name=driver_name, month=current_month, year=current_year)

@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        hashed_password = generate_password_hash(password)
        new_user = {"name": name, "username": username, "password": hashed_password, "email": email}
        drivers_collection.insert_one(new_user)
        flash("Signup successful! Please log in.")
        return redirect(url_for('login_page'))
    return render_template('signup.html')

@app.route('/logout_admin', methods=['GET'])
def logout_admin():
    return render_template('logout_admin.html')

@app.route('/confirm_logout_admin', methods=['POST'])
def confirm_logout_admin():
    session.pop('admin_logged_in', None)
    session.clear()
    return redirect(url_for('admin_page'))

@app.route('/my_schedules')
def my_schedules():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    username = session['username']
    driver = drivers_collection.find_one({'username': username})
    
    if not driver:
        flash("Driver not found.")
        return redirect(url_for('login_page'))

    assignments = list(assignments_collection.find({'driver_id': driver['_id']}))
    print(assignments)  # Debug line

    return render_template('myschedules.html', assignments=assignments, driver_name=driver['name'])



def send_security_alert(username):
    user = drivers_collection.find_one({"username": username})
    if user and 'email' in user:
        msg = Message("Security Alert: Multiple Failed Login Attempts", recipients=[user['email']])
        msg.body = f"Dear {username},\n\nWe detected multiple failed login attempts on your account. If this wasn't you, please reset your password immediately.\n\nRegards,\nBus Management System"
        mail.send(msg)

@app.route('/driverlogout')
def driverlogout():
    session.pop('driver', None)
    return redirect('/driverlogin')


if __name__ == '__main__':
    app.run(debug=True)
