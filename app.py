from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask import jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message  
import re
from datetime import datetime, timedelta
import calendar

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "djmadl2025buschedule"  


# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["bus_scheduling"]
drivers_collection = db["drivers"]
assignments_collection = db["assignments"]
schedules_collection = db["schedules"]



# Configure Flask-Mail for Email Notifications
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '23z317@psgtech.ac.in' 
app.config['MAIL_PASSWORD'] = 'dd.'  
app.config['MAIL_DEFAULT_SENDER'] = '23z317@psgtech.ac.in'

mail = Mail(app)

@app.route('/')
def home():
    return redirect(url_for('landing_page'))

@app.route('/schedule')
def schedule():
    auto_unassign_old_shifts()
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
    bus_id = request.form.get('bus_id')

    existing_schedule = schedules_collection.find_one({
        "driver_id": ObjectId(driver_id),
        "date": date
    })

    if existing_schedule:
        return render_template("shift.html",
                               drivers=get_available_drivers(date),
                               routes=["Route A", "Route B", "Route C"],
                               message="Driver already assigned for this date.")

    driver = drivers_collection.find_one({"_id": ObjectId(driver_id)})
    if driver and 'name' in driver:
        driver_name = driver['name']

        schedule_data = {
            "driver_id": ObjectId(driver_id),
            "driver_name": driver_name,
            "shift_time": shift_time,
            "bus_route": bus_route,
            "date": date,
            "bus_id": bus_id
        }

        schedules_collection.insert_one(schedule_data)
        assignments_collection.insert_one(schedule_data)

        drivers_collection.update_one(
            {"_id": ObjectId(driver_id)},
            {"$set": {"status": "Assigned"}}
        )

    return redirect(url_for('schedule'))



@app.route('/get_available_drivers/<date>')
def get_available_drivers(date):
    assigned_ids = schedules_collection.find({"date": date})
    assigned_driver_ids = [entry["driver_id"] for entry in assigned_ids]

    available_drivers = drivers_collection.find({
        "_id": {"$nin": assigned_driver_ids}
    })

    drivers_data = [{"_id": str(driver["_id"]), "name": driver["name"]} for driver in available_drivers]
    return jsonify(drivers_data)


@app.route('/unassign_driver/<driver_id>', methods=['POST'])
def unassign_driver(driver_id):
    drivers_collection.update_one({"_id": ObjectId(driver_id)}, {"$set": {"status": "Unassigned"}})
    return redirect(url_for('unassigned_page'))

@app.route('/add_driver', methods=['GET', 'POST'])
def add_driver():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        experience = request.form.get('experience')
        availability = request.form.get('availability')

        if name and username and email and phone and experience and availability:
            # Default password is "password123" (hashed)
            default_password = generate_password_hash("password123")

            new_driver = {
                "name": name,
                "username": username,
                "email": email,
                "phone": phone,
                "experience": int(experience),
                "availability": availability,
                "password": default_password,
                "status": "Unassigned"
            }

            drivers_collection.insert_one(new_driver)
            return redirect(url_for('schedule'))

    return render_template('add_driver.html')

login_attempts = {}

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Initialize tracking if not present
        if username not in login_attempts:
            login_attempts[username] = {'count': 0, 'lockout_until': None}

        # Check if account is locked
        if login_attempts[username]['lockout_until']:
            if datetime.now() < login_attempts[username]['lockout_until']:
                time_left = (login_attempts[username]['lockout_until'] - datetime.now()).seconds
                flash(f'Account locked. Try again in {time_left} seconds.')
                return redirect(url_for('login_page'))
            else:
                login_attempts[username] = {'count': 0, 'lockout_until': None}  # Reset lockout after expiry

        # Check credentials in the MongoDB database
        user = drivers_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):  # Using check_password_hash for security
            login_attempts[username] = {'count': 0, 'lockout_until': None}  # Reset on success

            # Set the session variable here after successful login
            session['username'] = username 
            session['driver_id'] = str(user['_id']) 
            flash('Login successful!')
            return redirect(url_for('dashboard_page'))  # Redirect to dashboard page after login
        else:
            login_attempts[username]['count'] += 1

            if login_attempts[username]['count'] >= 3:
                login_attempts[username]['lockout_until'] = datetime.now() + timedelta(minutes=5)
                flash('Too many failed attempts. Account locked for 5 minutes.')
                return redirect(url_for('login_page'))

            attempts_left = 3 - login_attempts[username]['count']
            flash(f'Invalid credentials. You have {attempts_left} attempts left.')
            return redirect(url_for('login_page'))

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

@app.route('/update_availability', methods=['POST'])
def update_availability():
    driver_id = request.form.get('driver_id')
    if not driver_id:
        flash("Driver ID missing.")
        return redirect(url_for('driver_profile'))

    new_status = request.form.get('availability')

    drivers_collection.update_one(
        {"_id": ObjectId(driver_id)},
        {"$set": {"availability": new_status}} 
    )

    return redirect(url_for('driver_profile'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login_page'))

@app.route('/dashboard')
def dashboard_page():
    if 'username' not in session or 'driver_id' not in session:
        flash("You must be logged in to access the dashboard.")
        return redirect(url_for('login_page'))  # Redirect to login if not logged in
    return render_template('dashboard.html')  # Proceed to dashboard if logged in

@app.route('/shift_page')
def shift_page():
    all_drivers = list(drivers_collection.find({}))
    routes = ["Route A", "Route B", "Route C"]
    return render_template("shift.html", drivers=all_drivers, routes=routes)


@app.route('/unscheduling')
def unscheduling_page():
    assigned_drivers = list(assignments_collection.find({}))

    for driver in assigned_drivers:
        driver_data = drivers_collection.find_one({"_id": driver["driver_id"]})
        if driver_data:
            driver["name"] = driver_data.get("name", "Unknown")  
            driver["route"] = driver_data.get("route", "Not Assigned")  

    return render_template("unscheduling.html", assigned_drivers=assigned_drivers)


@app.route('/unschedule_driver/<assignment_id>', methods=['POST'])
def unschedule_driver(assignment_id):
    assignment = assignments_collection.find_one({"_id": ObjectId(assignment_id)})

    if assignment:
        driver_id = assignment["driver_id"]
        date = assignment.get("date")  

        drivers_collection.update_one({"_id": driver_id}, {"$set": {"status": "Unassigned"}})

        assignments_collection.delete_one({"_id": ObjectId(assignment_id)})
        drivers_collection.delete_one({"_id": ObjectId(assignment_id)})

        if date:
            schedules_collection.delete_one({
                "driver_id": driver_id,
                "date": date
            })

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



@app.route('/filter_search', methods=['GET', 'POST'])
def filter_search():
    reports = []
    month = None
    year = None

    if request.method == 'POST':
        driver_id = request.form.get('driver_id', '').strip()
        driver_name = request.form.get('driver_name', '').strip()
        month = int(request.form.get('month'))
        year = int(request.form.get('year'))

        start_date = datetime(year, month, 1)
        end_day = calendar.monthrange(year, month)[1]
        end_date = datetime(year, month, end_day, 23, 59, 59)

        query = {
            'date': {
                '$gte': start_date.strftime("%Y-%m-%d"),
                '$lte': end_date.strftime("%Y-%m-%d")
            }
        }

        if driver_id:
            try:
                query['driver_id'] = ObjectId(driver_id)
            except:
                pass
        elif driver_name:
            query['driver_name'] = {'$regex': driver_name, '$options': 'i'}

        reports = list(assignments_collection.find(query))

    return render_template('filter_search.html', reports=reports, month=month, year=year)

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
    if 'driver_id' not in session:
        return redirect(url_for('login_page'))  # Redirect if not logged in

    driver_id = session['driver_id']
    schedules = list(assignments_collection.find({'driver_id': ObjectId(driver_id)}))

    return render_template('myschedules.html', schedules=schedules)

def send_security_alert(username):
    user = drivers_collection.find_one({"username": username})
    if user and 'email' in user:
        msg = Message("Security Alert: Multiple Failed Login Attempts", recipients=[user['email']])
        msg.body = f"Dear {username},\n\nWe detected multiple failed login attempts on your account. If this wasn't you, please reset your password immediately.\n\nRegards,\nBus Management System"
        mail.send(msg)

from datetime import datetime

def auto_unassign_old_shifts():
    today = datetime.today().strftime("%Y-%m-%d")
    
    expired = assignments_collection.find({"date": {"$lt": today}})

    for assign in expired:
        drivers_collection.update_one(
            {"_id": assign["driver_id"]},
            {"$set": {"status": "Unassigned"}} 
        )
        assignments_collection.delete_one({"_id": assign["_id"]})


@app.route('/logout')
def driverlogout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login_page'))

@app.route('/cleanup_assignments')
def cleanup_assignments():
    # Wipe all existing incorrect assignments from schedules_collection
    result = schedules_collection.delete_many({})
    return f"Deleted {result.deleted_count} schedule entries."



if __name__ == '__main__':
    app.run(debug=True)
