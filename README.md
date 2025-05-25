VIATRA is a comprehensive web application designed to automate bus scheduling, route management, and driver assignment. It streamlines daily operations for transit authorities by providing efficient scheduling, real-time driver management, and detailed reporting features.

Features
Bus Scheduling: Create, assign, and manage bus schedules by shifts and routes.

Driver Management: Register drivers, assign them to shifts, and manage their profiles.

Shift Selection: Drivers can view and select their assigned shifts.

Real-time Schedule Display: Drivers can view their upcoming schedules via a personalized dashboard.

Reports & Logs: Generate detailed reports on trips, driver performance, and schedules.

Authentication: Secure login for admins and drivers with role-based access control.

Notifications: Email alerts for login attempts and important updates.

Responsive UI: Modern, user-friendly interface with attractive CSS styling.

Technologies Used
Backend: Python, Flask

Database: MongoDB

Frontend: HTML, CSS, JavaScript

Others: Email SMTP for notifications

Installation
Prerequisites
Python 3.8+

MongoDB installed and running

pip package manager

Steps
Clone the repository:

bash
Copy
Edit
git clone https://github.com/Dharanika-K/Bus-scheduling.git
cd absrms
Create a virtual environment and activate it:

bash
Copy
Edit
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Configure environment variables (create a .env file or set variables):

MONGO_URI for MongoDB connection

SECRET_KEY for Flask sessions

EMAIL_USER and EMAIL_PASS for SMTP email notifications

Run the application:

bash
Copy
Edit
flask run
Open your browser and navigate to http://localhost:5000

Usage
Admin Panel: Manage buses, routes, drivers, and schedules.

Driver Login: Drivers can log in to view and manage their assigned shifts.

Reports: Generate reports based on driver, date, or route.

Project Structure
csharp
Copy
Edit
absrms/
├── app.py                 # Main Flask application
├── templates/             # HTML templates
├── static/
│   ├── css/               # CSS files
│   ├── js/                # JavaScript files
├── models/                # Database models (if any)
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
