H&C Access Control System

Overview:

The H&C Access Control System is a Flask-based web application designed to manage users and their roles efficiently. This system provides robust user authentication, role-based access control, and an admin interface for managing users.

Key Features:

User Authentication: Secure login/logout system with password hashing.
Role-Based Access Control: Admins can manage user accounts and roles, while regular users can update their profiles.
Secure Password Handling: Enforces strong password policies with an optional password generator.
Admin Dashboard: Comprehensive user management interface for admins.
Profile Management: Users can upload profile pictures and change their details.
File Upload Support: Allows secure uploads of profile pictures (PNG, JPG).

Setup Instructions:

1. Clone the repository
git clone https://github.com/your-username/hc-access-control.git
cd hc-access-control

2. Create a virtual environment
python -m venv venv
source venv/bin/activate      # For Linux/Mac
venv\Scripts\activate         # For Windows

3. Install dependencies
pip install -r requirements.txt

4. Configure the application
The default database is chan.db, and the secret key is pre-configured. To change the secret key, update app.secret_key in app.py.

5. Initialize the database
python
>>> from app import db
>>> db.create_all()
>>> exit()

6. Run and access the application
python app.py
http://127.0.0.1:5000 

Usage Instructions:
For Admin Registration:
Visit the /register page to register as an admin.
Ensure you set up the first admin before any other users.
User Management:
Admins can add, edit, or delete users from the admin dashboard.
Regular users can only manage their own profiles.
Profile Pictures:
Supported formats: PNG, JPG.
Upload your picture through the profile management page.

Troubleshooting
Common Issues:
1. Database Not Found:
Ensure you’ve run db.create_all() in the Flask shell.
2. Login Fails with Valid Credentials:
Check if the password hashing algorithm matches during registration.
3. Admin Privileges Missing:
Ensure the first registered user has the admin role.

