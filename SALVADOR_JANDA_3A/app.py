import logging 
import os
import re
import secrets
import string
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

#Setup logging 
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s',
                    handlers=[
                        logging.FileHandler("app.log"),
                        logging.StreamHandler()
                    ])

app = Flask(__name__)
app.secret_key = 'Harold,Christian'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chan.db'  # Updated database name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg',}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)  # Store the file path for profile picture
    role = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    logging.info(f"Loading user with ID: {user_id}")
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    logging.debug(f"Checking if file '{filename}' is allowed: {result}")
    return result

#Landing Page
@app.route('/')
def home():
    logging.info("Redirecting to login page.")
    return redirect(url_for('login'))

#App route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        logging.info(f"Attempting login for user: {username}")

        user = User.query.filter(User.username == username).first()
        if user and check_password_hash(user.password, password):
            logging.info(f"Login successful for user: {username}")
            login_user(user)
            return redirect(url_for('dashboard'))
        logging.warning(f"Failed login attempt for user: {username}")
        flash('Invalid username or password!', 'danger')
    return render_template('login.html')

#App route for register 
@app.route('/register', methods=['GET', 'POST'])
def register():
    admin_exists = User.query.filter_by(role='admin').first()
    logging.info(f"Admin exists: {bool(admin_exists)}")
    if current_user.is_authenticated and current_user.role != 'admin' and admin_exists:
        logging.warning("Unauthorized register access attempt.")
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    suggested_password = None
    if request.method == 'POST':
        if 'suggest_password' in request.form:
            suggested_password = suggest_password()
            logging.info(f"Generated suggested password: {suggested_password}")
            flash('Here is a suggested password!', 'info')
            return render_template('register.html', suggested_password=suggested_password)

        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        logging.info(f"Registering user: {username}, role: {role}")

        if User.query.filter_by(username=username).first():
            logging.warning(f"Registration failed. Username {username} already exists.")
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        if not is_strong_password(password):
            logging.warning("Password does not meet strength requirements.")
            flash('Password must have at least 8 characters, uppercase, lowercase, and a number.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User {username} registered successfully.")
        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', suggested_password=suggested_password)

#App route for dashboard
@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if current_user.role == 'admin':
        logging.info(f"Admin user {current_user.username} accessed the dashboard.")
        users = User.query.all()
    else:
        logging.info(f"User {current_user.username} accessed the dashboard.")
        users = None
    return render_template('dashboard.html', users=users)

#App route for profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        logging.info(f"User {current_user.username} is updating their profile.")

        if 'username' in request.form:
            new_username = request.form['username']
            logging.debug(f"Updating username from {current_user.username} to {new_username}.")
            current_user.username = new_username

        if 'password' in request.form and request.form['password']:
            logging.debug("Updating password for user.")
            current_user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                logging.debug(f"Saving profile picture to {file_path}.")
                file.save(file_path)
                current_user.profile_pic = filename

        db.session.commit()
        logging.info(f"Profile updated successfully for user {current_user.username}.")
        flash('Profile updated successfully!', 'success')

    return render_template('profile.html', user=current_user)

#App route for editing profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        logging.info(f"User {current_user.username} is editing their profile.")

        username = request.form.get('username')
        password = request.form.get('password')
        profile_pic = request.files.get('profile_pic')

        if username and username != current_user.username:
            logging.debug(f"Updating username from {current_user.username} to {username}.")
            current_user.username = username

        if password:
            logging.debug("Updating password for user.")
            current_user.password = generate_password_hash(password)

        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logging.debug(f"Saving profile picture to {file_path}.")
            profile_pic.save(file_path)
            current_user.profile_pic = filename

        db.session.commit()
        logging.info(f"Profile changes saved successfully for user {current_user.username}.")
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html')

#App route for add user function
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        logging.warning(f"Unauthorized access attempt to 'add_user' by user {current_user.username}.")
        flash("You do not have permission to access this page.", 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        logging.info(f"Admin {current_user.username} is attempting to add a new user with username: {username}, role: {role}.")

        username_exists, password_exists = is_duplicate(username, password)
        if username_exists:
            logging.warning(f"Failed to add user: Username '{username}' already exists.")
            flash('Username already exists!', 'danger')
            return redirect(url_for('add_user'))
        if password_exists:
            logging.warning("Failed to add user: Password is already in use.")
            flash('Password has already been used!', 'danger')
            return redirect(url_for('add_user'))

        if not is_strong_password(password):
            logging.warning("Failed to add user: Password does not meet strength requirements.")
            flash('Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and have no spaces.', 'danger')
            return redirect(url_for('add_user'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        logging.info(f"New user '{username}' with role '{role}' added successfully by admin {current_user.username}.")
        flash("New user added successfully!", 'success')
        return redirect(url_for('dashboard'))

    logging.info(f"Admin {current_user.username} accessed the 'add_user' page.")
    return render_template('add_user.html')


#App route for edit user function 
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        logging.warning(f"Unauthorized access attempt to 'edit_user' by user {current_user.username}.")
        flash("You do not have permission to access this page.")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    logging.info(f"Admin {current_user.username} accessed 'edit_user' for user ID {user_id} (username: {user.username}).")

    if request.method == 'POST':
        old_username = user.username
        old_role = user.role

        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()

        logging.info(
            f"User ID {user_id} updated by admin {current_user.username}. "
            f"Changes - Username: '{old_username}' to '{user.username}', Role: '{old_role}' to '{user.role}'."
        )
        flash("User details updated successfully!")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html')

#App route for delete user function (for admin)
@app.route('/admin/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        logging.warning(f"Unauthorized access attempt to 'delete_user' by user {current_user.username}.")
        flash("You do not have permission to delete a user.")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    logging.info(f"Admin {current_user.username} accessed 'delete_user' for user ID {user_id} (username: {user.username}).")

    db.session.delete(user)
    db.session.commit()

    logging.info(f"User ID {user_id} (username: {user.username}) was deleted by admin {current_user.username}.")
    flash("User deleted successfully!")
    return redirect(url_for('dashboard'))

#Password checking 
def is_duplicate(username, password):
    logging.info(f"Checking for duplicate username and password for username: {username}.")
    username_exists = User.query.filter_by(username=username).first()
    if username_exists:
        logging.warning(f"Duplicate username found: {username}.")

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    password_exists = User.query.filter(User.password == hashed_password).first()
    if password_exists:
        logging.warning("Duplicate password detected.")

    return username_exists, password_exists

def is_strong_password(password):
    logging.info("Validating password strength.")
    strong = (len(password) >= 8 and
              re.search(r'[A-Z]', password) and
              re.search(r'[a-z]', password) and
              re.search(r'\d', password) and
              not re.search(r'\s', password))

    if strong:
        logging.info("Password is strong.")
    else:
        logging.warning("Password is weak. Ensure it meets all strength requirements.")
    
    return strong

def suggest_password(length=12):
    if length < 8:
        logging.warning(f"Requested password length ({length}) is less than 8. Adjusting to 8.")
        length = 8

    logging.info(f"Generating a suggested password with length: {length}.")
    
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = string.punctuation.replace(' ', '')

    password = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits)
    ]

    if secrets.choice([True, False]):
        password.append(secrets.choice(special))

    all_chars = upper + lower + digits + special
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]
    secrets.SystemRandom().shuffle(password)

    suggested_password = ''.join(password)
    logging.info(f"Suggested password generated: {suggested_password} (hidden in production logs).")
    
    return suggested_password

#App route for user profile 
@app.route('/user/profile/<int:user_id>')
def view_profile(user_id):
    logging.info(f"Attempting to view profile for user_id: {user_id}.")
    user = User.query.get_or_404(user_id)
    logging.info(f"Profile loaded successfully for user_id: {user_id}.")
    return render_template('view_profile.html', user=user)

# Logout app route
@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        logging.info(f"User {current_user.username} is logging out.")
    else:
        logging.info("An unauthenticated user is attempting to log out.")

    logout_user()
    flash('You have been logged out.', 'info')

    if current_user.is_authenticated:
        logging.info(f"User {current_user.username} successfully logged out.")
    else:
        logging.info("An unauthenticated user has successfully logged out.")

    return redirect(url_for('login'))


# Clearing caches
@app.after_request
def add_cache_control(response):
    logging.debug("Adding cache-control headers to the response.")
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    logging.debug("Cache-control headers added successfully.")
    return response

# OS config for directory
with app.app_context():
    logging.info("Initializing database and checking upload directory configuration.")
    db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logging.info(f"Created upload directory at {app.config['UPLOAD_FOLDER']}.")
    else:
        logging.info(f"Upload directory already exists at {app.config['UPLOAD_FOLDER']}.")

if __name__ == '__main__':
    app.run(debug=True)
