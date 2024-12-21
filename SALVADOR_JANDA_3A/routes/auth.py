import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User  # Assuming the User model is defined
from .. import db  # Assuming db is initialized in your __init__.py

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

def is_password_strong(password: str) -> bool:
    """Basic password strength validation: at least 8 characters, 1 uppercase, 1 digit"""
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    return True

def user_exists(email: str) -> bool:
    """Check if a user already exists with the provided email"""
    return User.query.filter_by(email=email).first() is not None

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Query the database for the user
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')  # Redirect to the page they tried to access
            return redirect(next_page or url_for('home.dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            logger.warning(f"Failed login attempt for email: {email}")

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate passwords
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.register'))

        if not is_password_strong(password):
            flash('Password must be at least 8 characters long, contain an uppercase letter and a number.', 'danger')
            return redirect(url_for('auth.register'))

        # Check if user already exists
        if user_exists(email):
            flash('Email already registered!', 'warning')
            return redirect(url_for('auth.register'))

        # Create a new user
        hashed_password = generate_password_hash(password, method='bcrypt')  # Use bcrypt for better security
        new_user = User(email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            logger.info(f"New user registered with email: {email}")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while processing your registration.', 'danger')
            logger.error(f"Error during registration: {e}")

    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
