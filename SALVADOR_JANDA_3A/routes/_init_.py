import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from routes.home import home_bp
from routes.auth import auth_bp

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Set up logging
def setup_logging():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    return logger

# Set up configuration loading based on the environment
def load_config(app):
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')  # Ensure secret key is set securely
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Turn off modification tracking for performance
    # Add other environment-specific configurations if needed

def create_app(config_object="config.Config"):
    app = Flask(__name__)

    # Load configuration
    load_config(app)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Set login manager configuration
    login_manager.login_view = "auth.login"

    # Register blueprints dynamically (easier to scale)
    blueprints = [home_bp, auth_bp]
    for blueprint in blueprints:
        app.register_blueprint(blueprint)

    # Set up logging
    logger = setup_logging()
    logger.info("Application started")

    return app
