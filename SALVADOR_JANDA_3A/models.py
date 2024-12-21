from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import exc

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)  # Primary Key
    username = db.Column(db.String(80), nullable=False, unique=True)  # Unique username
    email = db.Column(db.String(120), nullable=False, unique=True)  # Unique email
    password_hash = db.Column(db.String(128), nullable=False)  # Hashed password
    profile_picture = db.Column(db.String(200), default='default.png')  # Optional profile picture

    # Hash the password before saving
    def set_password(self, password: str) -> None:
        """Hash the password using bcrypt."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Verify the password during login
    def check_password(self, password: str) -> bool:
        """Check if the hashed password matches the input password."""
        return bcrypt.check_password_hash(self.password_hash, password)

    # Represent the object
    def __repr__(self) -> str:
        return f"<User {self.username}, Email: {self.email}, Profile Picture: {self.profile_picture}>"

    # Ensure that the username and email are unique before inserting
    @classmethod
    def create(cls, username: str, email: str, password: str) -> 'User':
        """Create a new user and handle unique constraints."""
        if cls.query.filter_by(username=username).first():
            raise ValueError("Username is already taken")
        if cls.query.filter_by(email=email).first():
            raise ValueError("Email is already registered")
        
        user = cls(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
            return user
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError("An error occurred while creating the user: " + str(e))

