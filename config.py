# python_backend/config.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Flask Secret Key for session management and security
    # Generate a strong one: import secrets; secrets.token_hex(16)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-very-secret-key-replace-this-in-production'

    # MySQL Database Configuration for local development
    # Make sure these match the details you set up in phpMyAdmin
    DB_USER = os.environ.get('DB_USER') or 'bsdoc_app_user' # The user you created
    DB_PASSWORD = os.environ.get('DB_PASSWORD') or 'testUser123-' # The password for that user
    DB_HOST = os.environ.get('DB_HOST') or 'localhost' # Your local WampServer MySQL host
    DB_PORT = os.environ.get('DB_PORT') or '3306' # Default MySQL port
    DB_NAME = os.environ.get('DB_NAME') or 'bsdoc_app_db' # The database you created

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Recommended to set to False