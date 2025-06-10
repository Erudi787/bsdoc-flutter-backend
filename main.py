# # python_backend/app.py

# from flask import Flask, jsonify
# from flask_sqlalchemy import SQLAlchemy
# from config import Config # Import your Config class
# import click # <-- IMPORT CLICK for custom CLI commands

# # --- Flask App Initialization ---
# app = Flask(__name__)
# app.config.from_object(Config) # Load configuration from Config class

# # --- Database Initialization ---
# db = SQLAlchemy(app)

# # --- Define a simple database model (e.g., for users) ---
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)

#     def __repr__(self):
#         return f'<User {self.username}>'

# # --- Custom Flask CLI Command for Database Initialization ---
# # This is the recommended way to create tables
# @app.cli.command('init-db')
# def init_db_command():
#     """Clear existing data and create new tables."""
#     # It's good practice to drop existing tables for a clean start during dev,
#     # but be careful with this in production! You'd typically use migrations.
#     db.drop_all()
#     db.create_all()
#     click.echo('Initialized the database.') # Use click.echo for CLI output

# # --- Define your first API endpoint (route) ---
# @app.route('/')
# def home():
#     return jsonify({"message": "Welcome to your Health App Backend!"})

# @app.route('/users')
# def get_users():
#     users = User.query.all()
#     # Convert users to a list of dictionaries for JSON response
#     user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
#     return jsonify(user_list)

# # This block ensures app.run() is called only when the script is executed directly
# # and not when imported (e.g., by the 'flask' command).
# if __name__ == '__main__':
#     app.run(debug=True, port=5000) # Run on port 5000 for development
# ^^app.py

import os
from fastapi import FastAPI, HTTPException
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(url, key)

app = FastAPI()

class UserCredentials(BaseModel):
    email: str
    password: str
    
@app.post("/signup")
async def signup(credentials: UserCredentials):
    existing_user_res = supabase.table("users").select("id").eq("email", credentials.email).execute()
    
    if existing_user_res.data:
        raise HTTPException(
            status_code=409, #conflict code
            detail="This email is already registered. Please try logging in.",
        )
        
    response = supabase.auth.sign_up({
        "email": credentials.email,
        "password": credentials.password,
    })
    
    if response.user:
        return {"message": "Signup successful! Please check your email to verify your account."}
    elif response.error:
        raise HTTPException(
            status_code=400,
            detail=response.error.message,
        )
        
    raise HTTPException(status_code=500, detail="An unexpected error occurred during signup.")

@app.post("/login")
async def login(credentials: UserCredentials):
    res = supabase.auth.sign_in_with_password({
        "email": credentials.email,
        "password": credentials.password
    })

    if res.session:
        return res.session
    elif res.error:
        if "Invalid login credentials" in res.error.message:
            raise HTTPException(
                status_code=401, #unauth code
                detail="Invalid email or password. Please try again.",
            )
        
        raise HTTPException(
            status_code=400,
            detail=res.error.message,
        )
        
    raise HTTPException(status_code=500, detail="An unknown error has occurred during login.")