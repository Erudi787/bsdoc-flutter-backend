import os
from fastapi import FastAPI, HTTPException, Depends, Header, Form, File, UploadFile
from fastapi.responses import JSONResponse
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Annotated
from datetime import datetime
from gotrue.errors import AuthApiError

# --- Setup ---
load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
service_key: str = os.environ.get("SUPABASE_SERVICE_KEY")
anon_key: str = os.environ.get("SUPABASE_ANON_KEY")

# Public client for actions that don't require admin rights (signup/login)
supabase_public: Client = create_client(url, anon_key)
# Admin client for all trusted backend operations
supabase_admin: Client = create_client(url, service_key)

app = FastAPI()

# --- Pydantic Models ---
class UserCredentials(BaseModel):
    email: str
    password: str

# --- Reusable Dependencies ---
async def get_current_user(authorization: Annotated[str, Header()]):
    """A dependency that validates the JWT and returns the authenticated user."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    
    token = authorization.split(" ")[1]
    
    try:
        # Always use the admin client on the backend to validate a JWT
        response = supabase_admin.auth.get_user(token)
        user = response.user
        if user:
            return user
        else:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication error: {e}")

# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "BSDOC FastAPI backend is running!"}

@app.post("/signup")
async def signup(credentials: UserCredentials):
    """Handles standard user registration."""
    # Use the ADMIN client to check for existing users to bypass RLS if any
    existing_user_res = supabase_admin.table("users").select("id", count='exact').eq("email", credentials.email.lower()).execute()
    
    if existing_user_res.count > 0:
        raise HTTPException(
            status_code=409, # Conflict
            detail="This email is already registered. Please try logging in.",
        )
        
    # Use the PUBLIC client for the public-facing sign_up method
    response = supabase_public.auth.sign_up({
        "email": credentials.email,
        "password": credentials.password,
    })
    
    if response.user:
        return {"message": "Signup successful! Please check your email to verify your account."}
    
    # The supabase-py library raises an exception on error, so this part is for safety
    raise HTTPException(status_code=500, detail="An unexpected error occurred during signup.")

@app.post("/login")
async def login(credentials: UserCredentials):
    """Handles user login and returns the session object."""
    try:
        # Use the PUBLIC client to sign in, as this is a user-level action
        res = supabase_public.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        return res.session
    except AuthApiError as e:
        # Catch specific auth errors from the library
        if "Invalid login credentials" in e.message:
            raise HTTPException(
                status_code=401, # Unauthorized
                detail="Invalid email or password. Please try again.",
            )
        raise HTTPException(status_code=400, detail=e.message)

@app.post('/logout')
async def logout(authorization: Annotated[str, Header()]):
    """Logs out the user by invalidating their token."""
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")
        
        token = authorization.split(" ")[1]
        
        # Use the admin client to sign out the user with their JWT token
        supabase_admin.auth.sign_out(token)
        return JSONResponse(status_code=200, content={"message": "User logged out successfully"})
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # For logout, we can be more lenient - if the token is already invalid, 
        # that's essentially what we wanted anyway
        return JSONResponse(status_code=200, content={"message": "User logged out successfully"})

@app.get("/users/me")
async def get_my_profile(current_user: Annotated[dict, Depends(get_current_user)]):
    """Fetches the profile for the currently authenticated user."""
    user_id = current_user.id
    
    try:
        res = supabase_admin.table("profiles").select("*").eq("id", user_id).single().execute()
        
        # Check if we got data back
        if res.data:
            return res.data
        else:
            raise HTTPException(status_code=404, detail="Profile not found for this user")
            
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not fetch user profile: {str(e)}")
    
@app.post("/doctors/registration")
async def doctorSignup(
    firstName: str = Form(...),
    lastName: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    file: UploadFile = File(...),
):
    print(f"--- Backend: /doctors/registration called for email: {email} ---")
    
    # 1. Check if user already exists
    try:
        existing_user_res = supabase_admin.table("users").select("id", count='exact').eq("email", email.lower()).execute()
        if existing_user_res.count > 0:
            raise HTTPException(status_code=409, detail="This email is already registered.")
    except HTTPException:
        raise HTTPException(status_code=500, detail="Error checking existing user")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking existing user: {str(e)}")
        
    # Variables for rollback if a step fails
    user_id = None
    uploaded_file_path = ""
    
    try:
        # 2. Create the user using the PUBLIC client
        try:
            signup_response = supabase_public.auth.sign_up({
                "email": email, "password": password,
            })
            
            if not signup_response.user or not signup_response.user.id:
                raise Exception("User creation failed: No user returned")
                
            user_id = signup_response.user.id
            print(f"Backend | User created with ID: {user_id}")
        except Exception as signup_error:
            raise Exception(f"User signup failed: {str(signup_error)}")

        # 3. Upload Proof File (use ADMIN client)
        try:
            file_ext = file.filename.split('.')[-1] if '.' in file.filename else ''
            file_path_in_storage = f"{user_id}/prc_id_{int(datetime.now().timestamp())}.{file_ext}"
            file_content = await file.read()
            
            upload_res = supabase_admin.storage.from_("doctor-proofs").upload(
                path=file_path_in_storage, file=file_content, file_options={"content-type": file.content_type}
            )
            uploaded_file_path = file_path_in_storage
            print(f"Backend | File uploaded to path: {uploaded_file_path}")
        except Exception as upload_error:
            raise Exception(f"File upload failed: {str(upload_error)}")

        # 4. Update the user's profile (use ADMIN client)
        try:
            profile_update_res = supabase_admin.table("profiles").update({
                "first_name": firstName, "last_name": lastName, "role": "user"
            }).eq("id", user_id).execute()
            
            print(f"Backend | Profile updated for user: {user_id}")
        except Exception as profile_error:
            raise Exception(f"Profile update failed: {str(profile_error)}")

        # 5. Insert verification record (use ADMIN client)
        try:
            verification_res = supabase_admin.table("doctor_verification").insert({
                "user_id": user_id, "prc_id_url": uploaded_file_path, "status": "pending"
            }).execute()
            
            print(f"Backend | Verification record created for user: {user_id}")
        except Exception as verification_error:
            raise Exception(f"Verification record creation failed: {str(verification_error)}")
        
        # 6. Notify Admins (use ADMIN client)
        try:
            admins_res = supabase_admin.table("profiles").select("id").eq("role", "admin").execute()
            if admins_res.data:
                notifications = [{
                    "user_id": admin["id"], "type": "VERIFICATION_SUBMITTED",
                    "message": f"New doctor verification request from {firstName} {lastName} needs review.",
                    "link_url": "admin:doctor-verification", "metadata": {"applicant_user_id": user_id}
                } for admin in admins_res.data]
                supabase_admin.table("notifications").insert(notifications).execute()
                print(f"Backend | Sent notifications to {len(admins_res.data)} admin(s).")
        except Exception as notification_error:
            # Don't fail the entire registration if notifications fail
            print(f"Warning: Failed to send admin notifications: {str(notification_error)}")

    except AuthApiError as e:
        # Catch specific auth errors (e.g., weak password)
        # Rollback if needed
        await cleanup_failed_registration(user_id, uploaded_file_path)
        raise HTTPException(status_code=400, detail=f"Authentication error: {e.message}")
    except Exception as e:
        # If any step fails, roll back the previous steps to keep the database clean
        await cleanup_failed_registration(user_id, uploaded_file_path)
        raise HTTPException(status_code=500, detail=f"An error occurred during registration: {str(e)}")
    
    return {"message": "Registration successful! Please check your email to verify your account."}

async def cleanup_failed_registration(user_id: str, uploaded_file_path: str):
    """Helper function to clean up failed registration attempts"""
    if user_id:
        try:
            supabase_admin.auth.admin.delete_user(user_id)
            print(f"Rolled back auth user: {user_id}")
        except Exception as delete_error:
            print(f"Failed to rollback user: {delete_error}")
    
    if uploaded_file_path:
        try:
            supabase_admin.storage.from_("doctor-proofs").remove([uploaded_file_path])
            print(f"Rolled back storage file: {uploaded_file_path}")
        except Exception as delete_error:
            print(f"Failed to rollback storage file: {delete_error}")

@app.get("/doctors/me/appointments")
async def get_my_appointments_for_date(
    current_user: Annotated[dict, Depends(get_current_user)]  ,
    date: str
):
    doctor_id = current_user.id
    
    try:
        res = supabase_admin.from_("appointments") \
        .select("*, patient:profiles(id, first_name, last_name, profile_image_url)") \
        .eq("doctor_id", doctor_id) \
        .eq("appointment_date", date) \
        .order("appointment_time", desc=False) \
        .execute()
    
        return res.data
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")