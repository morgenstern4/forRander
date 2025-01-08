import cloudinary
import cloudinary.uploader
import cloudinary.api
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient
from uuid import uuid4
from typing import List, Dict
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI()

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB configuration
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["demo_app"]
users_collection = db["users"]
groups_collection = db["groups"]
memories_collection = db["memories"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure = True,
)

# Models
class User(BaseModel):
    email: EmailStr
    password: str

class Group(BaseModel):
    group_name: str

class JoinGroup(BaseModel):
    group_name: str
    password: str

# Utilities
def hash_password(password: str) -> str:
    """Hash the password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify the password against the hashed value."""
    return pwd_context.verify(password, hashed)

def create_jwt(data: dict) -> str:
    """Create a JWT token."""
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token: str) -> dict:
    """Decode a JWT token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def extract_token(authorization: str) -> str:
    """Extract the token from the Authorization header."""
    if not authorization or " " not in authorization:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return authorization.split(" ")[1]

# Routes
@app.get("/")
def read_root() -> Dict[str, str]:
    """Root endpoint to check if the API is running."""
    return {"message": "API is running"}

@app.post("/signup")
async def signup(user: User) -> Dict[str, str]:
    """Endpoint for user signup."""
    # Check if the email already exists
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    # Insert new user into the database
    users_collection.insert_one({"email": user.email, "password": hash_password(user.password)})
    return {"message": "Signup successful"}

@app.post("/login")
async def login(user: User) -> Dict[str, str]:
    """Endpoint for user login."""
    # Log the request body for debugging
    print(f"Login attempt for user: {user.email}")

    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token and return it
    return {"access_token": create_jwt({"sub": user.email})}

@app.post("/create-group")
async def create_group(group: Group, authorization: str = Header(...)) -> Dict[str, str]:
    """Endpoint to create a new group."""
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    # Check if the group already exists
    if groups_collection.find_one({"group_name": group.group_name}):
        raise HTTPException(status_code=400, detail="Group already exists")

    # Create a password for the group and add the creator as a member
    password = str(uuid4())[:8]
    groups_collection.insert_one({
        "group_name": group.group_name,
        "password": password,
        "members": [decoded_token["sub"]]
    })
    return {"message": "Group created", "group_name": group.group_name, "password": password}

@app.post("/join-group")
async def join_group(data: JoinGroup, authorization: str = Header(...)) -> Dict[str, str]:
    """Endpoint to join an existing group."""
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    group = groups_collection.find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        raise HTTPException(status_code=400, detail="Invalid group or password")

    groups_collection.update_one(
        {"group_name": data.group_name},
        {"$addToSet": {"members": decoded_token["sub"]}}
    )
    return {"message": f"Joined group {data.group_name} successfully"}

@app.post("/upload-memory/{group_name}")
async def upload_memory(group_name: str, file: UploadFile = File(...), authorization: str = Header(...)) -> JSONResponse:
    """Endpoint to upload a memory (image) to Cloudinary and save the URL in the database."""
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    try:
        # Log file upload attempt
        print(f"Attempting to upload file for group: {group_name}")

        cloudinary_response = cloudinary.uploader.upload(file.file, folder="memories/")
        file_url = cloudinary_response['secure_url']

        # Log successful upload
        print(f"Upload successful. URL: {file_url}")
    except Exception as e:
        # Log failure and return detailed message
        print(f"Cloudinary upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

    memory_data = {
        "group_name": group_name,
        "url": file_url,
        "uploader": decoded_token["sub"],
    }
    memories_collection.insert_one(memory_data)

    return JSONResponse(content={"message": "Image uploaded successfully", "url": file_url})

@app.get("/memories/{group_name}")
async def get_memories(group_name: str, authorization: str = Header(...)) -> Dict[str, List[Dict[str, str]]]:
    """Endpoint to get all memories for a specific group."""
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    memories = list(memories_collection.find({"group_name": group_name}))
    for memory in memories:
        memory["_id"] = str(memory["_id"])
    return {"data": memories}

@app.exception_handler(Exception)
async def general_exception_handler(request, exc) -> JSONResponse:
    """General exception handler."""
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred", "details": str(exc)},
    )
