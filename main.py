import cloudinary
import cloudinary.uploader
import cloudinary.api
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
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
if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set in environment variables")
client = MongoClient(MONGO_URI)
try:
    client.server_info()  # Test the connection
    print("MongoDB connected successfully")
except Exception as e:
    raise RuntimeError(f"Failed to connect to MongoDB: {e}")

db = client["demo_app"]
users_collection = db["users"]
groups_collection = db["groups"]
memories_collection = db["memories"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables")
ALGORITHM = "HS256"

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

# Utilities
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_jwt(data: dict) -> str:
    try:
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        print(f"JWT Created: {token}")
        return token
    except Exception as e:
        print(f"JWT Creation Error: {e}")
        raise HTTPException(status_code=500, detail="Token creation failed")

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def extract_token(authorization: str) -> str:
    if not authorization or " " not in authorization:
        print(f"Invalid Authorization header: {authorization}")
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return authorization.split(" ")[1]

def success_response(message: str, data: dict = None) -> JSONResponse:
    return JSONResponse(content={"status": "success", "message": message, "data": data})

def error_response(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(content={"status": "error", "message": message}, status_code=status_code)

# Models
class User(BaseModel):
    email: EmailStr
    password: str

class Group(BaseModel):
    group_name: str

    @validator("group_name")
    def validate_group_name(cls, value):
        if len(value) < 3 or len(value) > 50:
            raise ValueError("Group name must be between 3 and 50 characters")
        return value

class JoinGroup(BaseModel):
    group_name: str
    password: str

# Routes
@app.get("/")
def read_root() -> JSONResponse:
    return success_response("API is running")

@app.post("/signup")
async def signup(user: User) -> JSONResponse:
    if users_collection.find_one({"email": user.email}):
        print(f"Signup failed: Email already exists - {user.email}")
        return error_response("Email already exists", 400)
    users_collection.insert_one({"email": user.email, "password": hash_password(user.password)})
    print(f"User signed up successfully: {user.email}")
    return success_response("Signup successful")

@app.post("/login")
async def login(user: User) -> JSONResponse:
    db_user = users_collection.find_one({"email": user.email})
    if not db_user:
        print(f"Login failed: User not found - {user.email}")
        return error_response("Invalid credentials", 401)
    if not verify_password(user.password, db_user["password"]):
        print(f"Login failed: Password mismatch for user - {user.email}")
        return error_response("Invalid credentials", 401)
    token = create_jwt({"sub": user.email})
    print(f"Login successful for user: {user.email}")
    return success_response("Login successful", {"access_token": token})

@app.post("/create-group")
async def create_group(group: Group, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    if groups_collection.find_one({"group_name": group.group_name}):
        print(f"Group creation failed: Group already exists - {group.group_name}")
        return error_response("Group already exists", 400)

    password = str(uuid4())[:8]
    groups_collection.insert_one({
        "group_name": group.group_name,
        "password": password,
        "members": [decoded_token["sub"]]
    })
    print(f"Group created: {group.group_name}, Password: {password}")
    return success_response("Group created", {"group_name": group.group_name, "password": password})

@app.post("/join-group")
async def join_group(data: JoinGroup, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    group = groups_collection.find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        print(f"Join group failed: Invalid group or password - {data.group_name}")
        return error_response("Invalid group or password", 400)

    groups_collection.update_one(
        {"group_name": data.group_name},
        {"$addToSet": {"members": decoded_token["sub"]}}
    )
    print(f"User {decoded_token['sub']} joined group: {data.group_name}")
    return success_response(f"Joined group {data.group_name} successfully")

@app.post("/upload-memory/{group_name}")
async def upload_memory(group_name: str, file: UploadFile = File(...), authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    try:
        cloudinary_response = cloudinary.uploader.upload(file.file, folder="memories/", resource_type="image")
        file_url = cloudinary_response['secure_url']
        print(f"File uploaded to Cloudinary: {file_url}")
    except Exception as e:
        print(f"Cloudinary upload failed: {e}")
        return error_response(f"Cloudinary upload failed: {str(e)}", 500)

    memories_collection.insert_one({
        "group_name": group_name,
        "url": file_url,
        "uploader": decoded_token["sub"],
    })
    print(f"Memory uploaded: {file_url} by {decoded_token['sub']}")
    return success_response("Image uploaded successfully", {"url": file_url})

@app.get("/memories/{group_name}")
async def get_memories(group_name: str, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decode_jwt(token)

    memories = list(memories_collection.find({"group_name": group_name}, {"_id": 0}))
    print(f"Fetched memories for group: {group_name}")
    return success_response("Memories fetched successfully", {"data": memories})

@app.exception_handler(Exception)
async def general_exception_handler(request, exc) -> JSONResponse:
    print(f"Unexpected error: {exc}")
    return error_response(f"An unexpected error occurred: {str(exc)}", 500)
