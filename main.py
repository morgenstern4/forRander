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

import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

Future<void> uploadMemory(File file, String groupName, String token) async {
  try {
    var uri = Uri.parse('http://localhost:8000/upload-memory/$groupName');
    var request = http.MultipartRequest('POST', uri)
      ..headers['Authorization'] = 'Bearer $token';

    // Read the file content
    var fileBytes = await file.readAsBytes();

    // Attach the file
    var multipartFile = http.MultipartFile.fromBytes(
      'file',
      fileBytes,
      filename: file.uri.pathSegments.last,
      contentType: MediaType('image', 'jpeg'), // or appropriate type for your file
    );
    
    request.files.add(multipartFile);

    var response = await request.send();
    
    if (response.statusCode == 200) {
      print("Upload successful!");
    } else {
      print("Upload failed with status code: ${response.statusCode}");
    }
  } catch (e) {
    print("Error uploading image: $e");
  }
}


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
