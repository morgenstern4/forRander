from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient
from uuid import uuid4
import os
import requests
from dotenv import load_dotenv

# FastAPI instance
app = FastAPI()

# Load environment variables for Cloudinary
load_dotenv()

# Cloudinary Configuration
CLOUDINARY_URL = os.getenv("CLOUDINARY_URL=cloudinary://457627976654174:nJKtU6wRmT9zy3rK4bfegWHfA18@ddjnsikcv")
CLOUDINARY_UPLOAD_URL = f"{CLOUDINARY_URL}/image/upload"

# MongoDB connection setup
MONGO_URI = "mongodb+srv://userForAPI:ABCDef123@mongoyoutube.7o7fj.mongodb.net/?retryWrites=true&w=majority&appName=MongoYoutube"  # Replace with your MongoDB connection string
client = MongoClient(MONGO_URI)
db = client["demo_app"]
users_collection = db["users"]
groups_collection = db["groups"]
memories_collection = db["memories"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = "e1f5d5a93f5e45c4b3c9bfec2af4e5ab59f3df2f1edc4f9f8c7c9a7e7b2d5e3f"  # Replace with a strong secret key
ALGORITHM = "HS256"

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
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_jwt(data: dict) -> str:
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.post("/signup")
async def signup(user: User):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = hash_password(user.password)
    users_collection.insert_one({"email": user.email, "password": hashed_password})
    return {"message": "Signup successful"}

@app.post("/login")
async def login(user: User):
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt({"sub": user.email})
    return {"access_token": token}

@app.post("/create-group")
async def create_group(group: Group, token: str = Depends(decode_jwt)):
    group_name = group.group_name
    group_password = str(uuid4())[:8]  # Auto-generate password
    
    if groups_collection.find_one({"group_name": group_name}):
        raise HTTPException(status_code=400, detail="Group already exists")
    
    groups_collection.insert_one({
        "group_name": group_name,
        "password": group_password,
        "members": [token["sub"]]
    })
    return {"message": "Group created", "password": group_password}

@app.post("/join-group")
async def join_group(data: JoinGroup, token: str = Depends(decode_jwt)):
    group = groups_collection.find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        raise HTTPException(status_code=400, detail="Invalid group name or password")
    
    if token["sub"] not in group["members"]:
        groups_collection.update_one(
            {"group_name": data.group_name},
            {"$push": {"members": token["sub"]}}
        )
    return {"message": "Joined group"}

@app.post("/upload-memory")
async def upload_memory(
    file: UploadFile = File(...), group_name: str = Form(...), uploader: str = Form(...)
):
    try:
        # Upload the file to Cloudinary
        files = {"file": (file.filename, await file.read())}
        response = requests.post(CLOUDINARY_UPLOAD_URL, files=files)
        response.raise_for_status()

        # Retrieve the Cloudinary URL
        cloudinary_url = response.json()["secure_url"]

        # Save the metadata to MongoDB
        memories_collection.insert_one({
            "group_name": group_name,
            "uploader": uploader,
            "url": cloudinary_url,
            "filename": file.filename
        })

        return {"message": "Memory uploaded successfully", "url": cloudinary_url}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/fetch-memories/{group_name}")
async def fetch_memories(group_name: str):
    memories = memories_collection.find({"group_name": group_name})
    return [
        {"url": memory["url"], "uploader": memory["uploader"], "filename": memory["filename"]}
        for memory in memories
    ]
