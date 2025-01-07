from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient
from uuid import uuid4
import os
import requests
from dotenv import load_dotenv

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

# Serve the uploaded files
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Routes
@app.post("/signup")
async def signup(user: User):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    users_collection.insert_one({"email": user.email, "password": hash_password(user.password)})
    return {"message": "Signup successful"}

@app.post("/login")
async def login(user: User):
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_jwt({"sub": user.email})}

@app.post("/create-group")
async def create_group(group: Group, authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        decoded_token = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if groups_collection.find_one({"group_name": group.group_name}):
        raise HTTPException(status_code=400, detail="Group already exists")

    password = str(uuid4())[:8]
    groups_collection.insert_one({
        "group_name": group.group_name,
        "password": password,
        "members": [decoded_token["sub"]]
    })
    return {"message": "Group created", "group_name": group.group_name, "password": password}

@app.post("/join-group")
async def join_group(data: JoinGroup, authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        decoded_token = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    group = groups_collection.find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        raise HTTPException(status_code=400, detail="Invalid group or password")

    groups_collection.update_one(
        {"group_name": data.group_name},
        {"$addToSet": {"members": decoded_token["sub"]}}
    )
    return {"message": f"Joined group {data.group_name} successfully"}

@app.post("/upload-memory/{group_name}")
async def upload_memory(group_name: str, file: UploadFile = File(...), authorization: str = Header(...)):
    # Authenticate user with JWT
    try:
        token = authorization.split(" ")[1]
        decoded_token = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Generate a unique filename for the image
    file_extension = file.filename.split(".")[-1]
    file_name = f"{uuid4()}.{file_extension}"
    file_path = os.path.join("uploads", file_name)

    # Ensure the directory exists
    os.makedirs("uploads", exist_ok=True)

    # Save the uploaded file
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Save the memory to the database
    memory_data = {
        "group_name": group_name,
        "url": f"/uploads/{file_name}",  # Adjust this based on how you serve static files
        "uploader": decoded_token["sub"],
    }
    memories_collection.insert_one(memory_data)

    return JSONResponse(content={"message": "Image uploaded successfully", "url": f"/uploads/{file_name}"})
