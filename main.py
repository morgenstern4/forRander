from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
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
    # Create JWT token and return it
    return {"access_token": create_jwt({"sub": user.email})}

@app.post("/create-group")
async def create_group(group: Group, token: str = Depends(decode_jwt)):
    if groups_collection.find_one({"group_name": group.group_name}):
        raise HTTPException(status_code=400, detail="Group already exists")
    groups_collection.insert_one({
        "group_name": group.group_name,
        "password": str(uuid4())[:8],
        "members": [token["sub"]]
    })
    return {"message": "Group created"}

@app.post("/join-group")
async def join_group(data: JoinGroup, token: str = Depends(decode_jwt)):
    group = groups_collection.find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        raise HTTPException(status_code=400, detail="Invalid group name or password")
    if token["sub"] not in group["members"]:
        groups_collection.update_one({"group_name": data.group_name}, {"$push": {"members": token["sub"]}})
    return {"message": "Joined group"}

@app.post("/upload-memory")
async def upload_memory(file: UploadFile = File(...), group_name: str = Form(...), uploader: str = Form(...)):
    try:
        response = requests.post("https://api.cloudinary.com/v1_1/ddjnsikcv/image/upload", files={"file": (file.filename, await file.read())})
        response.raise_for_status()
        cloudinary_url = response.json()["secure_url"]
        memories_collection.insert_one({"group_name": group_name, "uploader": uploader, "url": cloudinary_url})
        return {"message": "Memory uploaded", "url": cloudinary_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/fetch-memories/{group_name}")
async def fetch_memories(group_name: str):
    memories = [{"url": m["url"], "uploader": m["uploader"]} for m in memories_collection.find({"group_name": group_name})]
    if not memories:
        raise HTTPException(status_code=404, detail="No memories found")
    return memories
