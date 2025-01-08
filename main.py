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
from pymongo.errors import ConnectionFailure
from uuid import uuid4
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import logging
import time
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    max_age=600  # Cache preflight requests for 10 minutes
)

# Database Connection Manager
class DatabaseConnection:
    _instance = None
    _client = None
    
    def __init__(self):
        self.MONGO_URI = os.getenv("MONGO_URI")
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    @contextmanager
    def get_connection(self):
        retry_count = 0
        while retry_count < self.max_retries:
            try:
                if not self._client:
                    self._client = MongoClient(
                        self.MONGO_URI,
                        serverSelectionTimeoutMS=5000,
                        connectTimeoutMS=5000,
                        socketTimeoutMS=5000
                    )
                # Test the connection
                self._client.admin.command('ping')
                yield self._client
                break
            except ConnectionFailure as e:
                retry_count += 1
                logger.error(f"MongoDB connection attempt {retry_count} failed: {e}")
                if retry_count == self.max_retries:
                    raise HTTPException(
                        status_code=503,
                        detail="Database connection failed after multiple attempts"
                    )
                time.sleep(self.retry_delay)
            finally:
                if self._client and retry_count == self.max_retries:
                    self._client.close()

# Initialize database connection
db_connection = DatabaseConnection()

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
    secure=True,
)

# Constants
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Models
class User(BaseModel):
    email: EmailStr
    password: str

class Group(BaseModel):
    group_name: str

class JoinGroup(BaseModel):
    group_name: str
    password: str

class PaginationParams(BaseModel):
    page: int = 1
    limit: int = 10

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

# Health Check
@app.get("/health")
async def health_check():
    """Endpoint to check API health."""
    try:
        with db_connection.get_connection() as client:
            client.admin.command('ping')
            return {"status": "healthy", "message": "API is running"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=str(e))

# Routes
@app.post("/signup")
async def signup(user: User) -> Dict[str, str]:
    """Endpoint for user signup."""
    try:
        with db_connection.get_connection() as client:
            db = client["demo_app"]
            users_collection = db["users"]
            if users_collection.find_one({"email": user.email}):
                raise HTTPException(status_code=400, detail="Email already exists")
            users_collection.insert_one({
                "email": user.email,
                "password": hash_password(user.password)
            })
        logger.info(f"User signed up successfully: {user.email}")
        return {"message": "Signup successful"}
    except Exception as e:
        logger.error(f"Signup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
async def login(user: User) -> Dict[str, str]:
    """Endpoint for user login."""
    try:
        with db_connection.get_connection() as client:
            db = client["demo_app"]
            users_collection = db["users"]
            db_user = users_collection.find_one({"email": user.email})
            if not db_user or not verify_password(user.password, db_user["password"]):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            logger.info(f"User logged in successfully: {user.email}")
            return {"access_token": create_jwt({"sub": user.email})}
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/create-group")
async def create_group(group: Group, authorization: str = Header(...)) -> Dict[str, str]:
    """Endpoint to create a new group."""
    try:
        token = extract_token(authorization)
        decoded_token = decode_jwt(token)
        
        with db_connection.get_connection() as client:
            db = client["demo_app"]
            groups_collection = db["groups"]
            if groups_collection.find_one({"group_name": group.group_name}):
                raise HTTPException(status_code=400, detail="Group already exists")

            password = str(uuid4())[:8]
            groups_collection.insert_one({
                "group_name": group.group_name,
                "password": password,
                "members": [decoded_token["sub"]],
                "created_at": time.time()
            })
            logger.info(f"Group created: {group.group_name} by {decoded_token['sub']}")
            return {"message": "Group created", "group_name": group.group_name, "password": password}
    except Exception as e:
        logger.error(f"Group creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/join-group")
async def join_group(data: JoinGroup, authorization: str = Header(...)) -> Dict[str, str]:
    """Endpoint to join an existing group."""
    try:
        token = extract_token(authorization)
        decoded_token = decode_jwt(token)

        with db_connection.get_connection() as client:
            db = client["demo_app"]
            groups_collection = db["groups"]
            group = groups_collection.find_one({"group_name": data.group_name})
            if not group or group["password"] != data.password:
                raise HTTPException(status_code=400, detail="Invalid group or password")

            groups_collection.update_one(
                {"group_name": data.group_name},
                {"$addToSet": {"members": decoded_token["sub"]}}
            )
            logger.info(f"User {decoded_token['sub']} joined group: {data.group_name}")
            return {"message": f"Joined group {data.group_name} successfully"}
    except Exception as e:
        logger.error(f"Join group failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload-memory/{group_name}")
async def upload_memory(
    group_name: str,
    file: UploadFile = File(...),
    authorization: str = Header(...)
) -> JSONResponse:
    """Endpoint to upload a memory (image) to Cloudinary and save the URL in the database."""
    try:
        token = extract_token(authorization)
        decoded_token = decode_jwt(token)

        # Check file size
        contents = await file.read(MAX_FILE_SIZE + 1)
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large (max 5MB)")
        
        # Reset file pointer
        await file.seek(0)

        # Upload to Cloudinary
        cloudinary_response = cloudinary.uploader.upload(
            file.file,
            folder="memories/",
            resource_type="auto"
        )
        file_url = cloudinary_response['secure_url']

        # Save to database
        with db_connection.get_connection() as client:
            db = client["demo_app"]
            memories_collection = db["memories"]
            memory_data = {
                "group_name": group_name,
                "url": file_url,
                "uploader": decoded_token["sub"],
                "uploaded_at": time.time()
            }
            memories_collection.insert_one(memory_data)

        logger.info(f"Memory uploaded successfully for group: {group_name}")
        return JSONResponse(content={"message": "Image uploaded successfully", "url": file_url})
    except Exception as e:
        logger.error(f"Memory upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/memories/{group_name}")
async def get_memories(
    group_name: str,
    authorization: str = Header(...),
    page: int = 1,
    limit: int = 10
) -> Dict[str, List[Dict[str, str]]]:
    """Endpoint to get all memories for a specific group with pagination."""
    try:
        token = extract_token(authorization)
        decoded_token = decode_jwt(token)

        with db_connection.get_connection() as client:
            db = client["demo_app"]
            memories_collection = db["memories"]
            
            # Calculate skip value for pagination
            skip = (page - 1) * limit
            
            # Get total count
            total_memories = memories_collection.count_documents({"group_name": group_name})
            
            # Get paginated memories
            memories = list(memories_collection.find({"group_name": group_name})
                          .sort("uploaded_at", -1)
                          .skip(skip)
                          .limit(limit))
            
            # Convert ObjectId to string for JSON serialization
            for memory in memories:
                memory["_id"] = str(memory["_id"])

            return {
                "data": memories,
                "page": page,
                "limit": limit,
                "total": total_memories,
                "total_pages": -(-total_memories // limit)  # Ceiling division
            }
    except Exception as e:
        logger.error(f"Fetching memories failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.exception_handler(Exception)
async def general_exception_handler(request, exc) -> JSONResponse:
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred", "details": str(exc)},
    )

# Run the application
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
