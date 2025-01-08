import os
from fastapi import FastAPI, HTTPException, File, UploadFile, Depends
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import logging
import motor.motor_asyncio

# Load environment variables from .env file
load_dotenv()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB and Cloudinary settings
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB max file size

# Initialize Cloudinary
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

# Initialize MongoDB client and specify the database
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client["MongoYoutube"]  # Replace with the actual database name

app = FastAPI()

# OAuth2PasswordBearer for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class User(BaseModel):
    username: str
    email: str

class Group(BaseModel):
    name: str
    password: str


# Utility functions for JWT
def create_jwt(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Endpoint to authenticate the user and return a JWT token
@app.post("/token")
async def login(user: User):
    # This is a simplified login method, replace with actual authentication
    user_data = {"sub": user.username}
    token = create_jwt(user_data)
    return {"access_token": token, "token_type": "bearer"}


# Helper function to get the current user from the token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    return decode_jwt(token)


# Endpoint to create a group
@app.post("/groups/") 
async def create_group(group: Group, current_user: dict = Depends(get_current_user)):
    group_data = {"name": group.name, "password": group.password, "created_by": current_user["sub"]}
    group_collection = db.groups
    existing_group = await group_collection.find_one({"name": group.name})
    if existing_group:
        raise HTTPException(status_code=400, detail="Group already exists")
    
    await group_collection.insert_one(group_data)
    return {"message": "Group created successfully"}


# Endpoint to upload a memory (photo/video)
@app.post("/memories/")
async def upload_memory(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    # Check file size
    contents = await file.read(MAX_FILE_SIZE + 1)
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 5MB)")
    await file.seek(0)

    # Upload to Cloudinary
    try:
        result = cloudinary.uploader.upload(file.file)
        return {"url": result["secure_url"]}
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload to Cloudinary")


# Additional route to get group details
@app.get("/groups/{group_name}")
async def get_group(group_name: str):
    group_collection = db.groups
    group = await group_collection.find_one({"name": group_name})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


# General error handler for unexpected exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request, exc) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred", "details": str(exc)},
    )

# Root endpoint for health check
@app.get("/")
async def root():
    return {"message": "API is working!"}
