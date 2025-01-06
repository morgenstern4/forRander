from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from pymongo import MongoClient
from uuid import uuid4
import os
import requests
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO)

# FastAPI instance
app = FastAPI()

# Cloudinary Configuration
CLOUDINARY_URL = os.getenv("CLOUDINARY_URL", "https://default.cloudinary.url")
CLOUDINARY_UPLOAD_URL = f"{CLOUDINARY_URL}/image/upload"

# MongoDB connection setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client["demo_app"]
users_collection = db["users"]
groups_collection = db["groups"]
memories_collection = db["memories"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Log missing variables
if not SECRET_KEY or not CLOUDINARY_URL or not MONGO_URI:
    logging.error("Critical environment variables missing. Check your configuration.")

# Models and utility functions remain unchanged...

# Uvicorn Configuration for Render Hosting
if __name__ == "__main__":
    logging.info("Starting the FastAPI application...")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
