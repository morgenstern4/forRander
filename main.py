from fastapi import FastAPI, HTTPException, Path, Depends, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from jose import jwt, JWTError
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
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
MONGO_URI = os.getenv("MONGO_URI") or "your_mongodb_atlas_uri_here"
if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set in environment variables")
client = AsyncIOMotorClient(MONGO_URI)
db = client["budget_tracker"]  # Database name

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY") or "your_secret_key"
ALGORITHM = "HS256"

# Utilities
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_jwt(data: dict) -> str:
    try:
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        return token
    except Exception as e:
        raise HTTPException(status_code=500, detail="Token creation failed")

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def extract_token(authorization: str) -> str:
    if not authorization or " " not in authorization:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return authorization.split(" ")[1]

def success_response(message: str, data: dict = None) -> JSONResponse:
    return JSONResponse(content={"status": "success", "message": message, "data": data})

def error_response(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(content={"status": "error", "message": message}, status_code=status_code)

# Pydantic models
class Budget(BaseModel):
    category: str
    month: str  # Format: YYYY-MM
    amount: float
    spent: float

class Expense(BaseModel):
    category: str
    date: str  # Format: YYYY-MM-DD
    amount: float

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

# Utility function to convert BSON to JSON
def bson_to_json(data):
    data["_id"] = str(data["_id"])
    return data

# Routes
@app.get("/")
def read_root() -> JSONResponse:
    return success_response("API is running")

@app.post("/add-budget/{group_code}", response_model=dict)
async def add_budget(group_code: str, budget: Budget):
    budget_dict = budget.dict()
    budget_dict["group_code"] = group_code
    result = await db.budgets.insert_one(budget_dict)
    return {"id": str(result.inserted_id)}

@app.get("/get-budgets/{group_code}", response_model=List[dict])
async def get_budgets(group_code: str):
    budgets = await db.budgets.find({"group_code": group_code}).to_list(100)
    return [bson_to_json(budget) for budget in budgets]

@app.post("/add-expense/{group_code}", response_model=dict)
async def add_expense(group_code: str, expense: Expense):
    expense_dict = expense.dict()
    expense_dict["group_code"] = group_code
    result = await db.expenses.insert_one(expense_dict)
    return {"id": str(result.inserted_id)}

@app.get("/get-expenses/{group_code}", response_model=List[dict])
async def get_expenses(group_code: str):
    expenses = await db.expenses.find({"group_code": group_code}).to_list(100)
    return [bson_to_json(expense) for expense in expenses]

@app.delete("/delete-budget/{group_code}/{budget_id}", response_model=dict)
async def delete_budget(group_code: str, budget_id: str = Path(...)):
    result = await db.budgets.delete_one({"_id": ObjectId(budget_id), "group_code": group_code})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Budget not found")
    return {"message": "Budget deleted successfully"}

@app.delete("/delete-expense/{group_code}/{expense_id}", response_model=dict)
async def delete_expense(group_code: str, expense_id: str = Path(...)):
    result = await db.expenses.delete_one({"_id": ObjectId(expense_id), "group_code": group_code})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Expense not found")
    return {"message": "Expense deleted successfully"}

@app.post("/signup")
async def signup(user: User) -> JSONResponse:
    if db["users"].find_one({"email": user.email}):
        return error_response("Email already exists", 400)
    await db["users"].insert_one({"email": user.email, "password": hash_password(user.password)})
    return success_response("Signup successful")

@app.post("/login")
async def login(user: User) -> JSONResponse:
    db_user = await db["users"].find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        return error_response("Invalid credentials", 401)
    token = create_jwt({"sub": user.email})
    return success_response("Login successful", {"access_token": token})

@app.post("/create-group")
async def create_group(group: Group, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    if db["groups"].find_one({"group_name": group.group_name}):
        return error_response("Group already exists", 400)

    password = str(uuid4())[:8]
    await db["groups"].insert_one({
        "group_name": group.group_name,
        "password": password,
        "members": [decoded_token["sub"]]
    })
    return success_response("Group created", {"group_name": group.group_name, "password": password})

@app.post("/join-group")
async def join_group(data: JoinGroup, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    group = await db["groups"].find_one({"group_name": data.group_name})
    if not group or group["password"] != data.password:
        return error_response("Invalid group or password", 400)

    await db["groups"].update_one(
        {"group_name": data.group_name},
        {"$addToSet": {"members": decoded_token["sub"]}}
    )
    return success_response(f"Joined group {data.group_name} successfully")

@app.post("/upload-memory/{group_name}")
async def upload_memory(group_name: str, file: UploadFile = File(...), authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decoded_token = decode_jwt(token)

    try:
        # Cloudinary upload logic here
        cloudinary_response = "mocked_cloudinary_response"  # Replace with actual Cloudinary upload
        file_url = "mocked_file_url"  # Replace with actual file URL
    except Exception as e:
        return error_response(f"Cloudinary upload failed: {str(e)}", 500)

    await db["memories"].insert_one({
        "group_name": group_name,
        "url": file_url,
        "uploader": decoded_token["sub"],
    })
    return success_response("Image uploaded successfully", {"url": file_url})

@app.get("/memories/{group_name}")
async def get_memories(group_name: str, authorization: str = Header(...)) -> JSONResponse:
    token = extract_token(authorization)
    decode_jwt(token)

    memories = await db["memories"].find({"group_name": group_name}).to_list(100)
    return success_response("Memories fetched successfully", {"data": [bson_to_json(memory) for memory in memories]})

@app.exception_handler(Exception)
async def general_exception_handler(request, exc) -> JSONResponse:
    return error_response(f"An unexpected error occurred: {str(exc)}", 500)
