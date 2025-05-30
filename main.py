# main.py

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr
from typing import List
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

# Config
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("JWT_SECRET", "secret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = MongoClient(MONGO_URI)
db = client["crm"]
users_collection = db["users"]
leads_collection = db["leads"]

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Schemas
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class LeadCreate(BaseModel):
    name: str
    address: str
    email: EmailStr
    phone_number: str
    insurance_company: str
    deductible: float
    roof_coverage: bool
    roof_age: int

class LeadOut(LeadCreate):
    category: str
    owner_email: EmailStr

# Auth Helpers
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = users_collection.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.post("/register")
def register(user: UserCreate):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user.password)
    users_collection.insert_one({"name": user.name, "email": user.email, "password": hashed_pw})
    return {"msg": "User registered"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    token = create_access_token(data={"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/leads")
def create_lead(lead: LeadCreate, current_user: dict = Depends(get_current_user)):
    category = "Warm" if lead.roof_age > 20 and lead.deductible <= 1000 else "Cold"
    leads_collection.insert_one({**lead.dict(), "category": category, "owner_email": current_user["email"]})
    return {"msg": "Lead created"}

@app.get("/leads", response_model=List[LeadOut])
def list_leads(current_user: dict = Depends(get_current_user)):
    leads = leads_collection.find({"owner_email": current_user["email"]})
    return [{**lead, "_id": str(lead["_id"])} for lead in leads]