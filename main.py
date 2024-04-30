from bson import ObjectId
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from passlib.hash import bcrypt

app = FastAPI()

# Define the list of allowed origins
origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:9000"  # Add the port used by your frontend
]

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

client = MongoClient('localhost', 27017)
db = client['SCM_APP']
user_collection = db.users

class UserSignUp(BaseModel):
    username: str
    email: EmailStr
    password: str
    role : str

class UserLogin(BaseModel):
    email : EmailStr
    password : str

def hash_password(plain_password : str) -> str:
    return bcrypt.hash(plain_password)

def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)

@app.post('/signup')
async def signup(user : UserSignUp):
    if user_collection.find_one({'email' : user.email}):
        raise HTTPException(400, detail='Email Already Registered !')
    hashed_password = hash_password(user.password)
    user_details = {
        'username' : user.username,
        'email' : user.email,
        'password' : hashed_password,
        'role' : user.role
    }
    user_id = user_collection.insert_one(user_details).inserted_id
    return {'message' : 'User Registered Successfully !', "user_id": str(user_id)}


@app.get('/user/{user_id}/role')
async def get_user_role(user_id):
    user_data = user_collection.find_one({'_id' : ObjectId(user_id)})
    if user_data:
        return {'role' : user_data['role']}
    else:
        raise HTTPException(404, 'User Not Found !')


@app.post('/login')
async def login(user : UserLogin):
    user_data = user_collection.find_one({'email' : user.email})
    if not user_data:
        raise HTTPException(401, 'Invalid Email or Password')
    if not verify_password(user.password, user_data['password']):
        raise HTTPException(401, 'Invalid Email or Password')
    return {"message" : "User Signed In Successfully !", "user_id" : str(user_data['_id']), "role" : user_data['role']}


@app.get("/logout")
async def logout():
    # Your logout logic here, such as clearing session data or invalidating tokens
    # For example, if using sessions, you can clear session data like this:
    # session.clear()  # Make sure to import session from your session management library
    
    # In this example, just return a simple message
    return {"message": "Logout successful"}