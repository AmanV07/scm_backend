# from bson import ObjectId
from fastapi import FastAPI, HTTPException#, Depends, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt#, JWTError
from pymongo import MongoClient
from passlib.hash import bcrypt
from datetime import date, datetime, timedelta

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
shipment_collection = db.shipments

# Secret key to sign JWT tokens
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme for JWT token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Function to create a JWT token
def create_access_token(data: dict):
    to_encode = data.copy()
    # Set token expiration time
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class UserSignUp(BaseModel):
    username: str
    email: EmailStr
    password: str
    role : str

class UserLogin(BaseModel):
    email : EmailStr
    password : str

class Shipment(BaseModel):
    shipment_no : int
    route_details : str
    device : str
    po_no : str
    ndc_no : str
    serial_no_goods : str
    container_no : str
    goods_type : str
    expected_delivery_date : datetime
    delivery_no : int
    batch_id : int
    shipment_desc : str

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

# @app.get('/user/{user_id}/role')
# async def get_user_role(user_id):
#     user_data = user_collection.find_one({'_id' : ObjectId(user_id)})
#     if user_data:
#         return {'role' : user_data['role']}
#     else:
#         raise HTTPException(404, 'User Not Found !')

@app.post('/login')
async def login(user : UserLogin):
    user_data = user_collection.find_one({'email' : user.email})
    if not user_data:
        raise HTTPException(401, 'Invalid Email or Password')
    if not verify_password(user.password, user_data['password']):
        raise HTTPException(401, 'Inval id Email or Password')
    access_token = create_access_token(data={"sub": str(user_data['_id'])})
    return {"access_token": access_token, "token_type": "bearer"}
    


@app.post('/createShipment')
async def createShipment(shipment : Shipment):
    if shipment_collection.find_one({'shipment_no' : shipment.shipment_no}):
        raise HTTPException(400, 'Shipment Number Already Exists.')
    shipment_details = shipment.dict()
    shipment_id = shipment_collection.insert_one(shipment_details).inserted_id
    return {'message' : 'Shipment created successfully !', "shipment_id": str(shipment_id)}


@app.get("/logout")
async def logout():
    return {"message": "Logout successful"}