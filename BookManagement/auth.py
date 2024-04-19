from datetime import datetime,timedelta,timezone

from typing import Annotated,Optional
from fastapi import Depends,FastAPI,HTTPException,status,APIRouter
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import JWTError,jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from DatabaseConfig.db import conn
from pymongo.collection import Collection
import logging
from fastapi.encoders import jsonable_encoder

user=APIRouter()

SECRET_KEY="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30

logging.basicConfig(level=logging.DEBUG)


class Token(BaseModel):
    access_token:str
    token_type:str


class TokenData(BaseModel):
    username:str|None=None


class User(BaseModel):
    id:int
    username:str
    email:str
    password:str
   

class UserInDb(User):
    hashed_password:str



db=conn.usersdb
users_collection:Collection=db.users
pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")

#which url
oauth2_scheme=OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)


def get_password_hash(password:str):
    return pwd_context.hash(password)


def create_access_token(data:dict,expires_delta:Optional[timedelta]=None):
    to_encode=data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt


def get_user(username:str):
    user_data= conn.usersdb.users.find_one({"username":username})
    
    if user_data:
        response_user={
      
        "username": user_data.get("username"),
        "email":user_data.get("email"),
        
        "hashed_password":user_data.get("hashed_password")
    }
        return response_user
    return None


def authtenticate_user(username:str,password:str):
    
    user=get_user(username)
  
    if not user:
        return False
    if not verify_password(password,user.get("hashed_password")):
        return False
    return user

async def get_current_user(token:str=Depends(oauth2_scheme)):
    credentials_exception=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentilas",
        headers={"WWW-Authenticate":"Bearer"},
    )

    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username:str=payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data=TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user= get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return jsonable_encoder(user.get("username"))


async def get_current_active_user(current_user:User=Depends(get_current_user)):
    return current_user





