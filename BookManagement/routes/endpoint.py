from datetime import timedelta
from fastapi import APIRouter,HTTPException,Depends,status
from typing import Annotated, List,Optional

from models.book import Book
from DatabaseConfig.db import conn
from bson import ObjectId
from fastapi.encoders import jsonable_encoder
from auth import ACCESS_TOKEN_EXPIRE_MINUTES, authtenticate_user, create_access_token, oauth2_scheme,get_current_user,User,get_password_hash,get_user,get_current_active_user,UserInDb,Token
from fastapi.security import OAuth2PasswordRequestForm

user=APIRouter()



@user.post("/signup")
async def signup(user:UserInDb):
   
    existing_user =  get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = get_password_hash(user.password)

    new_user = {
        "id":user.id,
        "username": user.username,
        "email":user.email,
        "hashed_password": hashed_password,
        
    }
    result =  conn.usersdb.users.insert_one(jsonable_encoder(new_user))
    
    response_user={
       
        "username": user.username,
        "email":user.email,
        
    }
    # Return the newly created user
    return response_user


@user.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
   
    user=authtenticate_user(form_data.username,form_data.password)
    if not user:
        raise HTTPException(
              status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token=create_access_token(
        data={"sub":user.get("username")},expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@user.post("/books",response_model=Book)
def create_book(book:Book,token:str=Depends(oauth2_scheme)):
    username=get_current_user(token)
    userdb=conn.usersdb.user.find_one({"username":username})
    credentials_exception=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentilas",
        headers={"WWW-Authenticate":"Bearer"},
    )
    if userdb is None:
        raise credentials_exception
    jsonformat=jsonable_encoder(book)
    conn.booksdb.books.insert_one(jsonformat)
    return book



@user.get("/books",response_model=List[Book])
def get_all_books(token:str=Depends(oauth2_scheme)):
    return conn.booksdb.books.find()



@user.get("/users/me/")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user



@user.get("/books/{book_id}",response_model=Book)
def get_book_by_id(book_id:int,token:str=Depends(oauth2_scheme)):
    book = conn.booksdb.books.find_one({"id": book_id})
    if book is None:
        raise HTTPException(status_code=404, detail="Book Not Found")
    return book
    
    
    
@user.put("/books/{book_id}", response_model=Book)
def update_book(book_id: int, updated_book: Book,token:str=Depends(oauth2_scheme)):
    
    book = conn.booksdb.books.find_one({"id": book_id})
    if book is None:
       raise HTTPException(status_code=404, detail="Book Not Found")
    
   
    updated_book_json = jsonable_encoder(updated_book)
    
   
    conn.booksdb.books.find_one_and_update(
        {"id": book_id}, 
        {"$set": updated_book_json}  
    )
    
    return updated_book


@user.delete("/books/{book_id}")
def delete_book(book_id:int,token:str=Depends(oauth2_scheme)):
     book = conn.booksdb.books.find_one({"id": book_id})
     
     if book is None:
         raise HTTPException(status_code=404,detail="Book Not Found")
     if book.get("quantity", 0) > 0:
    
        updated_quantity = book["quantity"] - 1
      
        conn.booksdb.books.update_one(
            {"id": book_id},
            {"$set": {"quantity": updated_quantity}}
        )
        return "Books Reduced"
    
     elif book.get("quantity", 0) == 0:
        conn.booksdb.books.delete_one({"id": book_id})
        return "Book Deleted"