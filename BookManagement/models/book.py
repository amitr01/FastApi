from pydantic import BaseModel
from typing import List,Optional

class Book(BaseModel):
    id:int
    title:str
    author:str
    genre:Optional[str]=None
    quantity:int
