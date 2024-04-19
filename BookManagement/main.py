from fastapi import FastAPI
from routes.endpoint import user
app=FastAPI()
app.include_router(user)
