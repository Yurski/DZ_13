from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.util import get_remote_address
from app.database import engine, Base
from app import auth

app = FastAPI()

# Створення database таблиць
Base.metadata.create_all(bind=engine)

# CORS конфігурація
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await FastAPILimiter.init(RateLimiterMiddleware, redis=REDIS_URL)

@app.include_router(auth.router)
