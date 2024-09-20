from fastapi import APIRouter, HTTPException, Depends, status, File, UploadFile
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User
from app.security import get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
from pydantic import BaseModel
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import os
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader

load_dotenv()

router = APIRouter()

class UserCreate(BaseModel):
    email: str
    password: str

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_TLS=True,
    MAIL_SSL=False
)

cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("CLOUD_API_KEY"),
    api_secret=os.getenv("CLOUD_API_SECRET"),
)

async def send_verification_email(email: str, token: str):
    message = MessageSchema(
        subject="Email Verification",
        recipients=[email],
        body=f"Please verify your email by clicking on the link: http://localhost:8000/verify/{token}",
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

@router.post("/register/", response_model=UserCreate, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: Session = Depends(SessionLocal)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    verification_token = create_access_token(data={"sub": db_user.email}, expires_delta=timedelta(hours=1))
    await send_verification_email(user.email, verification_token)

    return db_user

@router.get("/verify/{token}")
async def verify_email(token: str, db: Session = Depends(SessionLocal)):
    payload = decode_token(token)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if user:
        user.is_verified = True
        db.commit()
    return {"msg": "Email verified"}

@router.put("/users/avatar/")
async def update_avatar(avatar: UploadFile = File(...), db: Session = Depends(SessionLocal)):
    upload_result = cloudinary.uploader.upload(avatar.file)
    user = db.query(User).filter(User.email == get_current_user()).first()
    user.avatar_url = upload_result['secure_url']
    db.commit()
    return {"msg": "Avatar updated", "url": user.avatar_url}
