from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models import Base, Contact
from pydantic import BaseModel
from datetime import date, timedelta
from app.auth import get_current_user

app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)

class ContactCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    birthday: Optional[date] = None
    additional_data: Optional[str] = None

class ContactRead(ContactCreate):
    id: int

    class Config:
        orm_mode = True

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/contacts/", response_model=ContactRead, status_code=status.HTTP_201_CREATED)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = Contact(**contact.dict(), owner_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

@app.get("/contacts/", response_model=List[ContactRead])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Contact).filter(Contact.owner_id == current_user.id).offset(skip).limit(limit).all()

@app.get("/contacts/{contact_id}", response_model=ContactRead)
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == current_user.id).first()
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

@app.put("/contacts/{contact_id}", response_model=ContactRead)
def update_contact(contact_id: int, contact: ContactCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    for key, value in contact.dict().items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

@app.delete("/contacts/{contact_id}", response_model=dict)
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return {"detail": "Contact deleted"}

@app.get("/contacts/search/", response_model=List[ContactRead])
def search_contacts(name: Optional[str] = None, email: Optional[str] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Contact).filter(Contact.owner_id == current_user.id)
    if name:
        query = query.filter((Contact.first_name.ilike(f"%{name}%")) | (Contact.last_name.ilike(f"%{name}%")))
    if email:
        query = query.filter(Contact.email.ilike(f"%{email}%"))
    return query.all()

@app.get("/contacts/birthday/soon/", response_model=List[ContactRead])
def get_contacts_birthday_soon(days: int = 7, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    today = date.today()
    upcoming_birthday = today + timedelta(days=days)
    contacts = db.query(Contact).filter(Contact.birthday.between(today, upcoming_birthday), Contact.owner_id == current_user.id).all()
    return contacts
