"""
Auth Routes — /api/auth
  POST /register   create account
  POST /login      get JWT token
  GET  /me         current user
"""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from core.auth import (
    create_access_token, get_current_user,
    hash_password, verify_password,
)
from core.config import settings
from db.database import get_db
from db.models import User

router = APIRouter()


class RegisterIn(BaseModel):
    email:        EmailStr
    username:     str
    password:     str
    company_name: str = ""


class UserOut(BaseModel):
    id:           int
    email:        str
    username:     str
    company_name: str = ""
    is_admin:     bool
    class Config: from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type:   str = "bearer"


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(400, "Username already taken")
    user = User(
        email=body.email,
        username=body.username,
        hashed_pass=hash_password(body.password),
        company_name=body.company_name,
    )
    db.add(user); db.commit(); db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_pass):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    token = create_access_token(
        {"sub": str(user.id)},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
