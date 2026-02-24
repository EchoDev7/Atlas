from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional


class AdminBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None


class AdminCreate(AdminBase):
    password: str


class AdminResponse(AdminBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str
