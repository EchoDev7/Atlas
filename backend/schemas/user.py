from pydantic import BaseModel, EmailStr, Field
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
    requires_password_change: bool = False
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    requires_password_change: bool = False


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class AdminPasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=256)


class AdminPasswordChangeResponse(BaseModel):
    success: bool
    message: str
