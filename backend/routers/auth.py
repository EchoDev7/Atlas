from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from backend.database import get_db
from backend.models.user import Admin
from backend.schemas.user import (
    LoginRequest,
    Token,
    AdminResponse,
    AdminPasswordChangeRequest,
    AdminPasswordChangeResponse,
)
from backend.services.auth_service import verify_password, create_access_token, get_password_hash
from backend.dependencies import get_current_user
from backend.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(Admin).filter(Admin.username == login_data.username).first()
    
    if not user:
        if login_data.username == settings.ADMIN_USERNAME and login_data.password == settings.ADMIN_PASSWORD:
            hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
            user = Admin(
                username=settings.ADMIN_USERNAME,
                hashed_password=hashed_password,
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    if not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=AdminResponse)
def get_current_admin(current_user: Admin = Depends(get_current_user)):
    return current_user


@router.post("/change-password", response_model=AdminPasswordChangeResponse)
def change_admin_password(
    payload: AdminPasswordChangeRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    return {
        "success": True,
        "message": "Admin password updated successfully",
    }
