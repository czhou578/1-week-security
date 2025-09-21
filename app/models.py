from pydantic import BaseModel, validator
from typing import Optional
import re
from enum import Enum


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

    @validator('username')
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('username cannot be empty')
        if len(v) > 50:
            raise ValueError('username too long')
        
        if re.search(r"[';\"\\-]", v):
            raise ValueError('Username contains invalid characters')
        return v.strip()
    
    @validator('password')
    def validate_password(cls, v):
        if not v or len(v) < 1:
            raise ValueError("password can't be empty")
        
        if len(v) > 200:
            raise ValueError('password too long')
    

class UserCreate(BaseModel):
    username: str
    email: str  # We'll validate this manually since EmailStr requires extra deps
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = "user"
    
    @validator('username')
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Username is required')
        if len(v) > 50:
            raise ValueError('Username too long (max 50 characters)')
        if len(v) < 3:
            raise ValueError('Username too short (min 3 characters)')
        # Allow only alphanumeric and underscore
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscore')
        return v.strip().lower()
    
    @validator('email')
    def validate_email(cls, v):
        if not v:
            raise ValueError('Email is required')
        if len(v) > 100:
            raise ValueError('Email too long')
        # Basic email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        return v.strip().lower()
    
    @validator('password')
    def validate_password(cls, v):
        if not v:
            raise ValueError('Password is required')
        if len(v) < 6:
            raise ValueError('Password too short (min 6 characters)')
        if len(v) > 200:
            raise ValueError('Password too long')
        # Basic password strength
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        return v
    
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v is not None:
            if len(v) > 50:
                raise ValueError('Name too long (max 50 characters)')
            # Prevent XSS and SQL injection
            if re.search(r"[<>\"'&;]", v):
                raise ValueError('Name contains invalid characters')
            return v.strip().title()
        return v
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ["user", "moderator", "admin"]
        if v not in allowed_roles:
            raise ValueError(f'Invalid role. Must be one of: {allowed_roles}')
        return v   

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"