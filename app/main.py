"""The main file for a Python Insecure App."""

import requests
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jinja2 import Template
from sqlalchemy import create_engine, text
import os
import jwt
import hashlib
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional, List
from functools import wraps
from enum import Enum

from app import config

app = FastAPI(
    title="Try Hack Me",
    description="A sample project that will be hacked soon.",
    version="0.0.1337",
    debug=config.DEBUG,
)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:password123@localhost:5432/insecure_app")
engine = create_engine(DATABASE_URL)

# VULNERABILITY: Weak JWT secret
JWT_SECRET = "weak123"  # Should be complex and from environment
JWT_ALGORITHM = "HS256"

def load_keys():
    try:
        with open('app/keys/private_key.pem', 'r') as f:
            private_key = f.read()
        with open('app/keys/public_key.pem', 'r') as f:
            public_key = f.read()
        
        return private_key, public_key
    except FileNotFoundError:
        return None, None

PRIVATE_KEY, PUBLIC_KEY = load_keys()
JWT_ALGORITHM = "RS256" if PRIVATE_KEY else "HS256"

# Security setup
security = HTTPBearer(auto_error=False)

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = "user"  # Default role

    def validate_role(cls, v):
        if v not in ["user", "moderator", "admin"]:
            raise ValueError("Invalid role")
        return v    

class UserUpdate(BaseModel):
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"

def hash_password(password: str) -> str:
    """VULNERABILITY: Weak hashing - just MD5, no salt"""
    return hashlib.md5(password.encode()).hexdigest()

def create_jwt_token(user_data: dict) -> str:
    """VULNERABILITY: No expiration, weak secret"""
    # No expiration date - tokens never expire!
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "role": user_data["role"],
        "iat": datetime.utcnow()
        # Missing 'exp' field - no expiration!
    }

    if PRIVATE_KEY:
        token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    else:
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return token

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """VULNERABILITY: No rate limiting, weak validation"""
    if not credentials:
        raise HTTPException(status_code=401, detail="No token provided")
    
    try:
        # VULNERABILITY: No expiration check because tokens don't expire

        token = credentials.credentials

        if PRIVATE_KEY:
            payload = jwt.decode(token, PRIVATE_KEY, algorithms=["RS256"])
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]) 

        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token_data: dict = Depends(verify_token)) -> dict:
    """Get current user from token - no additional validation"""
    return token_data

def require_roles(allowed_roles: List[str]):
    def role_checker(curr_user: dict = Depends(get_current_user)) -> dict:
        user_role = curr_user.get("role", "user")

        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied"
            )
        
        return curr_user
    
    return role_checker

def require_admin_self(user_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") == "admin": return current_user

    if str(current_user.get("user_id")) == str(user_id):
        return current_user

    raise HTTPException(
        status_code=403,
        detail="Access denied"
    )    

def require_admin_or_owner(resource_id: int, curr_user: dict = Depends(get_current_user)) -> dict:
    if curr_user.get("role") == "admin": return curr_user

    if curr_user.get("user_id") == resource_id: return curr_user

    raise HTTPException(
        status_code=403,
        detail="Access denied"
    )

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """VULNERABILITY: Weak admin check - easily bypassed"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@app.get("/", response_class=HTMLResponse)
async def try_hack_me(name: str = config.SUPER_SECRET_NAME):
    """
    Root endpoint that greets the user and provides a random text.

    Args:
        name (str, optional): Name of the user. Defaults to SUPER_SECRET_NAME.

    Returns:
        str: HTML content with a greeting and a random text.
    """
    try:
        # Get the public IP address from an external service
        public_ip_response = requests.get(config.PUBLIC_IP_SERVICE_URL)
        public_ip_response.raise_for_status()
    except (requests.HTTPError, requests.exceptions.InvalidSchema):
        public_ip = "Unknown"
    else:
        public_ip = public_ip_response.text
    name = name or config.SUPER_SECRET_NAME
    content = f"<h1>Hello, {name}!</h1><h2>Public IP: <code>{public_ip}</code></h2>"
    # FIXME: https://fastapi.tiangolo.com/advanced/custom-response/#return-a-response
    return Template(content).render()


@app.post("/register")
async def register(user: UserCreate):
    """Register new user - VULNERABILITY: No input validation, weak password hashing"""
    try:
        with engine.connect() as connection:
            # VULNERABILITY: No password strength requirements
            hashed_password = hash_password(user.password)
            
            # VULNERABILITY: SQL injection via direct string concatenation
            query = f"""
                INSERT INTO users (username, email, password, first_name, last_name, role) 
                VALUES ('{user.username}', '{user.email}', '{hashed_password}', 
                        '{user.first_name}', '{user.last_name}', '{user.role}')
                RETURNING id, username, email, first_name, last_name, role
            """
            
            result = connection.execute(text(query))
            connection.commit()
            row = result.fetchone()
            
            if row:
                return {
                    "message": "User registered successfully",
                    "user": {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "first_name": row[3],
                        "last_name": row[4],
                        "role": row[5]
                    }
                }
    except Exception as e:
        return {"error": str(e)}

@app.post("/login")
async def login(login_data: LoginRequest):
    """Login endpoint - VULNERABILITY: No rate limiting, plaintext password comparison"""
    try:
        with engine.connect() as connection:
            # VULNERABILITY: SQL injection
            query = f"SELECT id, username, email, first_name, last_name, password, role FROM users WHERE username = '{login_data.username}'"
            result = connection.execute(text(query))
            row = result.fetchone()
            
            if row:
                stored_password = row[5]
                input_password_hash = hash_password(login_data.password)
                
                # VULNERABILITY: Timing attack possible
                if stored_password == input_password_hash:
                    user_data = {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "first_name": row[3],
                        "last_name": row[4],
                        "role": row[6] if row[6] else "user"
                    }
                    
                    token = create_jwt_token(user_data)
                    
                    return {
                        "message": "Login successful",
                        "token": token,
                        "user": user_data
                    }
                else:
                    # VULNERABILITY: Information disclosure
                    return {"error": "Invalid password for user: " + login_data.username}
            else:
                # VULNERABILITY: Information disclosure
                return {"error": "User not found: " + login_data.username}
                
    except Exception as e:
        return {"error": str(e)}

@app.get("/users")
async def get_users(username: str = None, current_user: dict = Depends(require_roles["admin"])):
    """Get users - VULNERABILITY: SQL injection, no proper access control"""
    try:
        with engine.connect() as connection:
            if username:
                # VULNERABLE: Direct string concatenation - SQL injection risk
                query = f"SELECT id, username, email, first_name, last_name, role FROM users WHERE username = '{username}'"
            else:
                query = "SELECT id, username, email, first_name, last_name, role FROM users"

            # Execute raw SQL without parameterization
            result = connection.execute(text(query))
            users = []
            for row in result:
                users.append(
                    {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "first_name": row[3],
                        "last_name": row[4],
                        "role": row[5]
                    }
                )

            return {"users": users}

    except Exception as e:
        return {"error": str(e)}


@app.get("/user/{user_id}")
async def get_user_by_id(user_id: str, current_user: dict = Depends(require_admin_self)):
    """VULNERABILITY: IDOR - can access any user by incrementing ID, no authorization check"""
    try:
        with engine.connect() as connection:
            # VULNERABLE: Direct string concatenation + IDOR
            query = f"SELECT id, username, email, first_name, last_name, password, role FROM users WHERE id = {user_id}"
            result = connection.execute(text(query))
            row = result.fetchone()

            if row:
                # VULNERABILITY: No check if current user should access this data
                return {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "first_name": row[3],
                    "last_name": row[4],
                    "password": row[5],  # Exposing password hash
                    "role": row[6],
                    "accessed_by": current_user["username"]  # Shows who accessed it
                }
            else:
                return {"error": "User not found"}

    except Exception as e:
        return {"error": str(e)}

@app.put("/user/{user_id}")
async def update_user(user_id: str, user_update: UserUpdate, current_user: dict = Depends(require_admin_self)):
    """VULNERABILITY: IDOR - can update any user by ID, no authorization check"""
    try:
        with engine.connect() as connection:
            # Build update query dynamically (more SQL injection opportunities)
            updates = []
            if user_update.email:
                updates.append(f"email = '{user_update.email}'")
            if user_update.first_name:
                updates.append(f"first_name = '{user_update.first_name}'")
            if user_update.last_name:
                updates.append(f"last_name = '{user_update.last_name}'")
            if user_update.role:
                # VULNERABILITY: Any authenticated user can change roles!
                updates.append(f"role = '{user_update.role}'")
            
            if not updates:
                return {"error": "No fields to update"}
            
            # VULNERABLE: SQL injection + IDOR
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = {user_id} RETURNING id, username, email, first_name, last_name, role"
            result = connection.execute(text(query))
            connection.commit()
            row = result.fetchone()
            
            if row:
                return {
                    "message": f"User {user_id} updated by {current_user['username']}",
                    "user": {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "first_name": row[3],
                        "last_name": row[4],
                        "role": row[5]
                    }
                }
            else:
                return {"error": "User not found"}
                
    except Exception as e:
        return {"error": str(e)}

@app.delete("/user/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """VULNERABILITY: IDOR - can delete any user, minimal access control"""
    try:
        with engine.connect() as connection:
            # VULNERABILITY: No check if user should be able to delete this account
            query = f"DELETE FROM users WHERE id = {user_id} RETURNING username"
            result = connection.execute(text(query))
            connection.commit()
            row = result.fetchone()
            
            if row:
                return {
                    "message": f"User {row[0]} (ID: {user_id}) deleted by {current_user['username']}"
                }
            else:
                return {"error": "User not found"}
                
    except Exception as e:
        return {"error": str(e)}

@app.get("/admin/users")
async def admin_get_all_users(admin_user: dict = Depends(require_admin)):
    """Admin endpoint - but IDOR still possible via other endpoints"""
    try:
        with engine.connect() as connection:
            # Even admin endpoint is vulnerable to SQL injection
            query = "SELECT id, username, email, first_name, last_name, role, password FROM users ORDER BY id"
            result = connection.execute(text(query))
            users = []
            for row in result:
                users.append({
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "first_name": row[3],
                    "last_name": row[4],
                    "role": row[5],
                    "password_hash": row[6]  # Exposing password hashes
                })
            
            return {
                "message": f"All users retrieved by admin: {admin_user['username']}",
                "users": users,
                "total_count": len(users)
            }
            
    except Exception as e:
        return {"error": str(e)}

@app.post("/admin/promote/{user_id}")
async def promote_user_to_admin(user_id: str, admin_user: dict = Depends(require_admin)):
    """VULNERABILITY: IDOR + SQL injection even in admin endpoint"""
    try:
        with engine.connect() as connection:
            # VULNERABLE: Direct string concatenation
            query = f"UPDATE users SET role = 'admin' WHERE id = {user_id} RETURNING username, role"
            result = connection.execute(text(query))
            connection.commit()
            row = result.fetchone()
            
            if row:
                return {
                    "message": f"User {row[0]} promoted to {row[1]} by admin {admin_user['username']}"
                }
            else:
                return {"error": "User not found"}
                
    except Exception as e:
        return {"error": str(e)}

@app.get("/profile")
async def get_own_profile(current_user: dict = Depends(get_current_user)):
    """Get current user's profile - but tokens never expire!"""
    try:
        with engine.connect() as connection:
            # Even this has SQL injection
            query = f"SELECT id, username, email, first_name, last_name, role FROM users WHERE id = {current_user['user_id']}"
            result = connection.execute(text(query))
            row = result.fetchone()
            
            if row:
                return {
                    "profile": {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "first_name": row[3],
                        "last_name": row[4],
                        "role": row[5]
                    },
                    "token_info": {
                        "user_id": current_user["user_id"],
                        "issued_at": current_user.get("iat"),
                        "expires": "Never! (Security vulnerability)"
                    }
                }
            else:
                return {"error": "Profile not found"}
                
    except Exception as e:
        return {"error": str(e)}
    
