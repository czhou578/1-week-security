"""The main file for a Python Insecure App."""

import requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jinja2 import Template
from sqlalchemy import create_engine, text
import os
import jwt
import hashlib
from datetime import datetime
from typing import List
from functools import wraps
import config
import logging
from crypto_utils import hash_password, encrypt_data, decrypt_data
from pathlib import Path
from models import UserCreate, UserRole, LoginRequest

app = FastAPI(
    title="Try Hack Me",
    description="A sample project that will be hacked soon.",
    version="0.0.1337",
    debug=config.DEBUG,
)

def get_cors_origins():
    """Get CORS origins based on environment"""
    if config.DEBUG:
        # Development - more permissive
        return [
            "http://localhost:3000",
            "http://localhost:8000", 
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
            "http://localhost:1337"
        ]
    else:
        # Production - strict origins only
        allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
        # Remove empty strings
        return [origin.strip() for origin in allowed_origins if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origina=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-CSRF-Token",
        "X-Requested-With"
    ],
    expose_headers=["X-Total-Count"],
    max_age=600
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

def read_secret(secret_name: str, fallback: str = None) -> str:
    """Read secret from file or return fallback"""
    try:
        # Try Docker secrets first (/run/secrets/)
        docker_secret_path = Path(f"/run/secrets/{secret_name}")
        if docker_secret_path.exists():
            return docker_secret_path.read_text().strip()
        
        # Try local secrets folder (remove .txt extension assumption)
        local_secret_path = Path(f"secrets/{secret_name}.txt")
        if local_secret_path.exists():
            return local_secret_path.read_text().strip()
            
    except Exception as e:
        logger.warning(f"Failed to read secret '{secret_name}': {e}")
    
    # Return fallback or raise error
    if fallback is not None:
        return fallback
    raise ValueError(f"Secret '{secret_name}' not found and no fallback provided")

def build_database_url() -> str:
    """Build database URL from secrets"""
    try:
        # Read database credentials from secrets
        db_user = read_secret("db_user", "admin")
        db_password = read_secret("db_password", "password123")  
        db_host = read_secret("db_host", "db")        # Default to 'db' service name
        db_port = read_secret("db_port", "5432")
        db_name = read_secret("db_name", "insecure_app")
        
        # Build URL
        database_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        
        # Log connection (without password)
        logger.info(f"Database: postgresql://{db_user}:***@{db_host}:{db_port}/{db_name}")
        
        return database_url
        
    except Exception as e:
        logger.error(f"Failed to build database URL from secrets: {e}")
        # Fallback with Docker service name (NOT localhost)
        return "postgresql://admin:password123@db:5432/insecure_app"

# Database setup
try:
    DATABASE_URL = build_database_url()
    logger.info("Using database credentials from secrets")
except Exception as e:
    logger.error(f"Failed to load database secrets: {e}")
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:password123@localhost:5432/insecure_app")
    logger.warning("Using fallback database URL")
    
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

def generate_csrf_token():
    """
    Generate csrf token
    """

    timestamp = str(int(datetime.now().timestamp()))
    secret = "csrf"
    token = hashlib.md5(f"{timestamp}{secret}".encode()).hexdigest()

    return token

def verify_csrf_token(token: str):
    if not token: return False

    if len(token) == 32: return True

    return False

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

@app.get("/csrf-token")
async def get_csrf_token():
    """Get CSRF Token"""

    token = generate_csrf_token()

    return {
        "csrf_token": token,
        "expires": "never",  # VULNERABILITY: Tokens don't expire
        "algorithm": "md5"   # VULNERABILITY: Exposing algorithm
    }

@app.post("/register")
async def register(user: UserCreate):
    """Register new user - VULNERABILITY: No input validation, weak password hashing"""
    try:
        with engine.connect() as connection:
            # VULNERABILITY: No password strength requirements
            hashed_password = hash_password(user.password)

            encrypted_email = encrypt_data(user.email)

            if not encrypted_email:
                logger.warning("Failed to encrypt email")
                encrypted_email = user.email
            else:
                logger.info(f"email encrypted for user")
            
            # VULNERABILITY: SQL injection via direct string concatenation
            query = f"""
                INSERT INTO users (username, email, password, first_name, last_name, role) 
                VALUES ('{user.username}', encrypt_email('{user.email}'), '{hashed_password}', 
                        '{user.first_name}', '{user.last_name}', '{user.role}')
                RETURNING id, username, decrypt_email(email) as email, first_name, last_name, role
            """
            
            result = connection.execute(text(query))
            connection.commit()
            row = result.fetchone()
            
            if row:
                stored_email = row[2]
                decrypted_email = decrypt_data(stored_email)
                display_email = decrypted_email if decrypted_email else stored_email

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
async def login(login_data: LoginRequest, x_csrf_token: str = Header(None, alias="X-CSRF-Token")):
    """Login endpoint - VULNERABILITY: No rate limiting, plaintext password comparison"""

    if not x_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="No CSRF Token was provided."
        )

    try:
        with engine.connect() as connection:
            # VULNERABILITY: SQL injection
            # query = f"SELECT id, username, email, first_name, last_name, password, role FROM users WHERE username = '{login_data.username}'"
            
            query = text("""
                SELECT id, username, email, first_name, last_name, password, role 
                FROM users 
                WHERE username = :username
            """)            
            
            result = connection.execute(query, {"username": login_data.username})
            row = result.fetchone()
            logging.info(f'query result is {row}')
            
            if row:
                stored_password = row[5]
                if stored_password is None:
                    logging.error("Stored password is none")
                    return {"Error": "invalid credentials"}
                
                try:
                    input_password_hash = hash_password(login_data.password)
                except Exception as e:
                    logging.error(f"Password hashing error: {e}")
                    return {"error": "Authentication failed"}

                # VULNERABILITY: Timing attack possible
                if stored_password == input_password_hash:

                    # encrypted_email = row[2]
                    # decrypted_email = decrypt_data(encrypted_email)

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
async def get_users(username: str = None, current_user: dict = Depends(require_roles(["admin"]))):
    """Get users - VULNERABILITY: SQL injection, no proper access control"""
    try:
        with engine.connect() as connection:
            if username:
                # VULNERABLE: Direct string concatenation - SQL injection risk
                # query = f"SELECT id, username, email, first_name, last_name, role FROM users WHERE username = '{username}'"
                query = text("""
                            SELECT id, username, email, first_name, last_name, role FROM users WHERE username = :username
                             """)
            else:
                query = text("""SELECT id, username, email, first_name, last_name, role FROM users""")

            # Execute raw SQL without parameterization
            result = connection.execute(query, {"username": username})
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
            # query = f"SELECT id, username, email, first_name, last_name, password, role FROM users WHERE id = {user_id}"
            query = text(""" 
                        SELECT id, username, email, first_name, last_name, password, role FROM users WHERE id = :user_id
                        """)
            result = connection.execute(query)
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

@app.delete("/user/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """VULNERABILITY: IDOR - can delete any user, minimal access control"""
    try:
        with engine.connect() as connection:
            # VULNERABILITY: No check if user should be able to delete this account
            query = text("""DELETE FROM users WHERE id = :id RETURNING username""")
            result = connection.execute(query, {id: user_id})
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
    """Admin promote user with parameterized query"""
    try:
        with engine.connect() as connection:
            # SECURE: Parameterized query prevents SQL injection
            query = text("""
                UPDATE users SET role = 'admin' 
                WHERE id = :user_id 
                RETURNING username, role
            """)
            
            result = connection.execute(query, {"user_id": user_id})
            connection.commit()
            row = result.fetchone()
            
            if row:
                return {
                    "message": f"User {row[0]} promoted to {row[1]} by admin {admin_user['username']}"
                }
            else:
                return {"error": "User not found"}
                
    except Exception as e:
        logger.error(f"Promotion error: {e}")
        return {"error": "Failed to promote user"}

@app.get("/profile")
async def get_own_profile(current_user: dict = Depends(get_current_user)):
    """Get current user's profile - but tokens never expire!"""
    try:
        with engine.connect() as connection:
            # Even this has SQL injection
            query = f"SELECT id, username, email, first_name, last_name, role FROM users WHERE id = {current_user['user_id']}"
            query = text(""" 
                        SELECT id, username, email, first_name, last_name, role FROM users WHERE id = :id
                    """)
            result = connection.execute(query, {id: current_user["user_id"]})
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
    
