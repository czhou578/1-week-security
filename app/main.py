"""The main file for a Python Insecure App."""

import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Template
from sqlalchemy import create_engine, text
import os

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


@app.get("/users")
async def get_users(username: str = None):
    """Get users - VULNERABLE to SQL injection"""
    try:
        with engine.connect() as connection:
            if username:
                # VULNERABLE: Direct string concatenation - SQL injection risk
                query = f"SELECT id, username, email, first_name, last_name FROM users WHERE username = '{username}'"
            else:
                query = "SELECT id, username, email, first_name, last_name FROM users"

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
                    }
                )

            return {"users": users}

    except Exception as e:
        return {"error": str(e)}


@app.get("/user/{user_id}")
async def get_user_by_id(user_id: str):
    """Get user by ID - VULNERABLE to SQL injection"""
    try:
        with engine.connect() as connection:
            # VULNERABLE: Direct string concatenation
            query = f"SELECT id, username, email, first_name, last_name, password FROM users WHERE id = {user_id}"
            result = connection.execute(text(query))
            row = result.fetchone()

            if row:
                return {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "first_name": row[3],
                    "last_name": row[4],
                    "password": row[5],  # Exposing password - another vulnerability
                }
            else:
                return {"error": "User not found"}

    except Exception as e:
        return {"error": str(e)}
