"""Simplified cryptographic utilities for secure password hashing and data encryption"""

import os
import base64
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

logger = logging.getLogger(__name__)

# Initialize Argon2 password hasher with secure defaults
password_hasher = PasswordHasher()

def generate_rsa_keys():
    """Generate and save RSA key pair"""
    os.makedirs('keys', exist_ok=True)
    
    # Generate keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Save private key
    with open('keys/private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open('keys/public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_rsa_keys():
    """Load RSA keys, generate if missing"""
    try:
        with open('keys/private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open('keys/public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    except FileNotFoundError:
        logger.info("Generating RSA keys...")
        generate_rsa_keys()
        return load_rsa_keys()

# Load keys on import
PRIVATE_KEY, PUBLIC_KEY = load_rsa_keys()

# Password functions
def hash_password(password: str) -> str:
    """Hash password using Argon2"""
    return password_hasher.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against Argon2 hash"""
    try:
        password_hasher.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False

def needs_rehash(hashed: str) -> bool:
    """Check if password hash needs updating"""
    try:
        return password_hasher.check_needs_rehash(hashed)
    except:
        return True

# Encryption functions
def encrypt_data(data: str) -> str:
    """Encrypt small data using RSA"""
    try:
        data_bytes = data.encode('utf-8')
        if len(data_bytes) > 190:  # RSA 2048-bit limit
            logger.warning("Data too large for RSA encryption")
            return data  # Return original if too large
        
        encrypted = PUBLIC_KEY.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return data  # Return original on failure

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using RSA"""
    try:
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted = PRIVATE_KEY.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return encrypted_data  # Return original on failure