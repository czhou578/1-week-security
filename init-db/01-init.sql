-- Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email TEXT NOT NULL, -- TEXT to store encrypted data
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    stock_quantity INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create utility functions for encrypted email operations
CREATE OR REPLACE FUNCTION encrypt_email(email_text TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_encrypt(email_text, 'email_encryption_key_2024');
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION decrypt_email(encrypted_email TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_email, 'email_encryption_key_2024');
EXCEPTION
    WHEN OTHERS THEN
        RETURN encrypted_email; -- Return original if decryption fails
END;
$$ LANGUAGE plpgsql;

-- Insert sample users with encrypted emails
INSERT INTO users (username, email, password, first_name, last_name, role) VALUES
('admin', encrypt_email('admin@example.com'), '0192023a7bbd73250516f069df18b500', 'Admin', 'User', 'admin'),
('john_doe', encrypt_email('john@example.com'), '482c811da5d5b4bc6d497ffa98491e38', 'John', 'Doe', 'user'),
('jane_smith', encrypt_email('jane@example.com'), 'd8578edf8458ce06fbc5bb76a58c5ca4', 'Jane', 'Smith', 'user'),
('test_user', encrypt_email('test@example.com'), '098f6bcd4621d373cade4e832627b4f6', 'Test', 'User', 'user');

-- Insert sample products
INSERT INTO products (name, description, price, category, stock_quantity) VALUES
('Laptop', 'High-performance gaming laptop', 1299.99, 'Electronics', 10),
('Coffee Mug', 'Ceramic coffee mug', 12.99, 'Kitchen', 50),
('T-Shirt', 'Cotton t-shirt', 19.99, 'Clothing', 25),
('Book', 'Programming guide', 39.99, 'Books', 15);