-- Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Read secrets for app_user creation
DO $$ 
DECLARE
    app_password TEXT;
BEGIN
    -- Try to read password from Docker secret, fallback to default
    BEGIN
        SELECT pg_read_file('/run/secrets/app_db_password') INTO app_password;
        app_password := trim(app_password);
    EXCEPTION WHEN OTHERS THEN
        app_password := 'app_password_2024';
    END;
    
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        EXECUTE format('CREATE ROLE app_user WITH LOGIN PASSWORD %L', app_password);
    END IF;
END $$;

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

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM users 
        WHERE username = CURRENT_USER AND role = 'admin'
    );
END;
$$ LANGUAGE plpgsql;

CREATE POLICY user_isolation_policy ON users
    FOR ALL
    TO app_user
    USING (
        username = CURRENT_USER OR 
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.username = CURRENT_USER AND u.role = 'admin'
        )
    );

CREATE POLICY admin_full_access_users on users
    For ALL 
    TO app_user
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.username = CURRENT_USER AND u.role = 'admin'
        )
    );

CREATE POLICY products_read_policy ON products
    FOR SELECT
    TO app_user
    USING (true);

GRANT SELECT, INSERT, UPDATE ON users TO app_user;

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
('johndoe', encrypt_email('john@example.com'), '482c811da5d5b4bc6d497ffa98491e38', 'John', 'Doe', 'user'),
('jane_smith', encrypt_email('jane@example.com'), 'd8578edf8458ce06fbc5bb76a58c5ca4', 'Jane', 'Smith', 'user'),
('test_user', encrypt_email('test@example.com'), '098f6bcd4621d373cade4e832627b4f6', 'Test', 'User', 'user');

-- Insert sample products
INSERT INTO products (name, description, price, category, stock_quantity) VALUES
('Laptop', 'High-performance gaming laptop', 1299.99, 'Electronics', 10),
('Coffee Mug', 'Ceramic coffee mug', 12.99, 'Kitchen', 50),
('T-Shirt', 'Cotton t-shirt', 19.99, 'Clothing', 25),
('Book', 'Programming guide', 39.99, 'Books', 15);

REVOKE CREATE ON SCHEMA public FROM app_user;

CREATE VIEW secure_users_view AS
SELECT 
    id,
    username,
    decrypt_email(email) as email,
    first_name,
    last_name,
    role,
    created_at
FROM users
WHERE 
    username = CURRENT_USER OR 
    is_admin();

-- Grant access to the view
GRANT SELECT ON secure_users_view TO app_user;