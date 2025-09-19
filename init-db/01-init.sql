-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
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

-- Insert sample users (using MD5 hashes - VULNERABILITY: weak hashing)
INSERT INTO users (username, email, password, first_name, last_name, role) VALUES
('admin', 'admin@example.com', '0192023a7bbd73250516f069df18b500', 'Admin', 'User', 'admin'),        -- admin123
('john_doe', 'john@example.com', '482c811da5d5b4bc6d497ffa98491e38', 'John', 'Doe', 'user'),         -- password123
('jane_smith', 'jane@example.com', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'Jane', 'Smith', 'user'),      -- qwerty
('test_user', 'test@example.com', '098f6bcd4621d373cade4e832627b4f6', 'Test', 'User', 'user'),       -- test
('power_user', 'power@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'Power', 'User', 'admin'),   -- password
('moderator1', 'mod@example.com', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'Mod', 'Erator', 'moderator'), -- password
('test_admin', 'testadmin@example.com', '098f6bcd4621d373cade4e832627b4f6', 'Test', 'Admin', 'admin'); -- test

-- Insert sample products
INSERT INTO products (name, description, price, category, stock_quantity) VALUES
('Laptop', 'High-performance gaming laptop', 1299.99, 'Electronics', 10),
('Coffee Mug', 'Ceramic coffee mug', 12.99, 'Kitchen', 50),
('T-Shirt', 'Cotton t-shirt', 19.99, 'Clothing', 25),
('Book', 'Programming guide', 39.99, 'Books', 15);