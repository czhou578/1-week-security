-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
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

-- Insert some sample data (insecure - passwords in plain text)
INSERT INTO users (username, email, password, first_name, last_name) VALUES
('admin', 'admin@example.com', 'admin123', 'Admin', 'User'),
('john_doe', 'john@example.com', 'password123', 'John', 'Doe'),
('jane_smith', 'jane@example.com', 'qwerty', 'Jane', 'Smith');

-- Insert sample products
INSERT INTO products (name, description, price, category, stock_quantity) VALUES
('Laptop', 'High-performance gaming laptop', 1299.99, 'Electronics', 10),
('Coffee Mug', 'Ceramic coffee mug', 12.99, 'Kitchen', 50),
('T-Shirt', 'Cotton t-shirt', 19.99, 'Clothing', 25),
('Book', 'Programming guide', 39.99, 'Books', 15);