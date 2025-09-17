import React, { useState } from 'react';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');

    // VULNERABILITY: Hardcoded API key in frontend code
    const API_KEY = 'sk-1234567890abcdef-SUPER-SECRET-KEY';

    const handleLogin = async (e) => {
        e.preventDefault();

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY // VULNERABILITY: Exposing API key
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (data.token) {
                // VULNERABILITY: Storing sensitive token in localStorage (not HttpOnly)
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userInfo', JSON.stringify(data.user));
                setMessage('Login successful!');
            } else {
                setMessage(data.error || 'Login failed');
            }
        } catch (error) {
            setMessage('Network error: ' + error.message);
        }
    };

    return (
        <div style={{ padding: '20px', maxWidth: '400px' }}>
            <h2>Login</h2>
            <form onSubmit={handleLogin}>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        style={{ width: '100%', padding: '8px' }}
                    />
                </div>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{ width: '100%', padding: '8px' }}
                    />
                </div>
                <button type="submit" style={{ width: '100%', padding: '10px' }}>
                    Login
                </button>
            </form>

            {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with user input */}
            {message && (
                <div
                    style={{ marginTop: '10px', color: 'red' }}
                    dangerouslySetInnerHTML={{ __html: message }}
                />
            )}
        </div>
    );
};

export default Login;