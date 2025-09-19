import React, { useEffect, useState } from 'react';
import Cookies from 'js-cookie';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');
    const [csrfToken, setCsrfToken] = useState('');


    // VULNERABILITY: Hardcoded API key in frontend code
    const API_KEY = 'sk-1234567890abcdef-SUPER-SECRET-KEY';

    useEffect(() => {
        fetchCSRFToken()
    }, [])

    const fetchCSRFToken = async () => {
        try {
            const response = await fetch(`/api/csrf-token`, {
                credentials: 'include'
            })

            if (response.ok) {
                const data = await response.json()
                setCsrfToken(data.csrf_token)
            }
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
    }

    const handleLogin = async (e: any) => {
        e.preventDefault();

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (data.token) {
                // VULNERABILITY: Storing sensitive token in localStorage (not HttpOnly)

                Cookies.set('authToken', data.token, {
                    expires: 7,
                    secure: true,
                    sameSite: 'strict'
                })

                Cookies.set('userInfo', JSON.stringify(data.user), {
                    expires: 7,
                    secure: true,
                    sameSite: 'strict'
                })

                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userInfo', JSON.stringify(data.user));

                setMessage('Login successful!');
            } else {
                setMessage(data.error || 'Login failed');
            }
        } catch (error) {
            setMessage('Network error: ' + (error instanceof Error ? error.message : 'Unknown error'));
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