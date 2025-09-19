import React, { useEffect, useState } from 'react';
import Cookies from 'js-cookie';
import { WebCryptoUtils } from '../utils/webCrypto';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');
    const [csrfToken, setCsrfToken] = useState('');
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
    const [isEncryptionEnabled, setIsEncryptionEnabled] = useState(true);

    // VULNERABILITY: Hardcoded API key in frontend code
    const API_KEY = 'sk-1234567890abcdef-SUPER-SECRET-KEY';

    useEffect(() => {
        fetchCSRFToken();
        initializeEncryption();
    }, []);

    const initializeEncryption = async () => {
        try {
            // Generate AES key for this session
            const key = await WebCryptoUtils.generateAESKey();
            setEncryptionKey(key);
            console.log('Client-side encryption initialized');
        } catch (error) {
            console.error('Failed to initialize encryption:', error);
            setIsEncryptionEnabled(false);
        }
    };

    const fetchCSRFToken = async () => {
        try {
            const response = await fetch(`/api/csrf-token`, {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                setCsrfToken(data.csrf_token);
            }
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
    };

    const handleLogin = async (e: any) => {
        e.preventDefault();

        try {
            let loginPayload: any = { username, password };

            // Client-side encryption if enabled
            if (isEncryptionEnabled && encryptionKey) {
                console.log('Encrypting form data...');
                
                // Encrypt sensitive data
                const encryptedPassword = await WebCryptoUtils.encryptData(password, encryptionKey);
                const encryptedUsername = await WebCryptoUtils.encryptData(username, encryptionKey);
                
                // Generate data integrity hash
                const dataHash = await WebCryptoUtils.hashData(username + password);
                
                loginPayload = {
                    encrypted_data: {
                        username: encryptedUsername,
                        password: encryptedPassword
                    },
                    encryption_method: 'AES-GCM',
                    data_hash: dataHash,
                    client_encryption: true
                };

                console.log('Form data encrypted on client side');
            } else {
                console.log('Sending plain text data (encryption disabled)');
            }

            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                    'X-API-Key': API_KEY, // VULNERABILITY: Exposing API key
                    'X-Client-Encryption': isEncryptionEnabled ? 'enabled' : 'disabled'
                },
                body: JSON.stringify(loginPayload)
            });

            const data = await response.json();

            if (data.token) {
                // VULNERABILITY: Storing sensitive token in localStorage (not HttpOnly)
                Cookies.set('authToken', data.token, {
                    expires: 7,
                    secure: true,
                    sameSite: 'strict'
                });

                Cookies.set('userInfo', JSON.stringify(data.user), {
                    expires: 7,
                    secure: true,
                    sameSite: 'strict'
                });

                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userInfo', JSON.stringify(data.user));

                setMessage(`Login successful! ${isEncryptionEnabled ? '(Client-side encrypted)' : '(Plain text)'}`);
            } else {
                setMessage(data.error || 'Login failed');
            }
        } catch (error) {
            setMessage('Network error: ' + (error instanceof Error ? error.message : 'Unknown error'));
        }
    };

    const toggleEncryption = () => {
        setIsEncryptionEnabled(!isEncryptionEnabled);
        setMessage(`Client-side encryption ${!isEncryptionEnabled ? 'enabled' : 'disabled'}`);
    };

    return (
        <div style={{ padding: '20px', maxWidth: '400px' }}>
            <h2>Login</h2>
            
            {/* Encryption toggle */}
            <div style={{ marginBottom: '15px', padding: '10px', backgroundColor: '#f0f0f0', borderRadius: '4px' }}>
                <label>
                    <input
                        type="checkbox"
                        checked={isEncryptionEnabled}
                        onChange={toggleEncryption}
                        style={{ marginRight: '8px' }}
                    />
                    Enable Client-side Encryption (Web Crypto API)
                </label>
                <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
                    {isEncryptionEnabled ? '🔒 Forms will be encrypted before sending' : '⚠️ Sending plain text data'}
                </div>
            </div>

            <form onSubmit={handleLogin}>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        style={{ width: '100%', padding: '8px' }}
                        required
                    />
                </div>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{ width: '100%', padding: '8px' }}
                        required
                    />
                </div>
                <button type="submit" style={{ width: '100%', padding: '10px' }}>
                    Login {isEncryptionEnabled ? '🔒' : ''}
                </button>
            </form>

            {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with user input */}
            {message && (
                <div
                    style={{ 
                        marginTop: '10px', 
                        color: message.includes('successful') ? 'green' : 'red',
                        padding: '10px',
                        border: '1px solid',
                        borderRadius: '4px'
                    }}
                    dangerouslySetInnerHTML={{ __html: message }}
                />
            )}

            {/* Debug info */}
            <div style={{ marginTop: '20px', fontSize: '12px', color: '#666' }}>
                <p>Debug Info:</p>
                <p>CSRF Token: {csrfToken}</p>
                <p>Encryption: {isEncryptionEnabled ? 'Enabled (AES-GCM)' : 'Disabled'}</p>
                <p>Test Users: admin/admin123, john_doe/password123</p>
            </div>
        </div>
    );
};

export default Login;