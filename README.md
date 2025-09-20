# 1-week-security

1. Broken Access Control

Privelige escalation
Cors misconfig
URL tampering
Accessing API with missing access controls

Examples:

Using unverified SQL data that is accessing account info
An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.

Except for public resources, deny by default
minizing CORS
Disable web server direct. listing
Log access control failures
rate limit api's
Stateful identifiers should be invalidated on server after logout
Stateless JWT tokens should be short lived.

2. Weak Cryptographic Controls

Old or weak algorithms
How is data being sent and what format
server certificate properly validated?

Disable caching for response that contain sensitive data.Always use authenticated encryption instead of just encryption.

Keys should be generated cryptographically randomly and stored in memory as byte arrays. If a password is used, then it must be converted to a key via an appropriate password base key derivation function. 


3. Identification and Authentication Failures

Credential stuffing
brute force
weak passwords
bad encryption of passwords
no 2fa
session identifier in URL, does not correctly invalidate session id's

implement mfa
no weak passwords allowed
NIST password policies
increasingly delay failed login attempts
server side session manager, not stored in url

"enumeration attacks", session timeouts not working

Zero Trust is a security model based on the principle of maintaining strict access controls and not trusting anyone by default

IDOR Vulnerabilities: 

For example, if a URL like https://example.com/profile?user_id=123 directly references a user's data in a database, an attacker could change the user_id parameter to 124 or 1, potentially accessing another user's profile or even an administrator's account, especially if the administrator's ID is commonly known.

directory traversal attack—such as accessing /etc/passwd by manipulating a filename parameter

JWT vs JWT with RS256

- RS256 offers stronger guarantees because only the holder with the private key can sign the token, making it authentic and valid.

RS256 requires public and private key. Public key is exchanged, while private key is kept.

```
openssl genrsa -out private_key.pem 2048
```

CSRF - a type of cyber attack that tricks a user into executing unwanted actions on a web application where they are authenticated

## Local storage vs cookie storage

Cookie storage have better security configs and better access control!

expires: expires time
secure: cookies only sent through HTTPS
HttpOnly: inaccessible through client side JS, reduces XSS
sameSite: prevents cookies from being sent through cross site requests, reduces CSRF attack

## Implemented CSRF Tokens

- token is generated at login time, and is sent back to the user. 

## Docker isolated networks

- provides logical separation
- increases security 
- environment isolation
- limiting unauthorized access

```
docker network prune -f
```

Removes all unused networks in docker 

```
docker-compose down --remove-orphans
```

Managed to review SQL Views and how to create extension and custom utility functions in sql

database encryption - can be queried normally. Even if someone gets db access or uses sql injection, db will still be encrypted!
