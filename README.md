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

7. Identification and Authentication Failures

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