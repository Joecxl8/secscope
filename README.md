SecScope // Domain Security Auditor
A lightweight, zero-dependency domain security auditor that inspects live TLS/SSL posture, HTTP security headers, cookie flags, and DNS/email defenses—and scores any domain from A+ to F.

What It Checks
TLS / SSL & Redirects: Certificate validity, protocol version (TLS 1.2/1.3), issuer, expiry countdown, and HTTP → HTTPS redirect enforcement.
HTTP Security Headers: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, plus Server / X-Powered-By stack disclosure.
Cookie Security Flags: Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.
DNS & Email Security: IPv4 resolution, SPF, DMARC, and CAA records.
Built-In Protections: Blocks private/local IP ranges (10.x, 127.x, 192.168.x, 172.16–31.x, link-local, loopback) to mitigate SSRF, and escapes all rendered output to prevent XSS.
Architecture
secscope/
├── index.html       # Single-file Tailwind CSS dashboard (HTML/CSS/JS)
└── api/
    └── audit.js     # Zero-dependency Node.js serverless function (tls, dns, fetch)
Deploy on Vercel
Fork or push this repo to GitHub.
Import the repository in Vercel (Framework Preset: Other).
Click Deploy—no build step or package.json required.
Author
Built by Joe Manu Thomas (@Joecxl8)
