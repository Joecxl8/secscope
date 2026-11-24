# SecScope // Domain Security Auditor

**Live Demo:** [secscope.vercel.app](https://secscope.vercel.app)

A lightweight, zero-dependency domain security auditor that inspects live TLS/SSL posture, HTTP security headers, cookie flags, and DNS/email defenses—and scores any domain from **A+ to F**.

## What It Checks
- **TLS / SSL & Redirects:** Certificate validity, protocol version (TLS 1.2/1.3), issuer, expiry countdown, and HTTP → HTTPS redirect enforcement.
- **HTTP Security Headers:** `Strict-Transport-Security (HSTS)`, `Content-Security-Policy (CSP)`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, plus `Server` / `X-Powered-By` stack disclosure.
- **Cookie Security Flags:** Inspects `Set-Cookie` headers for `Secure`, `HttpOnly`, and `SameSite` attributes.
- **DNS & Email Security:** IPv4 resolution, full `SPF`, `DMARC`, and `CAA` records.
- **Built-In Protections:** Blocks private/local IPv4 & IPv6 ranges and unsafe redirects to mitigate SSRF, enforces per-IP rate limiting, locks down HTTP security headers via `vercel.json`, and escapes all rendered output to prevent XSS.

## Architecture
```text
secscope/
├── index.html       # Single-file Tailwind CSS dashboard (HTML/CSS/JS)
├── vercel.json      # HTTP security headers (HSTS, CSP, XFO, XCTO, Referrer, Permissions)
└── api/
    └── audit.js     # Zero-dependency Node.js serverless function (tls, dns, fetch)
```

## Deploy on Vercel
1. Fork or push this repo to GitHub.
2. Import the repository in **Vercel** (Framework Preset: **Other**).
3. Click **Deploy**—no build step or `package.json` required.

## Author
Built by **Joe Manu Thomas** ([@Joecxl8](https://github.com/Joecxl8))
