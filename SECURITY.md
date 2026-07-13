# Security Policy

## Reporting a Vulnerability in VENOM AI

If you discover a security vulnerability **in VENOM AI's own code** (not in a target you scanned), please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead:

1. Email the maintainers at: venomaisecurity@gmail.com
2. Include:
   - A description of the vulnerability
   - Steps to reproduce
   - The potential impact
   - Any suggested fix (optional)

We aim to respond within **72 hours** and will work with you on a coordinated disclosure.

---

## Supported Versions

As an open-source project, security fixes are applied to the `main` branch. Please always run the latest version.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| older tags | ❌ |

---

## Security Best Practices for Self-Hosters

When you run VENOM AI yourself:

- **Never commit your `.env`** — it holds API keys and secrets. It's already in `.gitignore`.
- **Generate your own `SECRET_KEY` and `JWT_REFRESH_SECRET`** — never reuse the example values.
- **Set `ENV=production`** when hosting publicly (disables the API docs endpoint).
- **Restrict `ALLOWED_ORIGINS`** to your real domain in production.
- **Run behind HTTPS** in production (e.g. Nginx + Let's Encrypt).
- **Keep Docker images updated** — rebuild periodically to pull security patches.
- **Rotate API keys** if you ever suspect they've been exposed.

---

## Scope

This policy covers vulnerabilities in the VENOM AI codebase itself. It does **not** cover:
- Vulnerabilities you find in targets you scan (that's the tool working as intended)
- Issues in third-party dependencies (report those upstream)
