# VENOM AI — Auth Setup (Phase 1)

Phase 1 (auth foundation) is now in place. This guide walks you through getting it running.

---

## 1. Install new Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

The only new dependency is `email-validator` (needed by pydantic's `EmailStr`).
All other auth packages (`passlib[bcrypt]`, `python-jose`, `bcrypt`, `httpx`, `sqlalchemy`) were already installed.

---

## 2. Generate strong JWT secrets

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import secrets; print('JWT_REFRESH_SECRET=' + secrets.token_urlsafe(48))"
```

Paste both into `backend/.env`. **The two secrets MUST be different.**

---

## 3. Set up Resend (for sending verification + password-reset emails)

1. Go to **https://resend.com** and create a free account (3,000 emails/month).
2. **Add a domain** (or use the free `onboarding@resend.dev` for testing only).
   - Add the DNS records Resend shows you (SPF, DKIM).
   - Wait for verification (usually < 5 min).
3. Go to **API Keys** → **Create API Key** → name it `venom-ai` → copy the `re_...` token.
4. Paste into `backend/.env`:
   ```env
   RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxx
   EMAIL_FROM=VENOM AI <noreply@yourdomain.com>
   ```

> **Don't have a domain yet?** Use `EMAIL_FROM=onboarding@resend.dev` to start.
> Only test emails to your own account will deliver — that's fine for dev.

---

## 4. (Optional) Set up Google OAuth

If you want Google sign-in to appear on the login/signup pages:

1. Go to **https://console.cloud.google.com/apis/credentials**
2. **Create Credentials → OAuth client ID → Web application**
3. **Authorized redirect URIs**:
   - For local dev: `http://localhost:8000/api/auth/google/callback`
   - For production: `https://api.yourdomain.com/api/auth/google/callback`
4. Copy the Client ID + Client Secret into `backend/.env`:
   ```env
   GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=GOCSPX-xxxx
   GOOGLE_REDIRECT_URI=http://localhost:8000/api/auth/google/callback
   ```

If you leave `GOOGLE_CLIENT_ID` blank, the "Continue with Google" button is hidden automatically.

---

## 5. Start the stack

### Option A — full docker (recommended)
```bash
docker-compose up -d
```
This starts postgres + redis + api (port 8000) + frontend (port 3000) + celery workers.

### Option B — docker for DB only, run API locally
```bash
docker-compose up -d postgres redis
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# In another terminal:
cd frontend
python -m http.server 8080
# Then set FRONTEND_URL=http://localhost:8080 in backend/.env
```

On first API startup you should see:
```
[startup] DB tables ensured
```
That means the `users`, `refresh_tokens`, and `auth_tokens` tables were auto-created.

---

## 6. Test the flow (docker = port 3000, local = port 8080)

| Step | URL | Expected |
|---|---|---|
| Visit dashboard | http://localhost:3000/ | Redirects to `/login.html` |
| Sign up | http://localhost:3000/signup.html | Creates account, sends verification email |
| Check inbox | (your email) | Click "Verify Email" link |
| Verified | http://localhost:3000/verify-email.html?token=... | "Email verified ✓" |
| Log out | (user menu in sidebar) | Bounced to `/login.html` |
| Log in | http://localhost:3000/login.html | Lands on dashboard |
| Forgot pw | http://localhost:3000/forgot-password.html | Sends reset email |
| Reset | (click link in email) | New password set, must log in again |

---

## 7. API reference

All endpoints under `/api/auth/`:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/signup` | — | Create account, returns tokens, fires verify email |
| POST | `/login` | — | Email/password login, returns tokens |
| POST | `/refresh` | — | Exchange refresh for new access (rotates refresh too) |
| POST | `/logout` | — | Revoke a refresh token |
| POST | `/logout-all` | ✓ | Revoke ALL refresh tokens (sign out everywhere) |
| GET | `/me` | ✓ | Current user profile |
| PATCH | `/me` | ✓ | Update profile (full_name, company_name, avatar_url) |
| POST | `/verify-email` | — | Confirm email-verification token |
| POST | `/resend-verification` | — | Resend verification link |
| POST | `/forgot-password` | — | Send password-reset email |
| POST | `/reset-password` | — | Set new password via reset token |
| POST | `/change-password` | ✓ | Change password while logged in |
| GET | `/google` | — | Start Google OAuth flow |
| GET | `/google/callback` | — | OAuth callback (Google redirects here) |
| GET | `/providers` | — | Which login methods are enabled |

API docs: **http://localhost:8000/api/docs**

---

## 8. What's NOT in Phase 1 (Phase 2 will add)

- Existing endpoints (`/api/chat`, `/api/scan`, etc.) are **not yet auth-protected** — anyone with a token can still hit them anonymously. Phase 2 adds `Depends(get_current_user)` to all of them.
- Chat sessions, scans, monitors are still **global in-memory** — Phase 2 migrates them to be per-user in the DB.
- No usage quotas, no plan-based gating — that's Phase 3.

---

## 9. Database notes

- The `users`, `refresh_tokens`, and `auth_tokens` tables are auto-created by SQLAlchemy on startup.
- For production: replace the `create_all` startup hook with proper Alembic migrations. (See `/alembic/` — existing migrations don't cover auth, so you'd want a new revision: `alembic revision --autogenerate -m "add auth tables"`.)
- The `users` table now has these new columns vs. the old schema: `full_name`, `avatar_url`, `is_verified`, `oauth_provider`, `oauth_id`, `last_login_at`, `last_login_ip`, `updated_at`. `hashed_pass` is now nullable (OAuth-only users have no password).

---

## 10. Security notes

- Passwords are bcrypt-hashed via `passlib` (cost factor 12).
- Access tokens: 15-minute lifetime, HS256-signed with `SECRET_KEY`.
- Refresh tokens: 30-day lifetime, HS256-signed with `JWT_REFRESH_SECRET` (different key!), **stored hashed in DB** so they can be revoked server-side.
- Email verification + password reset tokens: 256-bit URL-safe random, **SHA-256 hashed in DB**, single-use, time-limited.
- Login attempts return a generic error (no user enumeration).
- `forgot-password` and `resend-verification` always return success (no user enumeration).
- Refresh tokens are **rotated** on every refresh — using an old refresh token fails.
- Password reset revokes ALL existing refresh tokens (forces re-login everywhere).

---

## Next session

When you're ready to continue, say:
> **"start Phase 2 — protect existing endpoints + per-user data"**

That will:
1. Add `Depends(get_current_user)` to all `/api/chat`, `/api/scan`, `/api/monitor`, `/api/reports` routes.
2. Migrate in-memory chat sessions / monitor list / scan history to be per-user in DB.
3. Make the user-based email work for monitoring alerts (alerts will go to the logged-in user's email, not a hardcoded one).
