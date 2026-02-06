# Edsby AI Auth Backend

Minimal backend for the Edsby AI iOS app: **Google SSO → backend → JWT for app**. No cookie scraping; the app uses ASWebAuthenticationSession and receives a short-lived JWT.

## Flow

1. App opens `GET /auth/start?school=asij`.
2. Backend redirects to **Google OAuth** (or your IdP).
3. After login, Google redirects to `GET /auth/callback?code=...&state=...`.
4. Backend exchanges `code` for tokens, then (in production) establishes an **Edsby session** and obtains `studentId`.
5. Backend creates a **JWT** and redirects to `edsbyai://auth-callback?token=JWT&studentId=...`.
6. iOS app receives the callback via ASWebAuthenticationSession, stores the JWT in Keychain, and uses it for all API calls (`Authorization: Bearer <token>`).

## Why this is reliable

- **Single redirect contract**: The app only needs to open one URL and receive one callback. No WKWebView, no HTML parsing, no fragile redirect detection.
- **Backend owns complexity**: Google/OAuth and Edsby integration live on the server (cookies, session, studentId). The app only stores and sends a JWT.
- **Standard OAuth**: Same pattern as “Sign in with Google” for web/mobile: authorize at IdP, callback to backend, backend returns app-specific token.

## Setup (Node)

```bash
cd backend
npm install
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export JWT_SECRET="a-strong-secret"
npm start
```

In Google Cloud Console, add an OAuth redirect URI: `https://your-domain.com/auth/callback` (or `http://localhost:3000/auth/callback` for local).

## Deploy

Deploy to any host (e.g. Railway, Render, Fly.io). Set the same env vars. In the iOS app, set `backendBaseURLString` in `AuthManager.swift` to your backend URL (e.g. `https://your-app.railway.app`).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/start?school=asij` | Redirects to Google OAuth |
| GET | `/auth/callback` | Handles Google callback, creates JWT, redirects to app |
| GET | `/auth/me` | Validates Bearer JWT (200 = valid) |
| GET | `/api/proxy?path=/p/BaseStudent/...` | Proxies to Edsby with stored session (implement cookie storage per user) |

The `/api/proxy` stub does not yet attach Edsby cookies; you must implement storing and retrieving Edsby session cookies keyed by user (e.g. from JWT `sub` or `studentId`) after you complete the Edsby login flow on the backend.
