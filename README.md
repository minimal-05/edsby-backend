# Edsby AI Auth Backend

Minimal backend for the Edsby AI iOS app: **Google SSO → backend → JWT for app**. The iOS app uses `ASWebAuthenticationSession` and receives an access token + refresh token. Edsby data is exposed as typed JSON endpoints.

## Flow

1. App opens `GET /auth/start?school=asij`.
2. Backend redirects to **Google OAuth** (or your IdP).
3. After login, Google redirects to `GET /auth/callback?code=...&state=...`.
4. Backend exchanges `code` for tokens, then (in production) establishes an **Edsby session** and obtains `studentId`.
5. Backend creates an **access token** and **refresh token** and redirects to `edsbyai://auth-callback?token=...&refresh=...&studentId=...&school=...`.
6. iOS app receives the callback via `ASWebAuthenticationSession`, stores tokens in Keychain, and uses the access token for API calls (`Authorization: Bearer <token>`). If it gets a 401, it calls `POST /auth/refresh`.

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
export REFRESH_TOKEN_SECRET="a-different-strong-secret"
export APP_CALLBACK="edsbyai://auth-callback"
npm start
```

In Google Cloud Console, add an OAuth redirect URI:

- `https://your-domain.com/auth/callback` (production)
- `http://localhost:3000/auth/callback` (local)

## Environment variables

Required:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `JWT_SECRET` (access token signing secret)
- `REFRESH_TOKEN_SECRET` (refresh token signing secret; should differ from `JWT_SECRET`)

Recommended:

- `APP_CALLBACK` (default: `edsbyai://auth-callback`)
- `ACCESS_TOKEN_TTL_SECONDS` (default: 900)
- `REFRESH_TOKEN_TTL_SECONDS` (default: 2592000)
- `PORT` (default: 3000)

## Deploy

Deploy to any host (e.g. Railway, Render, Fly.io). Set the same env vars.

Railway notes:

- Add all env vars above.
- Ensure your service is reachable via HTTPS.
- Google OAuth redirect URI must exactly match `https://<your-railway-domain>/auth/callback`.

In the iOS app, set `backendBaseURLString` in `AuthManager.swift` to your backend URL (e.g. `https://your-app.railway.app`).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/start?school=asij` | Redirects to Google OAuth |
| GET | `/auth/callback` | Handles Google callback, creates JWT, redirects to app |
| GET | `/auth/me` | Validates Bearer access token (200 = valid) |
| POST | `/auth/refresh` | Exchanges refresh token for a new access token |
| GET | `/api/proxy?path=/p/BaseStudent/...` | Proxies to Edsby with stored session (implement cookie storage per user) |
| GET | `/edsby/ping` | Returns whether the current session has Edsby cookies linked |
| GET | `/edsby/all` | Returns courses + schedule + per-course posts/grades/docs as typed JSON |
| GET | `/edsby/courses` | Returns typed course list |
| GET | `/edsby/schedule` | Returns schedule extracted from BaseStudent |
| GET | `/edsby/course/:courseId/posts` | Returns course posts |
| GET | `/edsby/course/:courseId/grades` | Returns course grades/assignments |
| GET | `/edsby/course/:courseId/docs` | Returns Google Doc links |

Notes:

- This backend stores Edsby cookies in-memory for the demo. For production you must use Redis/DB keyed by user/session.
- If Edsby cookies are missing or invalid, Edsby endpoints return `503` with `error: edsby_session_required`.
