/**
 * Production backend for Edsby AI app.
 *
 * Flow:
 * 1. App opens GET /auth/start?school=asij → redirect to Google OAuth
 * 2. Google redirects to GET /auth/callback?code=... → exchange for tokens, create JWT and session, redirect to app
 * 3. App (optionally) POSTs Edsby cookies to /auth/edsby-cookies so backend can proxy to Edsby
 * 4. App calls GET /api/proxy?path=... with Bearer JWT → backend forwards to Edsby with stored cookies
 */

import express from 'express';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();
app.use(express.json({ limit: '100kb' }));

const PORT = process.env.PORT || 3000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-change-in-production';
const APP_CALLBACK = 'edsbyai://auth-callback';

/** Session store: sessionId -> { school, studentId, cookieHeader }. Use Redis in production. */
const edsbySessions = new Map();

/**
 * GET /auth/start?school=asij
 * Redirects to Google OAuth. state should include school so we know where to send the user after.
 */
app.get('/auth/start', (req, res) => {
  const school = req.query.school || 'asij';
  const state = Buffer.from(JSON.stringify({ school })).toString('base64');
  const redirectUri = `${getBaseUrl(req)}/auth/callback`;
  const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  googleAuthUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.set('redirect_uri', redirectUri);
  googleAuthUrl.searchParams.set('response_type', 'code');
  googleAuthUrl.searchParams.set('scope', 'openid email profile');
  googleAuthUrl.searchParams.set('state', state);
  googleAuthUrl.searchParams.set('access_type', 'offline');
  res.redirect(302, googleAuthUrl.toString());
});

/**
 * GET /auth/callback?code=...&state=...
 * Google redirects here. Exchange code for tokens, then establish Edsby session (stub here),
 * create JWT, redirect to app.
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    return res.redirect(302, `${APP_CALLBACK}?error=${encodeURIComponent(error)}`);
  }
  if (!code) {
    return res.redirect(302, `${APP_CALLBACK}?error=missing_code`);
  }

  let school = 'asij';
  try {
    const stateObj = JSON.parse(Buffer.from(state || '{}', 'base64').toString());
    school = stateObj.school || school;
  } catch (_) {}

  const redirectUri = `${getBaseUrl(req)}/auth/callback`;

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      return res.redirect(302, `${APP_CALLBACK}?error=${encodeURIComponent('token_exchange_failed')}`);
    }
    const tokens = await tokenRes.json();
    const idToken = tokens.id_token;

    const studentId = await resolveEdsbyStudentId(school, idToken);
    const sessionId = crypto.randomUUID();

    edsbySessions.set(sessionId, {
      school,
      studentId,
      cookieHeader: '',
    });

    const appJwt = jwt.sign(
      { sub: tokens.access_token?.slice(0, 20) || 'user', school, studentId, sessionId },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const callbackUrl = `${APP_CALLBACK}?token=${encodeURIComponent(appJwt)}&studentId=${encodeURIComponent(studentId)}&school=${encodeURIComponent(school)}`;
    res.redirect(302, callbackUrl);
  } catch (e) {
    console.error(e);
    res.redirect(302, `${APP_CALLBACK}?error=server_error`);
  }
});

async function resolveEdsbyStudentId(school, googleIdToken) {
  return 'student-' + school;
}

/**
 * POST /auth/edsby-cookies
 * Body: { cookies: [ { name, value, domain } ], studentId?: string }
 * Header: Authorization: Bearer <jwt>
 * Stores Edsby cookies for this session so /api/proxy can use them.
 */
app.post('/auth/edsby-cookies', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  let payload;
  try {
    payload = jwt.verify(auth.slice(7), JWT_SECRET);
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const sessionId = payload.sessionId;
  if (!sessionId || !edsbySessions.has(sessionId)) {
    return res.status(400).json({ error: 'session_not_found' });
  }

  const { cookies: rawCookies, studentId: newStudentId } = req.body || {};
  if (!Array.isArray(rawCookies) || rawCookies.length === 0) {
    return res.status(400).json({ error: 'cookies_required' });
  }

  const cookieHeader = rawCookies
    .map((c) => (c && c.name && c.value ? `${c.name}=${encodeURIComponent(c.value)}` : null))
    .filter(Boolean)
    .join('; ');

  const session = edsbySessions.get(sessionId);
  session.cookieHeader = cookieHeader;
  if (newStudentId && typeof newStudentId === 'string') {
    session.studentId = newStudentId;
  }
  edsbySessions.set(sessionId, session);

  return res.status(200).json({ ok: true });
});

function getBaseUrl(req) {
  const host = req.get('host') || 'localhost:' + PORT;
  const proto = req.get('x-forwarded-proto') || (req.secure ? 'https' : 'http');
  return `${proto}://${host}`;
}

/**
 * GET /auth/me
 * Validates Bearer JWT and returns 200. Used by the app to validate session.
 */
app.get('/auth/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  const token = auth.slice(7);
  try {
    jwt.verify(token, JWT_SECRET);
    return res.status(200).json({ ok: true });
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

/**
 * GET /auth/edsby-status
 * Returns whether this session has Edsby cookies (so proxy will work).
 * Used by the app to know if it should show "Link Edsby" step.
 */
app.get('/auth/edsby-status', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  let payload;
  try {
    payload = jwt.verify(auth.slice(7), JWT_SECRET);
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  const sessionId = payload.sessionId;
  const session = sessionId ? edsbySessions.get(sessionId) : null;
  const linked = !!(session && session.cookieHeader && session.cookieHeader.length > 0);
  return res.status(200).json({ linked });
});

/**
 * GET /api/proxy?path=/p/BaseStudent/123
 * Forwards request to Edsby with the user's Edsby session (cookies) and returns the body.
 * Requires valid JWT; backend must have stored Edsby cookies when the user logged in.
 * This is a stub: you must implement storing/retrieving Edsby cookies per user (e.g. by JWT sub).
 */
app.get('/api/proxy', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  let payload;
  try {
    payload = jwt.verify(auth.slice(7), JWT_SECRET);
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const path = req.query.path;
  if (!path || !path.startsWith('/')) {
    return res.status(400).json({ error: 'invalid_path' });
  }

  const sessionId = payload.sessionId;
  const school = payload.school || 'asij';
  const session = sessionId ? edsbySessions.get(sessionId) : null;

  if (!session || !session.cookieHeader) {
    return res.status(503).json({ error: 'edsby_session_required', message: 'Sign in to Edsby in the app to sync your data.' });
  }

  const base = `https://${school}.edsby.com`;
  const url = base + path;
  try {
    const proxyRes = await fetch(url, {
      headers: {
        Cookie: session.cookieHeader,
        'User-Agent': 'EdsbyAI/1.0',
      },
      redirect: 'follow',
    });
    const body = await proxyRes.text();
    res.status(proxyRes.status).contentType(proxyRes.headers.get('content-type') || 'text/html').send(body);
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'proxy_failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Auth backend listening on port ${PORT}`);
  console.log(`Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET and deploy.`);
});
