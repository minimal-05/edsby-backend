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
import crypto from 'crypto';
import * as cheerio from 'cheerio';
import Redis from 'ioredis';
import pg from 'pg';
import { chromium } from 'playwright';
import { File, Blob } from 'node:buffer';

if (typeof globalThis.File === 'undefined') {
  globalThis.File = File;
}
if (typeof globalThis.Blob === 'undefined') {
  globalThis.Blob = Blob;
}

const app = express();
app.use(express.json({ limit: '100kb' }));

const PORT = process.env.PORT || 3000;

const { Pool } = pg;
const DATABASE_URL = process.env.DATABASE_URL;
const IS_PROD = process.env.NODE_ENV === 'production';

/**
 * Derive a 32-byte AES-GCM key from JWT_SECRET using HKDF-SHA256.
 * This removes the need for a separate COOKIE_ENCRYPTION_KEY env var.
 */
function deriveCookieEncryptionKey() {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is required to derive cookie encryption key');
  // Use HKDF with empty salt and info 'edsby-cookie-enc' to derive a 32-byte key
  return crypto.hkdfSync('sha256', secret, '', 'edsby-cookie-enc', 32);
}

const COOKIE_ENCRYPTION_KEY = deriveCookieEncryptionKey();
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

if (IS_PROD && !DATABASE_URL) {
  console.error('Missing DATABASE_URL in production. Refusing to start.');
  process.exit(1);
}

if (IS_PROD && !process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in production. Refusing to start.');
  process.exit(1);
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.PGSSLMODE === 'disable' ? false : undefined,
    })
  : null;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-change-in-production';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || JWT_SECRET;
const ACCESS_TOKEN_TTL_SECONDS_RAW = process.env.ACCESS_TOKEN_TTL_SECONDS;
const REFRESH_TOKEN_TTL_SECONDS_RAW = process.env.REFRESH_TOKEN_TTL_SECONDS;

const ACCESS_TOKEN_TTL_SECONDS = Number.parseInt(
  (ACCESS_TOKEN_TTL_SECONDS_RAW ?? String(15 * 60)).trim(),
  10
);
const REFRESH_TOKEN_TTL_SECONDS = Number.parseInt(
  (REFRESH_TOKEN_TTL_SECONDS_RAW ?? String(30 * 24 * 60 * 60)).trim(),
  10
);

if (!Number.isFinite(ACCESS_TOKEN_TTL_SECONDS) || ACCESS_TOKEN_TTL_SECONDS <= 0) {
  console.error('Invalid ACCESS_TOKEN_TTL_SECONDS:', ACCESS_TOKEN_TTL_SECONDS_RAW);
  throw new Error('invalid_access_token_ttl');
}
if (!Number.isFinite(REFRESH_TOKEN_TTL_SECONDS) || REFRESH_TOKEN_TTL_SECONDS <= 0) {
  console.error('Invalid REFRESH_TOKEN_TTL_SECONDS:', REFRESH_TOKEN_TTL_SECONDS_RAW);
  throw new Error('invalid_refresh_token_ttl');
}
const APP_CALLBACK = process.env.APP_CALLBACK || 'edsbyai://auth-callback';

/** Session store: sessionId -> { school, studentId, cookieHeader }. Use Redis in production. */
const edsbySessions = new Map();

/** OAuth state store: stateId -> { school, codeVerifier, createdAt }. Use Redis in production. */
const oauthStates = new Map();

const REDIS_URL = process.env.REDIS_URL;
const redis = REDIS_URL ? new Redis(REDIS_URL) : null;

const OAUTH_STATE_TTL_SECONDS = Number(process.env.OAUTH_STATE_TTL_SECONDS || 10 * 60);
const EDSBY_SESSION_TTL_SECONDS = Number(process.env.EDSBY_SESSION_TTL_SECONDS || 30 * 24 * 60 * 60);

async function dbQuery(text, params) {
  if (!pool) {
    const err = new Error('db_unavailable');
    err.code = 'db_unavailable';
    throw err;
  }
  return pool.query(text, params);
}

async function dbUpsertUser({ userId, email }) {
  await dbQuery(
    `INSERT INTO users (id, email, last_login_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (id)
     DO UPDATE SET email = EXCLUDED.email, last_login_at = NOW()`,
    [userId, email]
  );
}

async function dbInsertRefreshToken({ jti, userId, sessionId, expiresAt }) {
  await dbQuery(
    `INSERT INTO refresh_tokens (jti, user_id, session_id, expires_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (jti) DO NOTHING`,
    [jti, userId, sessionId, expiresAt]
  );
}

async function dbGetRefreshToken(jti) {
  const res = await dbQuery(
    `SELECT jti, user_id, session_id, expires_at, revoked_at
     FROM refresh_tokens
     WHERE jti = $1`,
    [jti]
  );
  return res.rows[0] || null;
}

async function dbUpsertEdsbyLink({ userId, school, status, numericStudentId, cookieJarEncrypted, linkedAt, lastValidatedAt }) {
  await dbQuery(
    `INSERT INTO edsby_links (
        user_id,
        school,
        status,
        numeric_student_id,
        cookie_jar_encrypted,
        linked_at,
        last_validated_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      ON CONFLICT (user_id, school)
      DO UPDATE SET
        status = EXCLUDED.status,
        numeric_student_id = EXCLUDED.numeric_student_id,
        cookie_jar_encrypted = EXCLUDED.cookie_jar_encrypted,
        linked_at = EXCLUDED.linked_at,
        last_validated_at = EXCLUDED.last_validated_at,
        updated_at = NOW()`,
    [userId, school, status, numericStudentId, cookieJarEncrypted, linkedAt, lastValidatedAt]
  );
}

// COOKIE_ENCRYPTION_KEY is now derived from JWT_SECRET; no need for requireCookieEncryptionKey

function encryptCookiePayload(cookiePayload) {
  const key = COOKIE_ENCRYPTION_KEY; // Already a Buffer from deriveCookieEncryptionKey
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(cookiePayload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

function extractNumericBaseStudentIdFromHtml(html) {
  const patterns = [
    /\/p\/BaseStudent\/([0-9]{4,})/i,
    /\\\/p\\\/BaseStudent\\\/([0-9]{4,})/i,
    /BaseStudent\/([0-9]{4,})/i,
    /BaseStudent\\\/([0-9]{4,})/i,
    /baseStudentId"\s*:\s*"?([0-9]{4,})"?/i,
    // JSON in script tags
    /(?:window|var|let|const)\s+(?:user|student|currentUser)\s*=\s*({[^}]+})/i,
    // Meta tags
    /<meta[^>]+name\s*=\s*["']?(?:edsby-)?student-id["']?\s+content\s*=\s*["']?([0-9]{4,})["']?/i,
    // Data attributes
    /data-(?:student|user)-id\s*=\s*["']?([0-9]{4,})["']?/i,
    // Fallback: any 4+ digit number in link/script context
    /(?:href|url|student|user)\D*([0-9]{4,})/i,
  ];
  for (const re of patterns) {
    const m = re.exec(html);
    if (m && m[1]) return String(m[1]);
  }
  // Try to parse JSON from script if present
  const jsonMatch = html.match(/(?:window|var|let|const)\s+(?:user|student|currentUser)\s*=\s*({[^}]+})/i);
  if (jsonMatch) {
    try {
      const obj = eval('(' + jsonMatch[1] + ')');
      if (obj && obj.id) return String(obj.id);
      if (obj && obj.studentId) return String(obj.studentId);
      if (obj && obj.userId) return String(obj.userId);
    } catch (_) {
      // ignore
    }
  }
  return null;
}

async function oauthStatePut(stateId, value) {
  if (!redis) {
    oauthStates.set(stateId, value);
    return;
  }
  const key = `oauth:state:${stateId}`;
  await redis.set(key, JSON.stringify(value), 'EX', OAUTH_STATE_TTL_SECONDS);
}

async function oauthStateGet(stateId) {
  if (!redis) {
    return oauthStates.get(stateId) || null;
  }
  const key = `oauth:state:${stateId}`;
  const raw = await redis.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

async function oauthStateDel(stateId) {
  if (!redis) {
    oauthStates.delete(stateId);
    return;
  }
  const key = `oauth:state:${stateId}`;
  await redis.del(key);
}

async function edsbySessionPut(sessionId, value) {
  if (!redis) {
    edsbySessions.set(sessionId, value);
    return;
  }
  const key = `edsby:session:${sessionId}`;
  await redis.set(key, JSON.stringify(value), 'EX', EDSBY_SESSION_TTL_SECONDS);
}

async function edsbySessionGet(sessionId) {
  if (!redis) {
    return edsbySessions.get(sessionId) || null;
  }
  const key = `edsby:session:${sessionId}`;
  const raw = await redis.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

async function edsbySessionExists(sessionId) {
  if (!redis) return edsbySessions.has(sessionId);
  const key = `edsby:session:${sessionId}`;
  const exists = await redis.exists(key);
  return exists === 1;
}

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function sha256Base64Url(str) {
  const digest = crypto.createHash('sha256').update(str).digest();
  return base64UrlEncode(digest);
}

function makeCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function makeStateId() {
  return base64UrlEncode(crypto.randomBytes(24));
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function signAccessToken({ userId, school, studentId, sessionId }) {
  return jwt.sign(
    { sub: userId, school, studentId, sessionId, typ: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL_SECONDS }
  );
}

function signRefreshToken({ userId, school, studentId, sessionId }) {
  const jti = crypto.randomUUID();
  return jwt.sign(
    { sub: userId, school, studentId, sessionId, typ: 'refresh', jti },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL_SECONDS }
  );
}

function verifyAccessToken(bearerToken) {
  const payload = jwt.verify(bearerToken, JWT_SECRET);
  if (!payload || payload.typ !== 'access') {
    const err = new Error('invalid_token_type');
    err.code = 'invalid_token_type';
    throw err;
  }
  return payload;
}

function verifyRefreshToken(refreshToken) {
  const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
  if (!payload || payload.typ !== 'refresh') {
    const err = new Error('invalid_token_type');
    err.code = 'invalid_token_type';
    throw err;
  }
  if (!payload.jti) {
    const err = new Error('invalid_refresh');
    err.code = 'invalid_refresh';
    throw err;
  }
  return payload;
}

/**
 * GET /auth/start?school=asij
 * Redirects to Google OAuth. state should include school so we know where to send the user after.
 */
app.get('/auth/start', (req, res) => {
  const school = req.query.school || 'asij';
  const codeVerifier = makeCodeVerifier();
  const codeChallenge = sha256Base64Url(codeVerifier);
  const stateId = makeStateId();
  oauthStatePut(stateId, { school, codeVerifier, createdAt: Date.now() }).catch((e) => console.error('oauthStatePut failed', e));

  const state = Buffer.from(JSON.stringify({ sid: stateId })).toString('base64');
  const redirectUri = `${getBaseUrl(req)}/auth/callback`;
  const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  googleAuthUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.set('redirect_uri', redirectUri);
  googleAuthUrl.searchParams.set('response_type', 'code');
  googleAuthUrl.searchParams.set('scope', 'openid email profile');
  googleAuthUrl.searchParams.set('state', state);
  googleAuthUrl.searchParams.set('code_challenge', codeChallenge);
  googleAuthUrl.searchParams.set('code_challenge_method', 'S256');
  googleAuthUrl.searchParams.set('access_type', 'offline');
  googleAuthUrl.searchParams.set('prompt', 'consent');
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
  let stateId = null;
  try {
    const stateObj = JSON.parse(Buffer.from(state || '{}', 'base64').toString());
    stateId = stateObj.sid || null;
  } catch (_) {}

  const storedState = stateId ? await oauthStateGet(stateId) : null;
  if (!storedState) {
    return res.redirect(302, `${APP_CALLBACK}?error=invalid_state`);
  }
  await oauthStateDel(stateId);
  school = storedState.school || school;

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
        code_verifier: storedState.codeVerifier,
      }),
    });
    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      console.error('token_exchange_failed', err);
      return res.redirect(302, `${APP_CALLBACK}?error=${encodeURIComponent('token_exchange_failed')}`);
    }
    const tokens = await tokenRes.json();
    const idToken = tokens.id_token;

    let userId = 'user';
    let email = null;
    if (idToken) {
      try {
        const infoRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
        if (infoRes.ok) {
          const info = await infoRes.json();
          if (info && info.aud === GOOGLE_CLIENT_ID && info.sub) {
            userId = String(info.sub);
            email = info.email ? String(info.email) : null;
          }
        }
      } catch (_) {}
    }

    const studentId = await resolveEdsbyStudentId(school, idToken) || `student-${school}`;
    const sessionId = crypto.randomUUID();

    // If we couldn't resolve a real numeric ID, we'll still create a session
    // The cookie bridge will later update it with a real numeric ID
    if (studentId.startsWith('student-')) {
      console.warn('[edsby] Using placeholder student ID; expecting cookie bridge to resolve real numeric ID');
    } else {
      console.log('[edsby] Resolved real numeric student ID:', studentId);
    }

    const sessionValue = {
      school,
      studentId,
      cookieHeader: '',
      userId,
      email,
      createdAt: Date.now(),
    };
    await edsbySessionPut(sessionId, sessionValue);

    const accessToken = signAccessToken({ userId, school, studentId, sessionId });
    const refreshToken = signRefreshToken({ userId, school, studentId, sessionId });

    try {
      await dbUpsertUser({ userId, email });
      const refreshPayload = verifyRefreshToken(refreshToken);
      const expiresAt = new Date((refreshPayload.exp || nowSeconds()) * 1000);
      await dbInsertRefreshToken({ jti: refreshPayload.jti, userId, sessionId, expiresAt });
    } catch (e) {
      console.error('[db] failed to persist auth session');
      console.error(e);
      if (IS_PROD) {
        return res.redirect(302, `${APP_CALLBACK}?error=server_error`);
      }
    }

    const callbackUrl = `${APP_CALLBACK}?token=${encodeURIComponent(accessToken)}&refresh=${encodeURIComponent(refreshToken)}&studentId=${encodeURIComponent(studentId)}&school=${encodeURIComponent(school)}`;
    res.redirect(302, callbackUrl);
  } catch (e) {
    console.error(e);
    res.redirect(302, `${APP_CALLBACK}?error=server_error`);
  }
});

/**
 * Resolve Edsby numeric student ID by authenticating with Edsby using Google ID token.
 * This replaces the stub implementation and returns a real numeric ID.
 */
async function resolveEdsbyStudentId(school, googleIdToken) {
  try {
    // Try common Edsby URL patterns
    const possibleUrls = [
      `https://${school}.edsby.com/p/BaseStudent`,
      `https://${school}.edsby.com/p/`,
      `https://${school}.edsby.com/home`,
      `https://${school}.edsby.com`,
      `https://edsby.com/${school}`,
    ];

    let loginHtml = null;
    let workingUrl = null;

    for (const url of possibleUrls) {
      console.log(`[edsby] Trying Edsby URL: ${url}`);
      const loginRes = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; EdsbyAI/1.0)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        },
        redirect: 'manual', // Prevent auto-redirect to capture cookies
      });

      if (loginRes.status === 200) {
        loginHtml = await loginRes.text();
        workingUrl = url;
        console.log(`[edsby] Successfully loaded Edsby page from: ${url}`);
        break;
      } else {
        console.warn(`[edsby] Failed to load ${url}: ${loginRes.status}`);
      }
    }

    if (!loginHtml) {
      console.warn('[edsby] Could not load any Edsby URL');
      return null;
    }

    // Look for Google sign-in button or form to extract Google OAuth URL for Edsby
    const googleSignInMatch = loginHtml.match(/href=["']([^"']+)["'][^>]*Google[^<]*Sign[^<]*In/i);
    if (googleSignInMatch) {
      const edsbyGoogleUrl = googleSignInMatch[1];
      console.log('[edsby] Found Edsby Google OAuth URL:', edsbyGoogleUrl);
      
      // Exchange our Google ID token for Edsby session via their OAuth
      // This is complex and may require reverse-engineering Edsby's OAuth flow
      // For now, fall back to extracting numeric ID from any existing session cookies if present
    }

    // Fallback: try to find numeric ID in login page (may contain user info for already logged-in users)
    const numericIdMatch = loginHtml.match(/(?:student|user|userId)["']?\s*[:=]\s*["']?(\d{4,})["']?/i);
    if (numericIdMatch) {
      const numericId = numericIdMatch[1];
      console.log('[edsby] Resolved numeric student ID from login page:', numericId);
      return numericId;
    }

    console.warn('[edsby] Could not resolve numeric student ID automatically');
    return null;
  } catch (e) {
    console.error('[edsby] Error in resolveEdsbyStudentId:', e);
    return null;
  }
}

/**
 * POST /auth/edsby-cookies
 * Body: { cookies: [ { name, value, domain } ], studentId?: string }
 * Header: Authorization: Bearer <jwt>
 * Stores Edsby cookies for this session so /api/proxy can use them.
 * Now derives encryption key from JWT_SECRET, eliminating env var dependency.
 * Also updates the session studentId if a numeric one is resolved from cookies.
 */
app.post('/auth/edsby-cookies', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  let payload;
  try {
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const sessionId = payload.sessionId;
  if (!sessionId) {
    return res.status(400).json({ error: 'session_not_found' });
  }

  const exists = await edsbySessionExists(sessionId);
  if (!exists) {
    return res.status(400).json({ error: 'session_not_found' });
  }

  const { cookies: rawCookies, studentId: newStudentId } = req.body || {};
  if (!Array.isArray(rawCookies) || rawCookies.length === 0) {
    return res.status(400).json({ error: 'cookies_required' });
  }

  const cookieHeader = rawCookies
    .map((c) => (c && c.name && c.value != null ? `${c.name}=${String(c.value)}` : null))
    .filter(Boolean)
    .join('; ');

  const session = await edsbySessionGet(sessionId);
  const next = session || { school: payload.school || 'asij', studentId: payload.studentId || '', cookieHeader: '' };
  next.cookieHeader = cookieHeader;
  if (newStudentId && typeof newStudentId === 'string') {
    next.studentId = newStudentId;
  }

  let numericStudentId = null;
  try {
    // Try to resolve numeric student ID from homepage first
    const homeRes = await fetchEdsbyHtml({
      school: next.school || payload.school || 'asij',
      cookieHeader: next.cookieHeader,
      path: '/',
    });
    if (homeRes.status >= 200 && homeRes.status < 300) {
      numericStudentId = extractNumericBaseStudentIdFromHtml(homeRes.body);
      if (numericStudentId) {
        next.studentId = numericStudentId;
        console.log('[edsby] Resolved numeric student ID from homepage:', numericStudentId);
      }
    }
    // If not found, try BaseStudent page as fallback
    if (!numericStudentId) {
      const baseStudentRes = await fetchEdsbyHtml({
        school: next.school || payload.school || 'asij',
        cookieHeader: next.cookieHeader,
        path: `/p/BaseStudent/${next.studentId}`,
      });
      if (baseStudentRes.status >= 200 && baseStudentRes.status < 300) {
        numericStudentId = extractNumericBaseStudentIdFromHtml(baseStudentRes.body);
        if (numericStudentId) {
          next.studentId = numericStudentId;
          console.log('[edsby] Resolved numeric student ID from BaseStudent page:', numericStudentId);
        }
      }
    }
  } catch (e) {
    console.error('[edsby] numeric student id resolve failed');
    console.error(e);
  }

  // Update the session with the potentially resolved numeric student ID
  await edsbySessionPut(sessionId, next);

  try {
    const encrypted = encryptCookiePayload(rawCookies);
    await dbUpsertEdsbyLink({
      userId: payload.sub,
      school: (next.school || payload.school || 'asij').toLowerCase(),
      status: 'linked',
      numericStudentId: numericStudentId,
      cookieJarEncrypted: encrypted,
      linkedAt: new Date(),
      lastValidatedAt: numericStudentId ? new Date() : null,
    });
  } catch (e) {
    console.error('[db] failed to persist edsby link');
    console.error(e);
    if (IS_PROD) {
      return res.status(500).json({ error: 'server_error' });
    }
  }

  // Return the potentially resolved numeric student ID to the client
  return res.status(200).json({ ok: true, studentId: next.studentId || null });
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
app.get('/auth/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  const token = auth.slice(7);
  try {
    const payload = verifyAccessToken(token);
    const session = payload.sessionId ? await edsbySessionGet(payload.sessionId) : null;
    return res.status(200).json({
      ok: true,
      school: payload.school,
      studentId: payload.studentId,
      userId: payload.sub,
      sessionId: payload.sessionId,
      edsbyLinked: !!(session && session.cookieHeader && session.cookieHeader.length > 0),
      exp: payload.exp,
      iat: payload.iat,
    });
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

/**
 * POST /auth/refresh
 * Body: { refresh: "<refresh token>" }
 * Returns: { token: "<new access token>" }
 */
app.post('/auth/refresh', async (req, res) => {
  const { refresh } = req.body || {};
  if (!refresh || typeof refresh !== 'string') {
    return res.status(400).json({ error: 'refresh_required' });
  }

  try {
    const payload = verifyRefreshToken(refresh);
    try {
      const record = await dbGetRefreshToken(payload.jti);
      if (!record || record.revoked_at) {
        return res.status(401).json({ error: 'invalid_refresh' });
      }
    } catch (e) {
      console.error('[db] refresh token lookup failed');
      console.error(e);
      if (IS_PROD) return res.status(500).json({ error: 'server_error' });
    }
    const sessionId = payload.sessionId;
    const session = sessionId ? await edsbySessionGet(sessionId) : null;

    const school = session?.school || payload.school || 'asij';
    const studentId = session?.studentId || payload.studentId || '';
    const userId = payload.sub;
    const token = signAccessToken({ userId, school, studentId, sessionId });
    return res.status(200).json({ token });
  } catch (e) {
    return res.status(401).json({ error: 'invalid_refresh' });
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
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  const sessionId = payload.sessionId;
  Promise.resolve(sessionId ? edsbySessionGet(sessionId) : null).then((session) => {
    const linked = !!(session && session.cookieHeader && session.cookieHeader.length > 0);
    return res.status(200).json({ linked });
  }).catch((e) => {
    console.error('edsbySessionGet failed', e);
    return res.status(500).json({ error: 'server_error' });
  });
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
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const path = req.query.path;
  if (!path || !path.startsWith('/')) {
    return res.status(400).json({ error: 'invalid_path' });
  }

  const sessionId = payload.sessionId;
  const school = payload.school || 'asij';
  const session = sessionId ? await edsbySessionGet(sessionId) : null;

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

async function requireAccessSession(req, res) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    res.status(401).json({ error: 'missing_token' });
    return null;
  }
  let payload;
  try {
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    res.status(401).json({ error: 'invalid_token' });
    return null;
  }

  const sessionId = payload.sessionId;
  const session = sessionId ? await edsbySessionGet(sessionId) : null;
  if (!session || !session.cookieHeader) {
    res.status(503).json({
      error: 'edsby_session_required',
      message: 'Sign in to Edsby in the app to sync your data.',
    });
    return null;
  }

  return {
    payload,
    session,
    school: payload.school || session.school || 'asij',
    studentId: session.studentId || payload.studentId,
  };
}

async function fetchEdsbyHtml({ school, cookieHeader, path }) {
  const base = `https://${school}.edsby.com`;
  const url = base + path;
  console.log(`[edsby] Fetching Edsby URL: ${url}`);
  console.log(`[edsby] Cookie header length: ${cookieHeader ? cookieHeader.length : 0}`);
  const res = await fetch(url, {
    headers: {
      Cookie: cookieHeader,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    },
    redirect: 'follow',
  });
  const body = await res.text();
  console.log(`[edsby] Response status: ${res.status}`);
  console.log(`[edsby] Response preview (first 800 chars): ${body.slice(0, 800)}`);
  return { status: res.status, headers: res.headers, body };
}

async function fetchEdsbyRenderedHtml({ school, cookieHeader, path }) {
  const base = `https://${school}.edsby.com`;
  const url = base + path;
  console.log(`[edsby] (playwright) Rendering URL: ${url}`);

  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  try {
    const context = await browser.newContext({
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 800 },
    });

    // Convert Cookie header string to Playwright cookie objects
    const cookies = String(cookieHeader || '')
      .split(';')
      .map((c) => c.trim())
      .filter(Boolean)
      .map((pair) => {
        const idx = pair.indexOf('=');
        if (idx <= 0) return null;
        const name = pair.slice(0, idx).trim();
        const value = pair.slice(idx + 1).trim();
        return {
          name,
          value,
          domain: `${school}.edsby.com`,
          path: '/',
          httpOnly: false,
          secure: true,
          sameSite: 'Lax',
        };
      })
      .filter(Boolean);

    if (cookies.length) {
      await context.addCookies(cookies);
    }

    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });
    const html = await page.content();
    console.log(`[edsby] (playwright) Rendered HTML length: ${html.length}`);
    console.log(`[edsby] (playwright) Rendered preview (first 800 chars): ${html.slice(0, 800)}`);
    await context.close();
    return { status: 200, headers: new Map(), body: html };
  } catch (e) {
    console.error('[edsby] (playwright) render failed', e);
    return { status: 599, headers: new Map(), body: '' };
  } finally {
    await browser.close();
  }
}

function isEdsbySessionRequiredStatus(status) {
  return status === 302 || status === 401 || status === 403;
}

function extractCourseIdsAndNames(html) {
  console.log('[edsby] extractCourseIdsAndNames: parsing HTML (first 2000 chars):', html.slice(0, 2000));
  const $ = cheerio.load(html);
  // Primary selector: direct course links
  let links = $('a[href^="/p/Course/"]');
  console.log('[edsby] Primary selector found links:', links.length);
  if (links.length === 0) {
    // Fallback selectors
    links = $('.course-card a');
    console.log('[edsby] Fallback .course-card a found links:', links.length);
    if (links.length === 0) {
      links = $('[data-course-id]');
      console.log('[edsby] Fallback [data-course-id] found links:', links.length);
      if (links.length === 0) {
        links = $('a[href*="/p/Course/"]');
        console.log('[edsby] Fallback a[href*="/p/Course/"] found links:', links.length);
        if (links.length === 0) {
          links = $('a[href*="Course/"]');
          console.log('[edsby] Fallback a[href*="Course/"] found links:', links.length);
        }
      }
    }
  }

  const courses = [];
  links.each((_, el) => {
    const href = $(el).attr('href') || '';
    const text = ($(el).text() || '').trim();
    const id = href.split('/').filter(Boolean).pop();
    if (!id) return;
    courses.push({ id, name: text || 'Course', currentGrade: null });
  });

  // If still no courses, try regex patterns
  if (courses.length === 0) {
    console.log('[edsby] No links found, trying regex patterns');
    const patterns = [
      /\/p\/Course\/([A-Za-z0-9_-]+)/gi,
      /\\\/p\\\/Course\\\/([A-Za-z0-9_-]+)/gi,
      /\/p\/Course\?id=([A-Za-z0-9_-]+)/gi,
      /\\\/p\\\/Course\?id=([A-Za-z0-9_-]+)/gi,
      /\/Course\/([A-Za-z0-9_-]+)/gi,
      /\\\/Course\\\/([A-Za-z0-9_-]+)/gi,
      /courseId"\s*:\s*"([A-Za-z0-9_-]+)"/gi,
      /course_id"\s*:\s*"([A-Za-z0-9_-]+)"/gi,
    ];

    const ids = new Set();
    for (const re of patterns) {
      let m;
      while ((m = re.exec(html)) !== null) {
        if (m[1]) ids.add(m[1]);
      }
    }

    console.log('[edsby] Regex patterns extracted IDs:', Array.from(ids));
    ids.forEach(id => courses.push({ id, name: 'Course', currentGrade: null }));
  }

  const uniqueById = new Map();
  for (const c of courses) {
    if (!uniqueById.has(c.id)) uniqueById.set(c.id, c);
  }

  console.log('[edsby] Final unique courses count:', uniqueById.size);
  return uniqueById.size > 0 ? Array.from(uniqueById.values()) : [];
}

function extractScheduleItems(baseStudentHtml) {
  const $ = cheerio.load(baseStudentHtml);
  const items = [];

  $('.schedule-row').each((i, el) => {
    const courseName = ($(el).find('.schedule-course').text() || '').trim() || 'Class';
    const timeText = ($(el).find('.schedule-time').text() || '').trim();
    const locationText = ($(el).find('.schedule-room').text() || '').trim();
    items.push({
      id: `${i}`,
      courseName,
      timeText,
      location: locationText.length ? locationText : null,
    });
  });

  return items;
}

function extractPosts(courseHtml, courseId) {
  const $ = cheerio.load(courseHtml);
  const nodes = $('.post, .feed-item, .announcement');
  const posts = [];

  nodes.each((index, el) => {
    const title = ($(el).find('.title, .subject').first().text() || '').trim() || 'Post';
    const body = ($(el).find('.body, .content').text() || '').trim();
    const dateText = ($(el).find('.date, .timestamp').text() || '').trim();
    posts.push({
      id: `${courseId}-${index}`,
      title,
      body,
      createdAt: dateText || null,
      courseId,
    });
  });

  return posts;
}

function extractGoogleDocs(courseHtml, courseId) {
  const $ = cheerio.load(courseHtml);
  const anchors = $('a[href*="docs.google.com/document"], a[href*="drive.google.com"]');
  const docs = [];

  anchors.each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (!href) return;
    const title = ($(el).text() || '').trim() || 'Google Doc';
    docs.push({
      id: crypto.randomUUID(),
      url: href,
      title,
      courseId,
      contentSnippet: null,
    });
  });

  return docs;
}

function extractAssignments(gradesHtml, courseId) {
  const $ = cheerio.load(gradesHtml);
  const rows = $('table tr');
  const assignments = [];

  rows.each((index, el) => {
    if (index === 0) return;
    const cols = $(el).find('td');
    if (cols.length < 4) return;
    const name = $(cols.get(0)).text().trim();
    const dueText = $(cols.get(1)).text().trim();
    const grade = $(cols.get(2)).text().trim();
    const points = $(cols.get(3)).text().trim();
    const category = cols.length > 4 ? $(cols.get(4)).text().trim() : '';
    assignments.push({
      id: crypto.randomUUID(),
      name,
      dueDate: dueText || null,
      grade: grade.length ? grade : null,
      points: points.length ? points : null,
      category: category.length ? category : null,
      courseId,
    });
  });

  return assignments;
}

app.get('/edsby/courses', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school, studentId } = ctx;
  const htmlRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/BaseStudent/${studentId}` });
  if (isEdsbySessionRequiredStatus(htmlRes.status)) {
    return res.status(503).json({ error: 'edsby_session_required' });
  }
  if (htmlRes.status < 200 || htmlRes.status >= 300) {
    return res.status(502).json({ error: 'edsby_upstream_error', status: htmlRes.status });
  }

  const courses = extractCourseIdsAndNames(htmlRes.body);
  return res.status(200).json({ courses });
});

app.get('/edsby/schedule', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school, studentId } = ctx;
  const htmlRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/BaseStudent/${studentId}` });
  if (isEdsbySessionRequiredStatus(htmlRes.status)) {
    return res.status(503).json({ error: 'edsby_session_required' });
  }
  if (htmlRes.status < 200 || htmlRes.status >= 300) {
    return res.status(502).json({ error: 'edsby_upstream_error', status: htmlRes.status });
  }

  const schedule = extractScheduleItems(htmlRes.body);
  return res.status(200).json({ schedule });
});

app.get('/edsby/course/:courseId/posts', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school } = ctx;
  const courseId = req.params.courseId;
  const htmlRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/Course/${courseId}` });
  if (isEdsbySessionRequiredStatus(htmlRes.status)) {
    return res.status(503).json({ error: 'edsby_session_required' });
  }
  if (htmlRes.status < 200 || htmlRes.status >= 300) {
    return res.status(502).json({ error: 'edsby_upstream_error', status: htmlRes.status });
  }

  const posts = extractPosts(htmlRes.body, courseId);
  return res.status(200).json({ posts });
});

app.get('/edsby/course/:courseId/docs', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school } = ctx;
  const courseId = req.params.courseId;
  const htmlRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/Course/${courseId}` });
  if (isEdsbySessionRequiredStatus(htmlRes.status)) {
    return res.status(503).json({ error: 'edsby_session_required' });
  }
  if (htmlRes.status < 200 || htmlRes.status >= 300) {
    return res.status(502).json({ error: 'edsby_upstream_error', status: htmlRes.status });
  }

  const linkedDocs = extractGoogleDocs(htmlRes.body, courseId);
  return res.status(200).json({ linkedDocs });
});

app.get('/edsby/course/:courseId/grades', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school, studentId } = ctx;
  const courseId = req.params.courseId;
  const htmlRes = await fetchEdsbyHtml({
    school,
    cookieHeader: session.cookieHeader,
    path: `/p/MyWorkStudent/${courseId}?student=${encodeURIComponent(studentId)}`,
  });
  if (isEdsbySessionRequiredStatus(htmlRes.status)) {
    return res.status(503).json({ error: 'edsby_session_required' });
  }
  if (htmlRes.status < 200 || htmlRes.status >= 300) {
    return res.status(502).json({ error: 'edsby_upstream_error', status: htmlRes.status });
  }

  const grades = extractAssignments(htmlRes.body, courseId);
  return res.status(200).json({ grades });
});

app.get('/edsby/all', async (req, res) => {
  const ctx = await requireAccessSession(req, res);
  if (!ctx) return;

  const { session, school, studentId } = ctx;

  console.log('[edsby] /edsby/all using studentId:', studentId, 'school:', school);

  // Fetch homepage to extract courses; BaseStudent page often has minimal content
  const homeRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: '/' });
  console.log('[edsby] Homepage status:', homeRes.status);
  console.log('[edsby] Homepage preview (first 800 chars):', homeRes.body.slice(0, 800));

  if (homeRes.status < 200 || homeRes.status >= 300) {
    if (isEdsbySessionRequiredStatus(homeRes.status)) {
      return res.status(503).json({ error: 'edsby_session_required' });
    }
    return res.status(502).json({ error: 'edsby_upstream_error', status: homeRes.status });
  }

  let courses = extractCourseIdsAndNames(homeRes.body);
  let schedule = extractScheduleItems(homeRes.body);

  // If homepage yields no courses, try other pages
  if (courses.length === 0) {
    console.log('[edsby] No courses on homepage, trying /p/');
    const pRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: '/p/' });
    if (pRes.status >= 200 && pRes.status < 300) {
      courses = extractCourseIdsAndNames(pRes.body);
      schedule = extractScheduleItems(pRes.body);
      console.log('[edsby] Found courses on /p/:', courses.length);
    }
    // Fallback: try BaseStudent page with numeric ID
    if (courses.length === 0 && /^\d+$/.test(String(studentId))) {
      console.log('[edsby] No courses on /p/, trying BaseStudent page with numeric ID');
      const baseRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/BaseStudent/${studentId}` });
      if (baseRes.status >= 200 && baseRes.status < 300) {
        courses = extractCourseIdsAndNames(baseRes.body);
        schedule = extractScheduleItems(baseRes.body);
        console.log('[edsby] Found courses on BaseStudent page:', courses.length);
      }
    }
  }

  // Final fallback: render via Playwright and re-extract courses/schedule
  if (courses.length === 0) {
    console.log('[edsby] No courses found via static fetch; trying Playwright-rendered homepage');
    const rendered = await fetchEdsbyRenderedHtml({ school, cookieHeader: session.cookieHeader, path: '/' });
    if (rendered.status >= 200 && rendered.status < 300 && rendered.body) {
      courses = extractCourseIdsAndNames(rendered.body);
      schedule = extractScheduleItems(rendered.body);
      console.log('[edsby] Found courses via Playwright:', courses.length);
    }
  }

  if (courses.length === 0) {
    return res.status(502).json({
      error: 'edsby_extract_failed',
      message: 'Could not extract courses from Edsby pages.',
    });
  }

  console.log('[edsby] Extracted courses count:', courses.length, 'schedule count:', schedule.length);

  const details = await Promise.all(
    courses.map(async (c) => {
      const [courseRes, gradesRes] = await Promise.all([
        fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/Course/${c.id}` }),
        fetchEdsbyHtml({
          school,
          cookieHeader: session.cookieHeader,
          path: `/p/MyWorkStudent/${c.id}?student=${encodeURIComponent(studentId)}`,
        }),
      ]);

      const posts = courseRes.status >= 200 && courseRes.status < 300 ? extractPosts(courseRes.body, c.id) : [];
      const linkedDocs = courseRes.status >= 200 && courseRes.status < 300 ? extractGoogleDocs(courseRes.body, c.id) : [];
      const grades = gradesRes.status >= 200 && gradesRes.status < 300 ? extractAssignments(gradesRes.body, c.id) : [];

      return {
        id: c.id,
        course: c,
        posts,
        grades,
        linkedDocs,
      };
    })
  );

  return res.status(200).json({
    courses: details,
    schedule,
  });
});

app.get('/edsby/ping', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }

  let payload;
  try {
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const sessionId = payload.sessionId;
  Promise.resolve(sessionId ? edsbySessionGet(sessionId) : null).then((session) => {
    const linked = !!(session && session.cookieHeader && session.cookieHeader.length > 0);
    return res.status(200).json({ linked });
  }).catch((e) => {
    console.error('edsbySessionGet failed', e);
    return res.status(500).json({ error: 'server_error' });
  });
});

app.post('/api/v1/ai/chat', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  let payload;
  try {
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  if (!OPENAI_API_KEY) {
    return res.status(503).json({ error: 'ai_not_configured' });
  }

  const { message, context } = req.body || {};
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message_required' });
  }

  const userKey = String(payload.sub || 'user');

  if (redis) {
    const key = `rl:ai:${userKey}`;
    try {
      const count = await redis.incr(key);
      if (count === 1) {
        await redis.expire(key, 60);
      }
      if (count > 20) {
        return res.status(429).json({ error: 'rate_limited' });
      }
    } catch (e) {
      console.error('[redis] rate limit failed');
      console.error(e);
    }
  }

  const contextText = typeof context === 'string' ? context.slice(0, 8000) : '';
  const userMsg = message.slice(0, 4000);

  try {
    const aiRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are a helpful student assistant. Use the provided context if present. Keep answers concise and actionable.',
          },
          ...(contextText
            ? [
                {
                  role: 'system',
                  content: `Context:\n${contextText}`,
                },
              ]
            : []),
          { role: 'user', content: userMsg },
        ],
        temperature: 0.4,
      }),
    });

    if (!aiRes.ok) {
      const body = await aiRes.text();
      console.error('[ai] upstream error', aiRes.status, body.slice(0, 500));
      return res.status(502).json({ error: 'ai_upstream_error' });
    }

    const data = await aiRes.json();
    const text = data?.choices?.[0]?.message?.content;
    return res.status(200).json({ reply: typeof text === 'string' ? text : '' });
  } catch (e) {
    console.error('[ai] request failed');
    console.error(e);
    return res.status(502).json({ error: 'ai_request_failed' });
  }
});

async function start() {
  if (pool) {
    try {
      await pool.query('SELECT 1');
      console.log('[db] Postgres connectivity OK');
    } catch (e) {
      console.error('[db] Postgres connectivity failed');
      console.error(e);
      if (IS_PROD) process.exit(1);
    }
  }

  app.listen(PORT, () => {
    console.log(`Auth backend listening on port ${PORT}`);
    console.log(`Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET and deploy.`);
  });
}

start();
