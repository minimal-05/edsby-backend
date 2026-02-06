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
import * as cheerio from 'cheerio';
import Redis from 'ioredis';

const app = express();
app.use(express.json({ limit: '100kb' }));

const PORT = process.env.PORT || 3000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-change-in-production';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || JWT_SECRET;
const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 15 * 60);
const REFRESH_TOKEN_TTL_SECONDS = Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 30 * 24 * 60 * 60);
const APP_CALLBACK = process.env.APP_CALLBACK || 'edsbyai://auth-callback';

/** Session store: sessionId -> { school, studentId, cookieHeader }. Use Redis in production. */
const edsbySessions = new Map();

/** OAuth state store: stateId -> { school, codeVerifier, createdAt }. Use Redis in production. */
const oauthStates = new Map();

const REDIS_URL = process.env.REDIS_URL;
const redis = REDIS_URL ? new Redis(REDIS_URL) : null;

const OAUTH_STATE_TTL_SECONDS = Number(process.env.OAUTH_STATE_TTL_SECONDS || 10 * 60);
const EDSBY_SESSION_TTL_SECONDS = Number(process.env.EDSBY_SESSION_TTL_SECONDS || 30 * 24 * 60 * 60);

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
  return jwt.sign(
    { sub: userId, school, studentId, sessionId, typ: 'refresh' },
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

    const studentId = await resolveEdsbyStudentId(school, idToken);
    const sessionId = crypto.randomUUID();

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

    const callbackUrl = `${APP_CALLBACK}?token=${encodeURIComponent(accessToken)}&refresh=${encodeURIComponent(refreshToken)}&studentId=${encodeURIComponent(studentId)}&school=${encodeURIComponent(school)}`;
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
    payload = verifyAccessToken(auth.slice(7));
  } catch (_) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const sessionId = payload.sessionId;
  if (!sessionId) {
    return res.status(400).json({ error: 'session_not_found' });
  }

  Promise.resolve(edsbySessionExists(sessionId)).then((exists) => {
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

    Promise.resolve(edsbySessionGet(sessionId)).then(async (session) => {
      const next = session || { school: payload.school || 'asij', studentId: payload.studentId || '', cookieHeader: '' };
      next.cookieHeader = cookieHeader;
      if (newStudentId && typeof newStudentId === 'string') {
        next.studentId = newStudentId;
      }
      await edsbySessionPut(sessionId, next);
      return res.status(200).json({ ok: true });
    }).catch((e) => {
      console.error('edsbySessionGet/Put failed', e);
      return res.status(500).json({ error: 'server_error' });
    });
  }).catch((e) => {
    console.error('edsbySessionExists failed', e);
    return res.status(500).json({ error: 'server_error' });
  });

  return;
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
    studentId: payload.studentId || session.studentId,
  };
}

async function fetchEdsbyHtml({ school, cookieHeader, path }) {
  const base = `https://${school}.edsby.com`;
  const url = base + path;
  const res = await fetch(url, {
    headers: {
      Cookie: cookieHeader,
      'User-Agent': 'EdsbyAI/1.0',
    },
    redirect: 'follow',
  });

  const body = await res.text();
  return { status: res.status, headers: res.headers, body };
}

function isEdsbySessionRequiredStatus(status) {
  return status === 302 || status === 401 || status === 403;
}

function extractCourseIdsAndNames(baseStudentHtml) {
  const $ = cheerio.load(baseStudentHtml);
  const links = $('a[href^="/p/Course/"]');

  const courses = [];
  links.each((_, el) => {
    const href = $(el).attr('href') || '';
    const text = ($(el).text() || '').trim();
    const id = href.split('/').filter(Boolean).pop();
    if (!id) return;
    courses.push({ id, name: text || 'Course', currentGrade: null });
  });

  const uniqueById = new Map();
  for (const c of courses) {
    if (!uniqueById.has(c.id)) uniqueById.set(c.id, c);
  }

  if (uniqueById.size > 0) return Array.from(uniqueById.values());

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
    while ((m = re.exec(baseStudentHtml)) !== null) {
      if (m[1]) ids.add(m[1]);
    }
  }

  return Array.from(ids).map((id) => ({ id, name: 'Course', currentGrade: null }));
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

  const baseStudentRes = await fetchEdsbyHtml({ school, cookieHeader: session.cookieHeader, path: `/p/BaseStudent/${studentId}` });
  if (baseStudentRes.status < 200 || baseStudentRes.status >= 300) {
    if (isEdsbySessionRequiredStatus(baseStudentRes.status)) {
      return res.status(503).json({ error: 'edsby_session_required' });
    }
    return res.status(502).json({ error: 'edsby_upstream_error', status: baseStudentRes.status });
  }

  const courses = extractCourseIdsAndNames(baseStudentRes.body);
  const schedule = extractScheduleItems(baseStudentRes.body);

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
  const session = sessionId ? edsbySessions.get(sessionId) : null;
  const linked = !!(session && session.cookieHeader && session.cookieHeader.length > 0);
  return res.status(200).json({ linked });
});

app.listen(PORT, () => {
  console.log(`Auth backend listening on port ${PORT}`);
  console.log(`Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET and deploy.`);
});
