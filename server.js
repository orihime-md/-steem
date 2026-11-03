/**
 * メsteem — Production Render Backend (Express + WebSocket + Render PostgreSQL)
 *
 * Responsibilities:
 * 1. Saves ONLY user email, password hash, and unique username in Render PostgreSQL
 *    to remember returning users and enable @username lookup for private chats.
 * 2. Seeds & maintains the Render Service Admin account (ADMIN_EMAIL + ADMIN_PASSWORD)
 *    as the Sovereign Admin of the public general clan メveil.
 * 3. Stores unique mixed Render group invite links in PostgreSQL with strict 7-day TTL,
 *    automatically deleting expired links from the database and allowing group admins to reset them.
 * 4. Relays live private & clan group messages, custom role assignments, and admin updates
 *    over WebSockets (/ws) while chat history and media live in each user's localStorage.
 */

import 'dotenv/config';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import pg from 'pg';
import { WebSocketServer, WebSocket } from 'ws';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const TOKEN_SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD || 'steem-clan-secret-key').digest('hex');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@steem.clan').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SteemVeilAdmin!2026';
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'veil_sovereign').trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '');

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const VEIL_GROUP_ID = 'veil_public';

if (!process.env.DATABASE_URL) {
  console.warn('[メsteem] WARNING: DATABASE_URL is not set. Set DATABASE_URL to your Render PostgreSQL Internal/External URL.');
}

const isLocalDb = (process.env.DATABASE_URL || '').includes('localhost') || (process.env.DATABASE_URL || '').includes('127.0.0.1');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isLocalDb ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

pool.on('error', (err) => {
  console.error('[メsteem] Unexpected idle PostgreSQL client error:', err.message);
});

// ---------------------------------------------------------------------------
// Password Hashing & Stateless Signed Auth Tokens (Zero native C++ deps)
// ---------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, storedHash) {
  const [salt, key] = (storedHash || '').split(':');
  if (!salt || !key) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(key, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

function signAuthToken(payload) {
  const data = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyAuthToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try {
    return JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function resolveBaseUrl(req) {
  if (process.env.RENDER_EXTERNAL_URL) {
    return process.env.RENDER_EXTERNAL_URL.replace(/\/+$/, '');
  }
  if (process.env.APP_URL) {
    return process.env.APP_URL.replace(/\/+$/, '');
  }
  if (req) {
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').toString().split(',')[0].trim();
    const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
    return `${proto}://${host}`;
  }
  return `http://localhost:${PORT}`;
}

function generateMixedInviteToken(baseUrl, groupId) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const seedHash = crypto
    .createHash('sha256')
    .update(`${baseUrl}::${groupId}::${Date.now()}::${crypto.randomBytes(16).toString('hex')}`)
    .digest();
  let mixed = 'xS';
  for (let i = 0; i < 22; i++) {
    mixed += alphabet[seedHash[i] % alphabet.length];
  }
  return mixed;
}

// ---------------------------------------------------------------------------
// Database Initialization & 7-Day Link Cleanup
// ---------------------------------------------------------------------------
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      is_veil_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_invites (
      token TEXT PRIMARY KEY,
      group_id TEXT UNIQUE NOT NULL,
      group_name TEXT NOT NULL,
      group_description TEXT NOT NULL DEFAULT '',
      group_avatar TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL,
      admins_json TEXT NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS clan_meta (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Upsert Render Service Admin account for メveil
  const existingAdmin = await pool.query('SELECT id, username FROM users WHERE email = $1', [ADMIN_EMAIL]);
  const adminHash = hashPassword(ADMIN_PASSWORD);

  let effectiveAdminUsername = ADMIN_USERNAME || 'veil_sovereign';
  if (existingAdmin.rows.length === 0) {
    const conflictUser = await pool.query('SELECT id FROM users WHERE username = $1', [effectiveAdminUsername]);
    if (conflictUser.rows.length > 0) {
      effectiveAdminUsername = `${effectiveAdminUsername}_${crypto.randomBytes(2).toString('hex')}`;
    }
    await pool.query(
      `INSERT INTO users (id, email, password_hash, username, is_veil_admin)
       VALUES ($1, $2, $3, $4, TRUE)`,
      [`usr_${crypto.randomUUID()}`, ADMIN_EMAIL, adminHash, effectiveAdminUsername]
    );
    console.log(`[メsteem] Seeded Render Service Admin (${ADMIN_EMAIL} / @${effectiveAdminUsername}) for メveil`);
  } else {
    effectiveAdminUsername = existingAdmin.rows[0].username;
    await pool.query(
      `UPDATE users SET password_hash = $1, is_veil_admin = TRUE WHERE email = $2`,
      [adminHash, ADMIN_EMAIL]
    );
  }

  // Ensure メveil clan metadata includes the Render admin
  const veilMetaRes = await pool.query('SELECT value_json FROM clan_meta WHERE key = $1', ['veil_state']);
  let veilState = { admins: [effectiveAdminUsername], roles: { [effectiveAdminUsername]: 'Sovereign Founder' } };
  if (veilMetaRes.rows.length > 0) {
    try {
      veilState = JSON.parse(veilMetaRes.rows[0].value_json);
      if (!Array.isArray(veilState.admins)) veilState.admins = [];
      if (!veilState.admins.includes(effectiveAdminUsername)) {
        veilState.admins.push(effectiveAdminUsername);
      }
      if (!veilState.roles) veilState.roles = {};
      if (!veilState.roles[effectiveAdminUsername]) {
        veilState.roles[effectiveAdminUsername] = 'Sovereign Founder';
      }
    } catch {
      // keep default
    }
  }
  await pool.query(
    `INSERT INTO clan_meta (key, value_json, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = NOW()`,
    ['veil_state', JSON.stringify(veilState)]
  );

  await purgeExpiredInvites();

  // Ensure メveil has an active 7-day link if none exists
  const veilInvite = await pool.query('SELECT token FROM group_invites WHERE group_id = $1', [VEIL_GROUP_ID]);
  if (veilInvite.rows.length === 0) {
    const baseUrl = resolveBaseUrl(null);
    const token = generateMixedInviteToken(baseUrl, VEIL_GROUP_ID);
    const expiresAt = new Date(Date.now() + SEVEN_DAYS_MS).toISOString();
    await pool.query(
      `INSERT INTO group_invites (token, group_id, group_name, group_description, group_avatar, created_by, admins_json, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        token,
        VEIL_GROUP_ID,
        'メveil',
        'Public General Clan Hall — Every operative entering メsteem is sworn into メveil.',
        '',
        effectiveAdminUsername,
        JSON.stringify(veilState.admins),
        expiresAt,
      ]
    );
  }
}

async function purgeExpiredInvites() {
  try {
    const res = await pool.query('DELETE FROM group_invites WHERE expires_at <= NOW() RETURNING group_id');
    if (res.rowCount && res.rowCount > 0) {
      console.log(`[メsteem] Purged ${res.rowCount} expired 7-day group invite link(s) from PostgreSQL.`);
    }
  } catch (err) {
    console.error('[メsteem] Failed purging expired invites:', err.message);
  }
}

async function getVeilState() {
  const res = await pool.query('SELECT value_json FROM clan_meta WHERE key = $1', ['veil_state']);
  if (res.rows.length === 0) return { admins: [], roles: {} };
  try {
    return JSON.parse(res.rows[0].value_json);
  } catch {
    return { admins: [], roles: {} };
  }
}

async function saveVeilState(state) {
  await pool.query(
    `INSERT INTO clan_meta (key, value_json, updated_at)
     VALUES ('veil_state', $1, NOW())
     ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = NOW()`,
    [JSON.stringify(state)]
  );
}

// ---------------------------------------------------------------------------
// Express App & REST API
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '15mb' }));

function requireUser(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const decoded = verifyAuthToken(auth.slice(7));
  if (!decoded || !decoded.id) {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }
  req.user = decoded;
  next();
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, platform: 'メsteem' });
});

app.get('/api/config', async (req, res) => {
  try {
    const veilState = await getVeilState();
    res.json({
      platform: 'メsteem',
      veilGroupId: VEIL_GROUP_ID,
      veilName: 'メveil',
      baseUrl: resolveBaseUrl(req),
      veilAdmins: veilState.admins || [],
      veilRoles: veilState.roles || {},
    });
  } catch {
    res.json({
      platform: 'メsteem',
      veilGroupId: VEIL_GROUP_ID,
      veilName: 'メveil',
      baseUrl: resolveBaseUrl(req),
      veilAdmins: [],
      veilRoles: {},
    });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const username = String(req.body?.username || '').trim().toLowerCase();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }
    if (!/^[a-z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3–24 characters (letters, numbers, _ . -).' });
    }

    // If signing up with the Render ADMIN_EMAIL, verify password matches ADMIN_PASSWORD and update username if desired
    if (email === ADMIN_EMAIL) {
      const adminRow = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (adminRow.rows.length > 0) {
        const existing = adminRow.rows[0];
        if (!verifyPassword(password, existing.password_hash)) {
          return res.status(409).json({ error: 'This email is reserved for the Render Service Admin. Sign in with your Render Admin password.' });
        }
        if (username !== existing.username) {
          const taken = await pool.query('SELECT id FROM users WHERE username = $1 AND id <> $2', [username, existing.id]);
          if (taken.rows.length > 0) {
            return res.status(409).json({ error: 'Username is already claimed by another operative.' });
          }
          await pool.query('UPDATE users SET username = $1 WHERE id = $2', [username, existing.id]);
          const veilState = await getVeilState();
          veilState.admins = Array.from(new Set([...(veilState.admins || []).filter((u) => u !== existing.username), username]));
          if (veilState.roles?.[existing.username]) {
            veilState.roles[username] = veilState.roles[existing.username];
            delete veilState.roles[existing.username];
          }
          await saveVeilState(veilState);
        }
        const userPayload = { id: existing.id, email, username, isVeilAdmin: true, createdAt: existing.created_at };
        return res.json({ token: signAuthToken(userPayload), user: userPayload });
      }
    }

    const dupEmail = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (dupEmail.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    }

    const dupUser = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (dupUser.rows.length > 0) {
      return res.status(409).json({ error: 'That username is already taken. Choose another handle.' });
    }

    const isVeilAdmin = email === ADMIN_EMAIL;
    const id = `usr_${crypto.randomUUID()}`;
    const passwordHash = hashPassword(password);

    const inserted = await pool.query(
      `INSERT INTO users (id, email, password_hash, username, is_veil_admin)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, username, is_veil_admin, created_at`,
      [id, email, passwordHash, username, isVeilAdmin]
    );

    const row = inserted.rows[0];
    if (row.is_veil_admin) {
      const veilState = await getVeilState();
      if (!veilState.admins.includes(row.username)) veilState.admins.push(row.username);
      await saveVeilState(veilState);
    }

    const userPayload = {
      id: row.id,
      email: row.email,
      username: row.username,
      isVeilAdmin: row.is_veil_admin,
      createdAt: row.created_at,
    };

    res.status(201).json({ token: signAuthToken(userPayload), user: userPayload });
  } catch (err) {
    console.error('[メsteem] Signup error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const row = result.rows[0];
    if (!verifyPassword(password, row.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const veilState = await getVeilState();
    const isPromotedVeilAdmin = Boolean(row.is_veil_admin || (veilState.admins || []).includes(row.username));

    const userPayload = {
      id: row.id,
      email: row.email,
      username: row.username,
      isVeilAdmin: isPromotedVeilAdmin,
      createdAt: row.created_at,
    };

    res.json({ token: signAuthToken(userPayload), user: userPayload });
  } catch (err) {
    console.error('[メsteem] Login error:', err);
    res.status(500).json({ error: 'Sign-in failed. Please try again.' });
  }
});

app.get('/api/auth/me', requireUser, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, username, is_veil_admin, created_at FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Account not found.' });
    }
    const row = result.rows[0];
    const veilState = await getVeilState();
    const isVeilAdmin = Boolean(row.is_veil_admin || (veilState.admins || []).includes(row.username));
    res.json({
      user: {
        id: row.id,
        email: row.email,
        username: row.username,
        isVeilAdmin,
        createdAt: row.created_at,
      },
    });
  } catch {
    res.status(500).json({ error: 'Session verification failed.' });
  }
});

app.patch('/api/auth/username', requireUser, async (req, res) => {
  try {
    const nextUsername = String(req.body?.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,24}$/.test(nextUsername)) {
      return res.status(400).json({ error: 'Username must be 3–24 valid characters.' });
    }
    const curRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (curRes.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    const oldUsername = curRes.rows[0].username;

    if (oldUsername !== nextUsername) {
      const dup = await pool.query('SELECT id FROM users WHERE username = $1 AND id <> $2', [nextUsername, req.user.id]);
      if (dup.rows.length > 0) {
        return res.status(409).json({ error: 'Username already taken.' });
      }
      await pool.query('UPDATE users SET username = $1 WHERE id = $2', [nextUsername, req.user.id]);
      const veilState = await getVeilState();
      if ((veilState.admins || []).includes(oldUsername)) {
        veilState.admins = veilState.admins.map((u) => (u === oldUsername ? nextUsername : u));
      }
      if (veilState.roles?.[oldUsername]) {
        veilState.roles[nextUsername] = veilState.roles[oldUsername];
        delete veilState.roles[oldUsername];
      }
      await saveVeilState(veilState);
    }

    const veilState = await getVeilState();
    const isVeilAdmin = Boolean(curRes.rows[0].is_veil_admin || (veilState.admins || []).includes(nextUsername));
    const userPayload = {
      id: curRes.rows[0].id,
      email: curRes.rows[0].email,
      username: nextUsername,
      isVeilAdmin,
      createdAt: curRes.rows[0].created_at,
    };
    res.json({ token: signAuthToken(userPayload), user: userPayload });
  } catch {
    res.status(500).json({ error: 'Could not update username.' });
  }
});

// Lookup a user by exact @username so users can start Private Chats
app.get('/api/users/lookup', requireUser, async (req, res) => {
  try {
    const raw = String(req.query.username || '').trim().toLowerCase().replace(/^@/, '');
    if (!raw) return res.status(400).json({ error: 'Provide a username.' });

    const result = await pool.query(
      'SELECT id, username, is_veil_admin, created_at FROM users WHERE username = $1',
      [raw]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: `No operative found with username @${raw}.` });
    }
    const row = result.rows[0];
    const liveProfile = presenceDirectory.get(row.username);
    res.json({
      user: {
        id: row.id,
        username: row.username,
        isVeilAdmin: row.is_veil_admin,
        avatar: liveProfile?.avatar || '',
        bio: liveProfile?.bio || '',
        online: onlineSocketsByUsername.has(row.username),
      },
    });
  } catch {
    res.status(500).json({ error: 'User lookup failed.' });
  }
});

// Fetch active 7-day group link (auto-deletes if >= 7 days old)
app.get('/api/groups/:groupId/invite', requireUser, async (req, res) => {
  try {
    await purgeExpiredInvites();
    const { groupId } = req.params;
    const result = await pool.query('SELECT * FROM group_invites WHERE group_id = $1', [groupId]);
    if (result.rows.length === 0) {
      return res.json({ invite: null, expired: true });
    }
    const row = result.rows[0];
    const baseUrl = resolveBaseUrl(req);
    res.json({
      invite: {
        token: row.token,
        groupId: row.group_id,
        groupName: row.group_name,
        url: `${baseUrl}/?join=${row.token}`,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        createdBy: row.created_by,
      },
    });
  } catch {
    res.status(500).json({ error: 'Failed to load group link.' });
  }
});

// Mint or Reset a 7-day group invite link (Admin action)
app.post('/api/groups/:groupId/invite/reset', requireUser, async (req, res) => {
  try {
    await purgeExpiredInvites();
    const { groupId } = req.params;
    const userRes = await pool.query('SELECT username, is_veil_admin FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(401).json({ error: 'Unauthorized' });
    const caller = userRes.rows[0];

    const groupName = String(req.body?.groupName || (groupId === VEIL_GROUP_ID ? 'メveil' : 'Clan Group')).trim();
    const groupDescription = String(req.body?.groupDescription || '').trim();
    const groupAvatar = String(req.body?.groupAvatar || '');
    const clientAdmins = Array.isArray(req.body?.admins) ? req.body.admins : [caller.username];

    if (groupId === VEIL_GROUP_ID) {
      const veilState = await getVeilState();
      const canAdminVeil = caller.is_veil_admin || (veilState.admins || []).includes(caller.username);
      if (!canAdminVeil) {
        return res.status(403).json({ error: 'Only メveil Admins can reset the public clan invite link.' });
      }
    } else {
      const existing = await pool.query('SELECT admins_json, created_by FROM group_invites WHERE group_id = $1', [groupId]);
      if (existing.rows.length > 0) {
        let knownAdmins = [];
        try {
          knownAdmins = JSON.parse(existing.rows[0].admins_json || '[]');
        } catch {
          knownAdmins = [];
        }
        if (
          knownAdmins.length > 0 &&
          !knownAdmins.includes(caller.username) &&
          existing.rows[0].created_by !== caller.username &&
          !clientAdmins.includes(caller.username)
        ) {
          return res.status(403).json({ error: 'Only a Group Admin can reset this clan invite link.' });
        }
      }
    }

    const baseUrl = resolveBaseUrl(req);
    const token = generateMixedInviteToken(baseUrl, groupId);
    const expiresAt = new Date(Date.now() + SEVEN_DAYS_MS).toISOString();

    await pool.query('DELETE FROM group_invites WHERE group_id = $1', [groupId]);
    await pool.query(
      `INSERT INTO group_invites (token, group_id, group_name, group_description, group_avatar, created_by, admins_json, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        token,
        groupId,
        groupName,
        groupDescription,
        groupAvatar,
        caller.username,
        JSON.stringify(Array.from(new Set([...clientAdmins, caller.username]))),
        expiresAt,
      ]
    );

    res.json({
      invite: {
        token,
        groupId,
        groupName,
        url: `${baseUrl}/?join=${token}`,
        createdAt: new Date().toISOString(),
        expiresAt,
        createdBy: caller.username,
      },
    });
  } catch (err) {
    console.error('[メsteem] Invite reset error:', err);
    res.status(500).json({ error: 'Could not generate invite link.' });
  }
});

// Resolve & validate a 7-day invite token when a user opens /?join=...
app.get('/api/invites/:token', requireUser, async (req, res) => {
  try {
    await purgeExpiredInvites();
    const token = String(req.params.token || '').trim();
    const result = await pool.query('SELECT * FROM group_invites WHERE token = $1', [token]);
    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'This invite link has expired (links last 7 days and are purged) or was reset by an admin.',
      });
    }
    const row = result.rows[0];
    let admins = [];
    try {
      admins = JSON.parse(row.admins_json || '[]');
    } catch {
      admins = [row.created_by];
    }

    const memGroup = customGroupsMeta.get(row.group_id);

    res.json({
      group: {
        id: row.group_id,
        name: memGroup?.name || row.group_name,
        description: memGroup?.description || row.group_description,
        avatar: memGroup?.avatar || row.group_avatar,
        admins: memGroup?.admins || admins,
        members: memGroup?.members || admins,
        roles: memGroup?.roles || {},
        expiresAt: row.expires_at,
      },
    });
  } catch {
    res.status(500).json({ error: 'Could not validate invite link.' });
  }
});

// Serve clean single-file frontend index.html
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));
app.get('*', (_req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// ---------------------------------------------------------------------------
// Real-Time WebSocket Relay Hub (/ws)
// ---------------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 16 * 1024 * 1024 });

const onlineSocketsByUsername = new Map(); // username -> Set<WebSocket>
const presenceDirectory = new Map(); // username -> { username, avatar, bio, lastSeen, isVeilAdmin }
const customGroupsMeta = new Map(); // groupId -> { id, name, description, avatar, admins, members, roles }
const recentGroupBuffer = new Map(); // groupId -> Array<MessagePacket> (lightweight ephemeral catchup)

function sendJson(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function broadcastAll(payload, excludeWs = null) {
  const raw = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      client.send(raw);
    }
  }
}

function sendToUsernames(usernames, payload, excludeWs = null) {
  const raw = JSON.stringify(payload);
  const unique = new Set(usernames.map((u) => String(u || '').toLowerCase()));
  for (const uname of unique) {
    const set = onlineSocketsByUsername.get(uname);
    if (!set) continue;
    for (const sock of set) {
      if (sock !== excludeWs && sock.readyState === WebSocket.OPEN) {
        sock.send(raw);
      }
    }
  }
}

wss.on('connection', (ws) => {
  let boundUsername = null;

  ws.on('message', async (rawBuf) => {
    let msg;
    try {
      msg = JSON.parse(rawBuf.toString());
    } catch {
      return;
    }

    if (msg.type === 'auth') {
      const decoded = verifyAuthToken(msg.token);
      if (!decoded?.id) {
        sendJson(ws, { type: 'auth:error', error: 'Invalid session' });
        return;
      }
      const dbUserRes = await pool.query('SELECT id, username, is_veil_admin FROM users WHERE id = $1', [decoded.id]).catch(() => ({ rows: [] }));
      const dbUser = dbUserRes.rows[0];
      if (!dbUser) return;

      boundUsername = dbUser.username;
      if (!onlineSocketsByUsername.has(boundUsername)) {
        onlineSocketsByUsername.set(boundUsername, new Set());
      }
      onlineSocketsByUsername.get(boundUsername).add(ws);

      const veilState = await getVeilState().catch(() => ({ admins: [], roles: {} }));
      const isVeilAdmin = Boolean(dbUser.is_veil_admin || (veilState.admins || []).includes(boundUsername));

      const prev = presenceDirectory.get(boundUsername) || {};
      presenceDirectory.set(boundUsername, {
        username: boundUsername,
        avatar: typeof msg.profile?.avatar === 'string' ? msg.profile.avatar : prev.avatar || '',
        bio: typeof msg.profile?.bio === 'string' ? msg.profile.bio : prev.bio || '',
        isVeilAdmin,
        lastSeen: new Date().toISOString(),
      });

      const directorySnapshot = Array.from(presenceDirectory.values()).map((entry) => ({
        ...entry,
        online: onlineSocketsByUsername.has(entry.username),
      }));

      sendJson(ws, {
        type: 'init:sync',
        username: boundUsername,
        isVeilAdmin,
        veilAdmins: veilState.admins || [],
        veilRoles: veilState.roles || {},
        directory: directorySnapshot,
        veilRecentMessages: recentGroupBuffer.get(VEIL_GROUP_ID) || [],
      });

      broadcastAll({
        type: 'presence:update',
        profile: {
          ...presenceDirectory.get(boundUsername),
          online: true,
        },
      }, ws);
      return;
    }

    if (!boundUsername) return;

    if (msg.type === 'profile:update') {
      const prev = presenceDirectory.get(boundUsername) || { username: boundUsername };
      const updated = {
        ...prev,
        username: boundUsername,
        avatar: typeof msg.avatar === 'string' ? msg.avatar : prev.avatar || '',
        bio: typeof msg.bio === 'string' ? msg.bio.slice(0, 180) : prev.bio || '',
        lastSeen: new Date().toISOString(),
      };
      presenceDirectory.set(boundUsername, updated);
      broadcastAll({
        type: 'presence:update',
        profile: { ...updated, online: true },
      });
      return;
    }

    if (msg.type === 'chat:message') {
      const packet = msg.message;
      if (!packet || !packet.id || !packet.threadId) return;
      packet.sender = boundUsername;
      packet.timestamp = packet.timestamp || new Date().toISOString();

      if (packet.scope === 'dm' && packet.recipient) {
        sendToUsernames([packet.recipient, boundUsername], { type: 'chat:message', message: packet }, ws);
      } else {
        if (packet.threadId === VEIL_GROUP_ID) {
          const buf = recentGroupBuffer.get(VEIL_GROUP_ID) || [];
          if (!buf.some((m) => m.id === packet.id)) {
            buf.push(packet);
            if (buf.length > 40) buf.shift();
            recentGroupBuffer.set(VEIL_GROUP_ID, buf);
          }
          broadcastAll({ type: 'chat:message', message: packet }, ws);
        } else {
          const g = customGroupsMeta.get(packet.threadId);
          const targets = Array.isArray(packet.members) ? packet.members : g?.members || [];
          if (targets.length > 0) {
            sendToUsernames(targets, { type: 'chat:message', message: packet }, ws);
          } else {
            broadcastAll({ type: 'chat:message', message: packet }, ws);
          }
        }
      }
      return;
    }

    if (msg.type === 'chat:reaction' || msg.type === 'chat:delete') {
      broadcastAll({ ...msg, actor: boundUsername }, ws);
      return;
    }

    if (msg.type === 'group:sync') {
      const g = msg.group;
      if (!g || !g.id || g.id === VEIL_GROUP_ID) return;
      customGroupsMeta.set(g.id, g);
      if (Array.isArray(g.members)) {
        sendToUsernames(g.members, { type: 'group:sync', group: g }, ws);
      }
      return;
    }

    if (msg.type === 'role:assign') {
      const { groupId, targetUsername, roleTitle } = msg;
      if (!groupId || !targetUsername) return;
      const cleanRole = String(roleTitle || '').trim().slice(0, 32);

      if (groupId === VEIL_GROUP_ID) {
        const veilState = await getVeilState();
        veilState.roles = veilState.roles || {};
        if (cleanRole) {
          veilState.roles[targetUsername] = cleanRole;
        } else {
          delete veilState.roles[targetUsername];
        }
        await saveVeilState(veilState);
        broadcastAll({
          type: 'veil:meta',
          veilAdmins: veilState.admins || [],
          veilRoles: veilState.roles || {},
          actor: boundUsername,
        });
      } else {
        const g = customGroupsMeta.get(groupId) || { id: groupId, roles: {} };
        g.roles = g.roles || {};
        if (cleanRole) g.roles[targetUsername] = cleanRole;
        else delete g.roles[targetUsername];
        customGroupsMeta.set(groupId, g);
        broadcastAll({
          type: 'role:assign',
          groupId,
          targetUsername,
          roleTitle: cleanRole,
          actor: boundUsername,
        });
      }
      return;
    }

    if (msg.type === 'admin:toggle') {
      const { groupId, targetUsername, makeAdmin } = msg;
      if (!groupId || !targetUsername) return;

      if (groupId === VEIL_GROUP_ID) {
        const dbRes = await pool.query('SELECT is_veil_admin FROM users WHERE username = $1', [boundUsername]);
        const veilState = await getVeilState();
        const callerIsAdmin = Boolean(dbRes.rows[0]?.is_veil_admin || (veilState.admins || []).includes(boundUsername));
        if (!callerIsAdmin) return;

        // Prevent revoking the root Render ADMIN_EMAIL account
        const targetRes = await pool.query('SELECT email FROM users WHERE username = $1', [targetUsername]);
        if (!makeAdmin && targetRes.rows[0]?.email === ADMIN_EMAIL) {
          return;
        }

        const set = new Set(veilState.admins || []);
        if (makeAdmin) set.add(targetUsername);
        else set.delete(targetUsername);
        veilState.admins = Array.from(set);
        await saveVeilState(veilState);

        broadcastAll({
          type: 'veil:meta',
          veilAdmins: veilState.admins,
          veilRoles: veilState.roles || {},
          actor: boundUsername,
        });
      } else {
        broadcastAll({
          type: 'admin:toggle',
          groupId,
          targetUsername,
          makeAdmin: Boolean(makeAdmin),
          actor: boundUsername,
        });
      }
    }
  });

  ws.on('close', () => {
    if (!boundUsername) return;
    const set = onlineSocketsByUsername.get(boundUsername);
    if (set) {
      set.delete(ws);
      if (set.size === 0) {
        onlineSocketsByUsername.delete(boundUsername);
        const prev = presenceDirectory.get(boundUsername);
        if (prev) {
          prev.lastSeen = new Date().toISOString();
          presenceDirectory.set(boundUsername, prev);
          broadcastAll({
            type: 'presence:update',
            profile: { ...prev, online: false },
          });
        }
      }
    }
  });
});

// Periodic 7-day group link expiration purge (every 10 minutes)
setInterval(() => {
  void purgeExpiredInvites();
}, 10 * 60 * 1000);

initDatabase()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[メsteem] Server & WebSocket live on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[メsteem] Database startup error:', err.message);
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[メsteem] Server started on port ${PORT} (awaiting valid DATABASE_URL)`);
    });
  });
