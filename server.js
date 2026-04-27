'use strict';

const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const path           = require('path');
const fs             = require('fs');
const crypto         = require('crypto');
const https          = require('https');
const { execSync }   = require('child_process');
const { v4: uuidv4 } = require('uuid');
const multer         = require('multer');
const XLSX           = require('xlsx');

// ── Paths ─────────────────────────────────────────────────────────────
// When run via npx/CLI, GRC_DATA_DIR and GRC_UPLOADS_DIR are set by bin/grc-server.js
// so data is stored in the user's working directory, not inside node_modules.
const DATA_DIR    = process.env.GRC_DATA_DIR    || path.join(__dirname, 'data');
const UPLOADS_DIR = process.env.GRC_UPLOADS_DIR || path.join(__dirname, 'uploads');
const DB_FILE     = path.join(DATA_DIR, 'grc.db');
const SESSION_DB  = path.join(DATA_DIR, 'sessions.db');

[DATA_DIR, UPLOADS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ── Database (better-sqlite3) ──────────────────────────────────────────
const Database = require('better-sqlite3');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
console.log('DB: better-sqlite3 (WAL mode)');

// ── Init schema ────────────────────────────────────────────────────────
function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id                   TEXT PRIMARY KEY,
      name                 TEXT NOT NULL,
      username             TEXT NOT NULL UNIQUE,
      role                 TEXT NOT NULL DEFAULT 'assessor',
      password_hash        TEXT NOT NULL,
      color                TEXT NOT NULL DEFAULT '',
      created              TEXT NOT NULL,
      last_login           TEXT,
      must_change_password INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assessments (
      std_id     TEXT NOT NULL,
      ctrl_id    TEXT NOT NULL,
      status     TEXT DEFAULT '',
      notes      TEXT DEFAULT '',
      finding    TEXT DEFAULT '',
      recommendation TEXT DEFAULT '',
      risk       TEXT DEFAULT '',
      remdate    TEXT DEFAULT '',
      assessor   TEXT DEFAULT '',
      ai_input   TEXT DEFAULT '',
      evidence   TEXT DEFAULT '[]',
      saved_at   TEXT,
      PRIMARY KEY (std_id, ctrl_id)
    );

    CREATE TABLE IF NOT EXISTS meta (
      std_id TEXT NOT NULL,
      key    TEXT NOT NULL,
      value  TEXT DEFAULT '',
      PRIMARY KEY (std_id, key)
    );

    CREATE TABLE IF NOT EXISTS attachments (
      id       TEXT PRIMARY KEY,
      std_id   TEXT NOT NULL,
      ctrl_id  TEXT NOT NULL,
      name     TEXT NOT NULL,
      path     TEXT NOT NULL,
      size     INTEGER NOT NULL DEFAULT 0,
      added    TEXT NOT NULL,
      UNIQUE(std_id, ctrl_id, name)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      ts            TEXT NOT NULL,
      ts_display    TEXT NOT NULL,
      std_id        TEXT NOT NULL,
      std_label     TEXT NOT NULL,
      std_color     TEXT NOT NULL DEFAULT '',
      ctrl_id       TEXT NOT NULL,
      ctrl_name     TEXT NOT NULL,
      field         TEXT NOT NULL,
      from_val      TEXT DEFAULT '',
      to_val        TEXT DEFAULT '',
      status        TEXT DEFAULT '',
      assessor      TEXT DEFAULT '',
      notes_preview TEXT DEFAULT '',
      action        TEXT DEFAULT 'saved'
    );

    CREATE INDEX IF NOT EXISTS idx_assessments    ON assessments(std_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(ts);
    CREATE INDEX IF NOT EXISTS idx_audit_std      ON audit_log(std_id);
    CREATE INDEX IF NOT EXISTS idx_attach_ctrl    ON attachments(std_id, ctrl_id);
  `);
  console.log('DB schema ready');
}

// ── Express setup ──────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session store
let sessionStore;
try {
  const SQLiteStore = require('connect-sqlite3')(session);
  sessionStore = new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR });
} catch(e) {
  sessionStore = undefined; // falls back to in-memory
}

app.use(session({
  store:             sessionStore,
  secret:            process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   60 * 60 * 1000,   // 1 hour — matches desktop inactivity timeout
  },
}));

// File upload (attachments)
const upload = multer({
  dest:   UPLOADS_DIR,
  limits: { fileSize: 50 * 1024 * 1024 },  // 50 MB
});

// ── Auth middleware ────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user) { req.session.destroy(); return res.status(401).json({ error: 'Session invalid' }); }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/auth/status', (req, res) => {
  // Never cache — must always reflect real server session state
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.set('Pragma', 'no-cache');
  if (!req.session?.userId) return res.json({ authenticated: false });
  const user = db.prepare('SELECT id,name,username,role,color,must_change_password,last_login FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.json({ authenticated: false });
  res.json({ authenticated: true, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });
  // Update last login
  db.prepare('UPDATE users SET last_login=? WHERE id=?').run(new Date().toISOString(), user.id);
  req.session.userId = user.id;
  req.session.save();
  res.json({ ok: true, user: { id: user.id, name: user.name, username: user.username, role: user.role, color: user.color, must_change_password: user.must_change_password } });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ════════════════════════════════════════════════════════
//  USER ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/users/count', (req, res) => {
  const row = db.prepare('SELECT COUNT(*) as c FROM users').get();
  res.json({ count: row.c });
});

app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id,name,username,role,color,created,last_login,must_change_password FROM users ORDER BY name').all();
  res.json(users);
});

app.post('/api/users', async (req, res, next) => {
  // Allow unauthenticated access only for first-time setup (zero users in DB)
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (userCount === 0) return next();
  return requireAdmin(req, res, next);
}, async (req, res) => {
  const { name, username, role, password, mustChange } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'name, username, password required' });
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(username.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Username already taken' });
  const hash  = await bcrypt.hash(password, 12);
  const color = makeAvatarColor(username);
  const id    = uuidv4();
  db.prepare('INSERT INTO users (id,name,username,role,password_hash,color,created,must_change_password) VALUES (?,?,?,?,?,?,?,?)').run(
    id, name, username.toLowerCase(), role || 'assessor', hash, color,
    new Date().toISOString(), mustChange ? 1 : 0
  );
  const user = db.prepare('SELECT id,name,username,role,color,created,last_login,must_change_password FROM users WHERE id=?').get(id);
  res.json(user);
});

app.patch('/api/users/:id/password', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;
  // Users can only change their own password unless admin
  if (id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (id === req.user.id && currentPassword) {
    // Verify current password for self-change
    const valid = await bcrypt.compare(currentPassword, req.user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?').run(hash, id);
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='admin'").get().c;
  const user = db.prepare('SELECT role FROM users WHERE id=?').get(id);
  if (user?.role === 'admin' && adminCount <= 1) return res.status(400).json({ error: 'Cannot delete the last admin' });
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  SETTINGS ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/settings/:key', requireAuth, (req, res) => {
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get(req.params.key);
  res.json({ value: row ? row.value : '' });
});

app.put('/api/settings/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run(req.params.key, value);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  UPDATE ROUTES
// ════════════════════════════════════════════════════════
// Check unzip is available — needed for applying updates
try { execSync('which unzip', { stdio: 'pipe' }); }
catch(e) { console.warn('[update] Warning: unzip not found. Install it with: sudo apt install unzip'); }

const GITHUB_REPO    = 'nader8388/GRC-Tool-Linux';
const GITHUB_API     = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
const CURRENT_VERSION = require('./package.json').version;

// Helper: make an HTTPS GET request and return parsed JSON
function githubGet(url) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        'User-Agent': 'grc-assessment-server',
        'Accept': 'application/vnd.github.v3+json',
      }
    };
    https.get(url, opts, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Invalid JSON from GitHub API')); }
      });
    }).on('error', reject);
  });
}

// Helper: download a file from a URL to a local path
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const opts = { headers: { 'User-Agent': 'grc-assessment-server' } };
    https.get(url, opts, res => {
      // Follow redirects (GitHub assets redirect to S3)
      if (res.statusCode === 302 || res.statusCode === 301) {
        file.close();
        fs.unlinkSync(dest);
        return downloadFile(res.headers.location, dest).then(resolve).catch(reject);
      }
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', err => {
      fs.unlink(dest, () => {});
      reject(err);
    });
  });
}

// Helper: unzip a file to a destination directory using built-in unzip
function extractZip(zipPath, destDir) {
  execSync(`unzip -o "${zipPath}" -d "${destDir}"`, { stdio: 'pipe' });
}

// GET /api/update/check — compare current version to latest GitHub release
app.get('/api/update/check', requireAdmin, async (req, res) => {
  try {
    const release = await githubGet(GITHUB_API);
    if (release.message) {
      // GitHub API error (e.g. rate limit or no releases yet)
      return res.json({ current: CURRENT_VERSION, latest: null, updateAvailable: false, error: release.message });
    }
    const latest = release.tag_name.replace(/^v/, '');
    const updateAvailable = latest !== CURRENT_VERSION;
    res.json({
      current: CURRENT_VERSION,
      latest,
      updateAvailable,
      releaseUrl: release.html_url,
      releaseName: release.name,
      releaseNotes: release.body || '',
      publishedAt: release.published_at,
      // Find the zip asset
      downloadUrl: (release.assets || []).find(a => a.name.endsWith('.zip'))?.browser_download_url || null,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/update/apply — download latest release zip and apply it, then restart via pm2
app.post('/api/update/apply', requireAdmin, async (req, res) => {
  const { downloadUrl } = req.body;
  if (!downloadUrl) return res.status(400).json({ error: 'downloadUrl required' });

  const tmpZip  = path.join(__dirname, '_update.zip');
  const tmpDir  = path.join(__dirname, '_update_tmp');
  const appDir  = __dirname;

  try {
    // 1. Download
    res.json({ step: 'downloading' });  // immediate feedback
  } catch(e) {
    return res.status(500).json({ error: e.message });
  }

  // Run the rest asynchronously after responding
  setImmediate(async () => {
    try {
      await downloadFile(downloadUrl, tmpZip);

      // 2. Extract to temp dir
      if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true });
      fs.mkdirSync(tmpDir);
      extractZip(tmpZip, tmpDir);

      // 3. Find the extracted folder (release zips usually have one top-level folder)
      const entries = fs.readdirSync(tmpDir);
      const extractedFolder = entries.length === 1 && fs.statSync(path.join(tmpDir, entries[0])).isDirectory()
        ? path.join(tmpDir, entries[0])
        : tmpDir;

      // 4. Copy new files over current install, preserving data/ and uploads/
      const PRESERVE = new Set(['data', 'uploads', '.env', 'node_modules', '_update.zip', '_update_tmp']);
      for (const entry of fs.readdirSync(extractedFolder)) {
        if (PRESERVE.has(entry)) continue;
        const src  = path.join(extractedFolder, entry);
        const dest = path.join(appDir, entry);
        if (fs.statSync(src).isDirectory()) {
          fs.cpSync(src, dest, { recursive: true });
        } else {
          fs.copyFileSync(src, dest);
        }
      }

      // 5. Install any new dependencies
      execSync('npm install --production', { cwd: appDir, stdio: 'pipe' });

      // 6. Clean up temp files
      fs.unlinkSync(tmpZip);
      fs.rmSync(tmpDir, { recursive: true });

      // 7. Restart via pm2
      execSync('pm2 restart all', { stdio: 'pipe' });
    } catch(e) {
      console.error('[update] Apply failed:', e);
    }
  });
});

// ════════════════════════════════════════════════════════
//  ASSESSMENT ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/assessments/:stdId', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM assessments WHERE std_id=?').all(req.params.stdId);
  const result = {};
  rows.forEach(r => {
    result[r.ctrl_id] = {
      status: r.status, notes: r.notes, finding: r.finding,
      recommendation: r.recommendation, risk: r.risk, remdate: r.remdate,
      assessor: r.assessor, aiInput: r.ai_input,
      evidence: tryJSON(r.evidence, []),
    };
  });
  res.json(result);
});

app.put('/api/assessments/:stdId/:ctrlId', requireAuth, (req, res) => {
  const { stdId, ctrlId } = req.params;
  const d = req.body;
  db.prepare(`INSERT OR REPLACE INTO assessments
    (std_id,ctrl_id,status,notes,finding,recommendation,risk,remdate,assessor,ai_input,evidence,saved_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    stdId, ctrlId, d.status||'', d.notes||'', d.finding||'',
    d.recommendation||'', d.risk||'', d.remdate||'', d.assessor||'',
    d.aiInput||'', JSON.stringify(d.evidence||[]), new Date().toISOString()
  );
  res.json({ ok: true });
});

app.delete('/api/assessments/:stdId/:ctrlId', requireAuth, (req, res) => {
  db.prepare('DELETE FROM assessments WHERE std_id=? AND ctrl_id=?').run(req.params.stdId, req.params.ctrlId);
  res.json({ ok: true });
});

app.delete('/api/assessments/:stdId', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM assessments WHERE std_id=?').run(req.params.stdId);
  db.prepare('DELETE FROM meta WHERE std_id=?').run(req.params.stdId);
  db.prepare('DELETE FROM attachments WHERE std_id=?').run(req.params.stdId);
  res.json({ ok: true });
});

// ── Meta ───────────────────────────────────────────────────────────────
app.get('/api/meta/:stdId', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key,value FROM meta WHERE std_id=?').all(req.params.stdId);
  const result = {};
  rows.forEach(r => { result[r.key] = r.value; });
  res.json(result);
});

app.put('/api/meta/:stdId/:key', requireAuth, (req, res) => {
  const { stdId, key } = req.params;
  db.prepare('INSERT OR REPLACE INTO meta (std_id,key,value) VALUES (?,?,?)').run(stdId, key, req.body.value || '');
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  ATTACHMENTS ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/attachments/:stdId/:ctrlId', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id,name,size,added FROM attachments WHERE std_id=? AND ctrl_id=?').all(req.params.stdId, req.params.ctrlId);
  res.json(rows);
});

app.post('/api/attachments/:stdId/:ctrlId', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { stdId, ctrlId } = req.params;
  const id   = uuidv4();
  const name = req.file.originalname;
  // Remove existing with same name
  const existing = db.prepare('SELECT path FROM attachments WHERE std_id=? AND ctrl_id=? AND name=?').get(stdId, ctrlId, name);
  if (existing) {
    try { fs.unlinkSync(existing.path); } catch(e) {}
    db.prepare('DELETE FROM attachments WHERE std_id=? AND ctrl_id=? AND name=?').run(stdId, ctrlId, name);
  }
  db.prepare('INSERT INTO attachments (id,std_id,ctrl_id,name,path,size,added) VALUES (?,?,?,?,?,?,?)').run(
    id, stdId, ctrlId, name, req.file.path, req.file.size, new Date().toISOString()
  );
  res.json({ ok: true, id, name, size: req.file.size });
});

app.delete('/api/attachments/:stdId/:ctrlId/:name', requireAuth, (req, res) => {
  const { stdId, ctrlId, name } = req.params;
  const row = db.prepare('SELECT path FROM attachments WHERE std_id=? AND ctrl_id=? AND name=?').get(stdId, ctrlId, decodeURIComponent(name));
  if (row) {
    try { fs.unlinkSync(row.path); } catch(e) {}
    db.prepare('DELETE FROM attachments WHERE std_id=? AND ctrl_id=? AND name=?').run(stdId, ctrlId, decodeURIComponent(name));
  }
  res.json({ ok: true });
});

app.get('/api/attachments/:stdId/:ctrlId/:name/download', requireAuth, (req, res) => {
  const row = db.prepare('SELECT path,name FROM attachments WHERE std_id=? AND ctrl_id=? AND name=?')
    .get(req.params.stdId, req.params.ctrlId, decodeURIComponent(req.params.name));
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.download(row.path, row.name);
});

// ════════════════════════════════════════════════════════
//  AUDIT LOG ROUTES
// ════════════════════════════════════════════════════════
app.post('/api/audit', requireAuth, (req, res) => {
  const entries = Array.isArray(req.body) ? req.body : [req.body];
  const ins = db.prepare(`INSERT INTO audit_log
    (ts,ts_display,std_id,std_label,std_color,ctrl_id,ctrl_name,field,from_val,to_val,status,assessor,notes_preview,action)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  try {
    const insertAll = db.transaction(rows => rows.forEach(e => ins.run(
      e.ts||new Date().toISOString(), e.ts_display||new Date().toLocaleString(),
      e.std_id||'', e.std_label||'', e.std_color||'', e.ctrl_id||'', e.ctrl_name||'',
      e.field||'', e.from_val||'', e.to_val||'', e.status||'', e.assessor||'',
      e.notes_preview||'', e.action||'saved'
    )));
    insertAll(entries);
  } catch(e) {
    console.error('[audit] Batch insert failed:', e.message);
  }
  res.json({ ok: true });
});

app.get('/api/audit/count', requireAuth, (req, res) => {
  const row = db.prepare('SELECT COUNT(*) as c FROM audit_log').get();
  res.json({ count: row.c });
});

app.get('/api/audit', requireAuth, (req, res) => {
  const { search, stdFilter, actFilter, dateFilter } = req.query;
  let where = '1=1'; const params = [];
  if (stdFilter)             { where += ' AND std_id=?';      params.push(stdFilter); }
  if (actFilter === 'status')  where += " AND field='status'";
  if (actFilter === 'notes')   where += " AND field='notes'";
  if (actFilter === 'finding') where += " AND field='finding'";
  if (actFilter === 'cleared') where += " AND action='cleared'";
  if (dateFilter) {
    const now   = new Date();
    const today = new Date(now.getFullYear(),now.getMonth(),now.getDate()).toISOString();
    const week  = new Date(now.getFullYear(),now.getMonth(),now.getDate()-7).toISOString();
    const month = new Date(now.getFullYear(),now.getMonth()-1,now.getDate()).toISOString();
    if (dateFilter==='today') { where += ' AND ts>=?'; params.push(today); }
    if (dateFilter==='week')  { where += ' AND ts>=?'; params.push(week); }
    if (dateFilter==='month') { where += ' AND ts>=?'; params.push(month); }
  }
  if (search) {
    where += ' AND (ctrl_id LIKE ? OR ctrl_name LIKE ? OR std_label LIKE ? OR assessor LIKE ? OR notes_preview LIKE ?)';
    const s = `%${search}%`;
    params.push(s,s,s,s,s);
  }
  const rows = db.prepare(`SELECT * FROM audit_log WHERE ${where} ORDER BY ts DESC LIMIT 500`).all(...params);
  res.json(rows);
});

app.get('/api/audit/standards', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT DISTINCT std_id,std_label FROM audit_log ORDER BY std_label').all());
});

app.get('/api/audit/info', requireAuth, (req, res) => {
  const oldest = db.prepare('SELECT ts FROM audit_log ORDER BY ts ASC  LIMIT 1').get();
  const newest = db.prepare('SELECT ts FROM audit_log ORDER BY ts DESC LIMIT 1').get();
  res.json({ oldest: oldest?.ts||null, newest: newest?.ts||null });
});

app.delete('/api/audit', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM audit_log').run();
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  EXPORT ROUTES
// ════════════════════════════════════════════════════════
app.post('/api/export/json/:stdId', requireAuth, (req, res) => {
  const { stdId } = req.params;
  const assessments = db.prepare('SELECT * FROM assessments WHERE std_id=?').all(stdId);
  const meta        = db.prepare('SELECT key,value FROM meta WHERE std_id=?').all(stdId);
  const metaObj = {};
  meta.forEach(r => { metaObj[r.key] = r.value; });
  res.setHeader('Content-Disposition', `attachment; filename="GRC_Backup_${stdId}_${dateStr()}.json"`);
  res.json({ stdId, meta: metaObj, assessments });
});

app.post('/api/import/json/:stdId', requireAdmin, express.json({ limit: '50mb' }), (req, res) => {
  const { stdId } = req.params;
  const { assessments, meta } = req.body;
  if (assessments) {
    db.prepare('DELETE FROM assessments WHERE std_id=?').run(stdId);
    assessments.forEach(a => {
      db.prepare(`INSERT OR REPLACE INTO assessments
        (std_id,ctrl_id,status,notes,finding,recommendation,risk,remdate,assessor,ai_input,evidence,saved_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        stdId, a.ctrl_id, a.status||'', a.notes||'', a.finding||'',
        a.recommendation||'', a.risk||'', a.remdate||'', a.assessor||'',
        a.ai_input||'', a.evidence||'[]', a.saved_at||new Date().toISOString()
      );
    });
  }
  if (meta) {
    Object.entries(meta).forEach(([k,v]) => {
      db.prepare('INSERT OR REPLACE INTO meta (std_id,key,value) VALUES (?,?,?)').run(stdId, k, v);
    });
  }
  res.json({ ok: true });
});

// ── Database reset ─────────────────────────────────────────────────────
app.post('/api/admin/reset', requireAdmin, (req, res) => {
  db.exec('DELETE FROM assessments; DELETE FROM meta; DELETE FROM attachments; DELETE FROM audit_log; DELETE FROM settings; DELETE FROM users;');
  req.session.destroy();
  res.json({ ok: true });
});

// ── Excel export ──────────────────────────────────────────────────────
app.get('/api/export/excel/:stdId', requireAuth, (req, res) => {
  const { stdId } = req.params;
  const rows = db.prepare('SELECT * FROM assessments WHERE std_id=?').all(stdId);
  const meta = db.prepare('SELECT key,value FROM meta WHERE std_id=?').all(stdId);
  const metaObj = {};
  meta.forEach(r => { metaObj[r.key] = r.value; });

  const wb  = XLSX.utils.book_new();
  const hdr = ['Control ID','Status','Risk','Assessor','Remediation Date','Notes','Finding','Recommendation'];
  const data = [hdr, ...rows.map(r => [
    r.ctrl_id, r.status, r.risk, r.assessor, r.remdate,
    r.notes, r.finding, r.recommendation
  ])];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(data), 'Assessment');

  const summaryData = [
    ['Standard', stdId],
    ['Organization', metaObj.org||''],
    ['Lead Assessor', metaObj.assessor||''],
    ['Assessment Date', metaObj.date||''],
    ['Scope', metaObj.scope||''],
    ['Exported', new Date().toISOString()],
  ];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(summaryData), 'Summary');

  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="GRC_${stdId}_${dateStr()}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

// ── Catch-all → serve SPA ──────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Helpers ────────────────────────────────────────────────────────────
function tryJSON(str, fallback) {
  try { return JSON.parse(str); } catch(e) { return fallback; }
}

function dateStr() { return new Date().toISOString().slice(0, 10); }

function makeAvatarColor(username) {
  let h = 0;
  for (const c of username) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  const cols = ['#58a6ff','#3fb950','#d29922','#e3813b','#f85149','#a371f7','#06b6d4','#ec4899','#ff7b72','#ffa657'];
  return cols[h % cols.length];
}

// ── Start server ──────────────────────────────────────────────────────
initDB();
app.listen(PORT, () => {
  console.log(`GRC Assessment Server running on http://localhost:${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
  console.log(`Uploads directory: ${UPLOADS_DIR}`);
});
