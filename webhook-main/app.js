require('dotenv').config();
const axios = require('axios');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const FormData = require('form-data');
const cron = require('node-cron');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');                // webhook aláírás ellenőrzéshez
const rateLimit = require('express-rate-limit'); // login rate limit
const nodemailer = require('nodemailer');
const PRIVACY_VERSION = process.env.PRIVACY_VERSION || 'v1';

process.env.TZ = process.env.TZ || 'Europe/Budapest';
const APP_TZ = process.env.APP_TZ || 'Europe/Budapest';
const APP_DTF = new Intl.DateTimeFormat('hu-HU', {
    timeZone: APP_TZ,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
});
function toAppTz(utcStr) {
    if (!utcStr) return null;
    const s = String(utcStr).trim();

    // Döntsük el, kell-e 'Z'
    let d;
    if (s.endsWith('Z') || /[+\-]\d{2}:\d{2}$/.test(s)) {
        // Már tartalmaz időzónát (Z vagy +hh:mm) → ne tegyünk hozzá semmit
        d = new Date(s);
    } else if (s.includes('T')) {
        // ISO, de nincs időzóna → kezeljük UTC-ként
        d = new Date(s + 'Z');
    } else {
        // SQLite 'YYYY-MM-DD HH:MM:SS' → alakítsuk ISO-vá és tegyünk 'Z'-t
        d = new Date(s.replace(' ', 'T') + 'Z');
    }

    if (isNaN(d.getTime())) {
        // Ha mégis rossz, ne dobjunk: adjuk vissza az eredetit
        return s || null;
    }

    const p = Object.fromEntries(APP_DTF.formatToParts(d).map(x => [x.type, x.value]));
    return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}


const app = express();

app.set('trust proxy', 1);

const ALLOWED_EMAIL_DOMAINS = (process.env.ALLOWED_EMAIL_DOMAINS||'')
    .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

function isEmailAllowed(email){
    const e = String(email||'').toLowerCase();
    if (!e.includes('@')) return false;
    if (!ALLOWED_EMAIL_DOMAINS.length) return true;            // nincs szűrés
    const domain = e.split('@').pop();
    return ALLOWED_EMAIL_DOMAINS.includes(domain);
}

function validatePassword(pw) {
    if (typeof pw !== 'string') return false;
    const longEnough = pw.length >= 8;
    const hasLower   = /[a-z]/.test(pw);
    const hasUpper   = /[A-Z]/.test(pw);
    const hasDigit   = /\d/.test(pw);
    return longEnough && hasLower && hasUpper && hasDigit;
}

function validateDisplayName(name){
    const s = String(name||'').trim();
    return s.length >= 2 && s.length <= 70;
}

function validateUsername(u){
    if (typeof u !== 'string') return false;
    const s = u.trim().toLowerCase();
    if (s.length < 3 || s.length > 32) return false;
    if (!/^[a-z0-9][a-z0-9._-]*[a-z0-9]$/.test(s)) return false; // betű/szám, ., _, -, nem kezdődik/ér véggel spec-kel
    if (/(\.\.|__|--)/.test(s)) return false;                   // duplák tiltása
    return true;
}

const mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT||587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

async function sendSignupCodeEmail(to, code){
    const from = process.env.MAIL_FROM || '"WhatsApp Panel" <no-reply@example.com>';
    await mailer.sendMail({
        from, to,
        subject: 'Regisztrációs kód',
        text: `A regisztrációs kódod: ${code} (10 percig érvényes)`,
        html: `<p>A regisztrációs kódod: <b>${code}</b></p><p>10 percig érvényes.</p>`
    });
}

// 6 számjegyű kód
function generateCode() {
    // 000000–999999, mindig 6 számjegy
    return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

const signupRequestLimiter = rateLimit({
    windowMs: 15*60*1000, max: 5, standardHeaders:true, legacyHeaders:false
});
const signupVerifyLimiter = rateLimit({
    windowMs: 15*60*1000, max: 15, standardHeaders:true, legacyHeaders:false
});

const recentLocks = new Map(); // key: originalMsgId
function acquireLock(key, ttlMs = 5000) {
    if (!key) return true;        // ha nincs context id, nem lockolunk
    if (recentLocks.has(key)) return false;
    const t = setTimeout(() => recentLocks.delete(key), ttlMs);
    recentLocks.set(key, t);
    return true;
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 perc
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Túl sok bejelentkezési próbálkozás. 15 perc múlva próbáld újra.' }
});
app.use('/admin/auth/login', loginLimiter);

// 👮 Jelszó/Email módosítás rate limit
const passwordChangeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/admin/account/change-password', passwordChangeLimiter);

const emailChangeLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/admin/account/change-email', emailChangeLimiter);

// ── Segédek a .env szerkesztőhöz ─────────────────────────────────────────────
function readEnvItems() {
    const envPath = path.join(__dirname, '.env');
    let text = '';
    try { text = fs.readFileSync(envPath, 'utf-8'); } catch { text = ''; }
    const items = [];
    for (const line of text.split(/\r?\n/)) {
        if (!line || /^\s*#/.test(line)) continue; // komment/üres
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
        if (m) items.push({ key: m[1], value: m[2] });
    }
    return items;
}
function isSensitiveKey(k) {
    // mindent elkap, ami jellemzően titok: token, secret, pass, key stb.
    return /(TOKEN|SECRET|PASSWORD|PASS|API_KEY|APP_SECRET|PRIVATE|KEY$|SMTP_PASS|SESSION_SECRET|ADMIN_SETUP_TOKEN)/i.test(k);
}

function needsRestartKey(k) {
    // pontos egyezések
    const hard = new Set([
        'PORT','NODE_ENV','SESSION_SECRET','PUBLIC_BASE_URL','GRAPH_API_VERSION',
        'APP_TZ','TZ','ALLOWED_EMAIL_DOMAINS','ALLOWED_ORIGINS'
    ]);
    if (hard.has(k)) return true;

    // prefix alapján (induláskor inicializált dolgok)
    const prefixes = ['SMTP_', 'MAIL_', 'DB_', 'SESSION_', 'SCHEDULE_', 'CRON_'];
    return prefixes.some(p => k.startsWith(p));
}

// --- .env frissítő helper ---
function updateEnvFile(updates = {}) {
    try {
        const envPath = path.join(__dirname, '.env');
        let text = '';
        try { text = fs.readFileSync(envPath, 'utf-8'); } catch { text = ''; }
        const lines = text.split(/\r?\n/);
        const kv = {};
        for (const line of lines) {
            const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
            if (m) kv[m[1]] = m[2];
        }
        for (const [k, v] of Object.entries(updates)) {
            if (v === undefined || v === null) continue;
            // egyszerű escape, hogy ne törjük szét a sort
            const safe = String(v).replace(/\r?\n/g, '');
            kv[k] = safe;
            process.env[k] = safe; // azonnali futás közbeni használathoz
        }
        const out = Object.entries(kv).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
        fs.writeFileSync(envPath, out, 'utf-8');
        return true;
    } catch (e) {
        console.error('❌ .env frissítés hiba:', e);
        return false;
    }
}

function maskSecret(s, show = 4) {
    if (!s) return '';
    const n = Math.max(0, s.length - show);
    return '*'.repeat(n) + s.slice(-show);
}

function loadTemplateQuestionnaires() {
    try {
        delete require.cache[require.resolve('./questionnaire')];
        return require('./questionnaire');
    } catch (e) {
        console.error('❌ questionnaire.js betöltési hiba:', e);
        return {};
    }
}

// Sessions fájlhely biztosítása
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

// --- SESSION a védett admin végpontokhoz ---
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.sqlite',
        dir: path.join(__dirname, 'data')
    }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production', // prod alatt csak HTTPS-en
        maxAge: 1000 * 60 * 60 * 8 // 8 óra
    }
}));

app.get('/', (req, res) => {
    if (req.session?.user) return res.redirect('/menu.html');
    return res.redirect('/login.html');
});

// 🔐 HTML oldalak védelme: login + privacy kivétel, admin csak admin/ownernek
const PUBLIC_HTML = new Set(['/login.html', '/privacy.html']);

app.use((req, res, next) => {
    if (req.method === 'GET' && /\.html$/.test(req.path)) {
        if (PUBLIC_HTML.has(req.path)) return next();   // ⬅️ engedjük
        const user = req.session?.user || null;
        if (!user) return res.redirect('/login.html');
        if (req.path === '/admin.html' && !['admin','owner'].includes(user.role)) {
            return res.status(403).send('Nincs jogosultság az admin felülethez.');
        }
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.use('/sent-media', express.static(path.join(__dirname, 'public/sent_media')));
app.use('/uploads',    express.static(path.join(__dirname, 'public/uploads')));
app.use('/kerdoivek',  express.static(path.join(__dirname, 'kerdoivek')));

const port = process.env.PORT || 3000;

const dbPath = path.resolve(__dirname, 'whatsapp_messages.db');
const questionnairesDir = path.join(__dirname, 'kerdoivek');
if (!fs.existsSync(questionnairesDir)) {
    fs.mkdirSync(questionnairesDir);
}
console.log('📂 Adatbázis fájl helye:', dbPath);

const db = new sqlite3.Database(dbPath);

const sessionDbPath = path.join(__dirname, 'data', 'sessions.sqlite');
function killUserSessions(userId){
    return new Promise((resolve) => {
        try{
            const sdb = new sqlite3.Database(sessionDbPath);
            sdb.run(
                `DELETE FROM sessions WHERE sess LIKE ?`,
                [`%"user":{"id":${Number(userId)},%`],
                (/*err*/) => { try{sdb.close();}catch{} resolve(); }
            );
        }catch{ resolve(); }
    });
}

// --- Segédfüggvények promisera (admin API-hoz kényelmes) ---
function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve({ id: this.lastID, changes: this.changes });
        });
    });
}
function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
    });
}
function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}


db.serialize(() => {

    // 🔧 Ellenőrizzük, hogy a "theme" oszlop létezik-e a sent_messages táblában, ha nem, hozzáadjuk
    db.all("PRAGMA table_info(sent_messages)", (err, columns) => {
        if (err) {
            console.error("❌ Nem sikerült lekérni a táblainformációkat:", err);
            return;
        }
        const hasTheme = columns.some(col => col.name === "theme");
        if (!hasTheme) {
            db.run("ALTER TABLE sent_messages ADD COLUMN theme TEXT", (err2) => {
                if (err2) {
                    console.error("❌ Nem sikerült hozzáadni a 'theme' oszlopot:", err2);
                } else {
                    console.log("✅ 'theme' oszlop sikeresen hozzáadva a sent_messages táblához.");
                }
            });
        } else {
            console.log("ℹ️ A 'theme' oszlop már létezik a sent_messages táblában.");
        }
    });

    // 🔧 users táblához privacy mezők (ha még nincsenek)
    db.all("PRAGMA table_info(users)", (err, cols) => {
        if (err) return console.error("❌ PRAGMA users hiba:", err);
        const hasDisplay = cols.some(c => c.name === 'display_name');
        const hasAvatar  = cols.some(c => c.name === 'avatar_url');
        const hasChanged = cols.some(c => c.name === 'display_name_changed_at'); // ‼️ ÚJ

        if (!hasDisplay) {
            db.run("ALTER TABLE users ADD COLUMN display_name TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: display_name", e);
                else   console.log("✅ users.display_name hozzáadva");
            });
        }
        if (!hasAvatar) {
            db.run("ALTER TABLE users ADD COLUMN avatar_url TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: avatar_url", e);
                else   console.log("✅ users.avatar_url hozzáadva");
            });
        }
        if (!hasChanged) {
            db.run("ALTER TABLE users ADD COLUMN display_name_changed_at TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: display_name_changed_at", e);
                else   console.log("✅ users.display_name_changed_at hozzáadva");
            });
        }
    });

    // 🔧 users táblához saját fiók mezők
    db.all("PRAGMA table_info(users)", (err, cols) => {
        if (err) return console.error("❌ PRAGMA users hiba:", err);
        const hasDisplay = cols.some(c => c.name === 'display_name');
        const hasAvatar  = cols.some(c => c.name === 'avatar_url');

        if (!hasDisplay) {
            db.run("ALTER TABLE users ADD COLUMN display_name TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: display_name", e);
                else   console.log("✅ users.display_name hozzáadva");
            });
        }
        if (!hasAvatar) {
            db.run("ALTER TABLE users ADD COLUMN avatar_url TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: avatar_url", e);
                else   console.log("✅ users.avatar_url hozzáadva");
            });
        }
    });

    // 🔧 users.username (opcionális felhasználónév) + case-insensitive egyediség
    db.all("PRAGMA table_info(users)", (err, cols) => {
        if (err) return console.error("❌ PRAGMA users hiba:", err);
        const hasUsername = cols.some(c => c.name === 'username');
        if (!hasUsername) {
            db.run("ALTER TABLE users ADD COLUMN username TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni: username", e);
                else   console.log("✅ users.username hozzáadva");
            });
        }
        // Egyediség eseti indexsel; kis/nagy különbség ne számítson
        db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(lower(username)) WHERE username IS NOT NULL", e => {
            if (e) console.error("❌ Nem sikerült létrehozni az egyedi indexet username-re:", e);
            else    console.log("✅ Egyedi index a users.username mezőre (case-insensitive)");
        });
    });

    // 🔧 users táblához PRIVACY oszlopok (ha még nincsenek)
    db.all("PRAGMA table_info(users)", (err, cols) => {
        if (err) return console.error("❌ PRAGMA users hiba:", err);

        const hasPrivacyAcceptedAt = cols.some(c => c.name === 'privacy_accepted_at');
        const hasPrivacyVersion    = cols.some(c => c.name === 'privacy_version');
        const hasPrivacyIp         = cols.some(c => c.name === 'privacy_accepted_ip');

        if (!hasPrivacyAcceptedAt) {
            db.run("ALTER TABLE users ADD COLUMN privacy_accepted_at TEXT", e =>
                e ? console.error("❌ Nem sikerült hozzáadni: privacy_accepted_at", e)
                    : console.log("✅ users.privacy_accepted_at hozzáadva"));
        }
        if (!hasPrivacyVersion) {
            db.run("ALTER TABLE users ADD COLUMN privacy_version TEXT", e =>
                e ? console.error("❌ Nem sikerült hozzáadni: privacy_version", e)
                    : console.log("✅ users.privacy_version hozzáadva"));
        }
        if (!hasPrivacyIp) {
            db.run("ALTER TABLE users ADD COLUMN privacy_accepted_ip TEXT", e =>
                e ? console.error("❌ Nem sikerült hozzáadni: privacy_accepted_ip", e)
                    : console.log("✅ users.privacy_accepted_ip hozzáadva"));
        }
    });

    // 🔧 messages.in_reply_to oszlop + egyedi index (csak ha nincs), duplikátumok tisztítása előtt
    db.all("PRAGMA table_info(messages)", (err, cols) => {
        if (err) return console.error("❌ PRAGMA hiba:", err);

        const hasInReplyTo = cols.some(c => c.name === 'in_reply_to');

        const ensureIndex = () => {
            // 💡 részleges egyedi index: csak a nem-NULL értékekre
            db.run(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_in_reply_to ON messages(in_reply_to) WHERE in_reply_to IS NOT NULL",
                e => {
                    if (e) console.error("❌ Nem sikerült létrehozni az egyedi indexet:", e);
                    else console.log("✅ Egyedi index kész: idx_messages_in_reply_to");
                }
            );
        };

        const dedupeThenIndex = () => {
            // 🧹 duplikátumok törlése: egy in_reply_to értékből csak a legkisebb ID marad
            db.run(
                `
                    DELETE FROM messages
                    WHERE in_reply_to IS NOT NULL
                      AND id NOT IN (
                        SELECT MIN(id)
                        FROM messages
                        WHERE in_reply_to IS NOT NULL
                        GROUP BY in_reply_to
                    )
                `,
                e => {
                    if (e) console.error("❌ Duplikátum-tisztítás hiba:", e);
                    else console.log("🧹 Duplikátumok törölve a messages.in_reply_to mezőn");
                    ensureIndex();
                }
            );
        };

        if (!hasInReplyTo) {
            db.run("ALTER TABLE messages ADD COLUMN in_reply_to TEXT", e => {
                if (e) console.error("❌ Nem sikerült hozzáadni az in_reply_to oszlopot:", e);
                else console.log("✅ in_reply_to oszlop hozzáadva a messages táblához.");
                dedupeThenIndex();
            });
        } else {
            dedupeThenIndex();
        }
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS contacts (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                wa_id TEXT UNIQUE,
                                                name TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS messages (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                contact_id INTEGER,
                                                message_body TEXT,
                                                message_type TEXT,
                                                received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                wa_message_id TEXT UNIQUE,
                                                FOREIGN KEY(contact_id) REFERENCES contacts(id)
            )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sent_messages (
                                                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                     phone TEXT,
                                                     type TEXT,
                                                     content TEXT,
                                                     timestamp TEXT,
                                                     media_url TEXT,
                                                     wa_message_id TEXT UNIQUE
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS message_metadata (
                                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        message_id INTEGER,
                                                        status TEXT,
                                                        timestamp TEXT,
                                                        error_code INTEGER,
                                                        error_message TEXT,
                                                        FOREIGN KEY(message_id) REFERENCES messages(id)
            )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS scheduled_messages (
                                                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                          phone TEXT NOT NULL,
                                                          type TEXT CHECK(type IN ('message', 'template', 'questionnaire', 'media')),
            content TEXT NOT NULL,
            scheduled_time TEXT NOT NULL,
            sent INTEGER DEFAULT 0
            );
    `);

    // --- Adminhoz szükséges táblák ---
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             email TEXT UNIQUE NOT NULL,
                                             password_hash TEXT NOT NULL,
                                             role TEXT NOT NULL CHECK(role IN ('owner','admin','operator','analyst','viewer')) DEFAULT 'viewer',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
            )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
                                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                  user_id INTEGER,
                                                  action TEXT NOT NULL,
                                                  entity_type TEXT,
                                                  entity_id TEXT,
                                                  meta TEXT,
                                                  ip TEXT,
                                                  user_agent TEXT,
                                                  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                                                  FOREIGN KEY(user_id) REFERENCES users(id)
            )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)`);

    db.run(`
        CREATE TABLE IF NOT EXISTS consents (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                wa_id TEXT NOT NULL,
                                                phone TEXT,
                                                source TEXT,
                                                scope TEXT,
                                                proof TEXT,
                                                granted_at TEXT NOT NULL,
                                                revoked_at TEXT,
                                                UNIQUE(wa_id, scope, granted_at)
            )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_consents_wa ON consents(wa_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_consents_scope ON consents(scope)`);

    db.run(`
        CREATE TABLE IF NOT EXISTS signup_verifications (
                                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                            email TEXT UNIQUE NOT NULL,
                                                            code_hash TEXT NOT NULL,
                                                            expires_at TEXT NOT NULL,
                                                            attempts_left INTEGER NOT NULL DEFAULT 5,
                                                            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS deleted_users (
        id INTEGER,
        email TEXT,
        display_name TEXT,
        role TEXT,
        created_at TEXT,
        last_login TEXT,
        deleted_at TEXT,
        deleted_by INTEGER,
        reason TEXT
      )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_deleted_users_deleted_at ON deleted_users(deleted_at)`);


    // -- MIGRÁCIÓ: engedjük a 'media' típust a scheduled_messages táblában
    db.get(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='scheduled_messages'",
        (err, row) => {
            if (err) return console.error('❌ sqlite_master lekérdezés hiba:', err);
            const createSql = row?.sql || '';
            if (createSql && !createSql.includes("'media'")) {
                console.log("🔧 Migráció: scheduled_messages CHECK bővítése 'media'-val...");
                db.exec(`
        BEGIN TRANSACTION;
        CREATE TABLE scheduled_messages_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          phone TEXT NOT NULL,
          type TEXT CHECK(type IN ('message','template','questionnaire','media')),
          content TEXT NOT NULL,
          scheduled_time TEXT NOT NULL,
          sent INTEGER DEFAULT 0
        );
        INSERT INTO scheduled_messages_new (id, phone, type, content, scheduled_time, sent)
          SELECT id, phone, type, content, scheduled_time, sent
          FROM scheduled_messages;
        DROP TABLE scheduled_messages;
        ALTER TABLE scheduled_messages_new RENAME TO scheduled_messages;
        COMMIT;
      `, (e) => {
                    if (e) console.error('❌ Migrációs hiba:', e);
                    else console.log('✅ Migráció kész: scheduled_messages most már engedi a media típust.');
                });
            }
        }
    );



    console.log('✅ Adatbázis táblák készen állnak');
});

app.use(express.json({
    verify: (req, res, buf) => {
        // a Meta aláírás ellenőrzéshez kell a nyers törzs:
        if (req.originalUrl === '/webhook' && req.method === 'POST') {
            req.rawBody = buf;
        }
    }
}));

// 👮 API-k védése – kivételek: webhook, login, setup
const PUBLIC_API_WHITELIST = new Set([
    '/webhook',               // GET/POST Meta webhook
    '/admin/auth/login',      // bejelentkezés
    '/admin/setup/owner',     // első owner létrehozása
    '/admin/me',              // lekérdezés; ha nincs session, 401
    '/admin/setup/state',
    '/auth/first-owner/verify'
]);

const PROTECTED_PREFIXES = [
    '/send-', '/schedule', '/available-', '/first-', '/get-questionnaire',
    '/contacts', '/messages', '/message-metadata', '/sent-messages',
    '/questionnaire-themes', '/all-questionnaires', '/download-db',
    '/admin/users', '/admin/consents'
];

app.use((req, res, next) => {
    if (PUBLIC_API_WHITELIST.has(req.path)) return next();
    if (PROTECTED_PREFIXES.some(p => req.path.startsWith(p))) {
        if (!req.session?.user) {
            return res.status(401).json({ error: 'Bejelentkezés szükséges.' });
        }
    }
    next();
});


// Webhook verifikáció
app.get('/webhook', (req, res) => {
    const VERIFY_TOKEN = String(process.env.VERIFY_TOKEN || '').trim();
    const mode      = String(req.query['hub.mode'] || '').trim();
    const token     = String(req.query['hub.verify_token'] || '').trim();
    const challenge = req.query['hub.challenge'];

    console.log('Webhook verify hit:', { mode, tokenLen: token.length });

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        return res.status(200).send(String(challenge));
    }
    console.warn('Webhook verify FAILED');
    return res.sendStatus(403);
});


app.get('/available-templates', async (req, res) => {
    const wabaId = process.env.WHATSAPP_BUSINESS_ACCOUNT_ID;
    const accessToken = process.env.ACCESS_TOKEN;


    if (!wabaId || !accessToken) {
        return res.status(500).json({ error: 'WHATSAPP_BUSINESS_ACCOUNT_ID vagy ACCESS_TOKEN hiányzik.' });
    }

    try {
        const response = await axios.get(
            `https://graph.facebook.com/v19.0/${wabaId}/message_templates`,
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );

        const templates = response.data.data || [];

        const simplified = {};

        templates.forEach(tpl => {
            const templateName = tpl.name;
            const parameters = [];

            tpl.components?.forEach(component => {
                if (component.type === 'BODY' && component.text) {
                    const matches = component.text.match(/\{\{\d+\}\}/g);
                    if (matches) {
                        matches.forEach((_, index) => {
                            parameters.push(`Paraméter ${index + 1}`);
                        });
                    }
                }
            });

            const bodyText = tpl.components?.find(c => c.type === 'BODY')?.text
                || tpl.components?.find(c => c.type === 'BODY')?.example?.body_text?.[0]
                || '';

            simplified[templateName] = {
                text: bodyText,
                parameters
            };
        });

        res.json(simplified);

    } catch (error) {
        console.error('❌ Hiba a sablonok lekérésénél:', error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data || 'Ismeretlen hiba történt.' });
    }
});

app.get('/available-template-questionnaires', (req, res) => {
    try {
        delete require.cache[require.resolve('./questionnaire')]; // friss betöltés
        const questionnaires = require('./questionnaire');
        const themes = Object.keys(questionnaires || {});
        res.json(themes);
    } catch (e) {
        console.error("❌ Nem sikerült beolvasni a questionnaire.js fájlt:", e);
        res.status(500).json({ error: "Nem sikerült beolvasni a kérdőíveket" });
    }
});

app.get('/first-templates', (req, res) => {
    try {
        delete require.cache[require.resolve('./questionnaire')];
        const questionnaires = require('./questionnaire');
        const firstTemplates = {};

        for (const theme in questionnaires) {
            const flow = questionnaires[theme];
            const allKeys = Object.keys(flow);
            const allTargets = new Set();

            for (const qId in flow) {
                const nextMap = flow[qId]?.next || {};
                Object.values(nextMap || {}).forEach(target => {
                    if (target) allTargets.add(target);
                });
            }

            const first = allKeys.find(id => !allTargets.has(id));
            if (first) firstTemplates[theme] = first;
        }

        res.json(firstTemplates);
    } catch (e) {
        console.error("❌ Hiba a first-template lekérés során:", e);
        res.status(500).json({ error: "Hiba történt a sablonok feldolgozásakor." });
    }
});

app.get('/get-questionnaire/:theme', (req, res) => {
    try {
        delete require.cache[require.resolve('./questionnaire')];
        const questionnaires = require('./questionnaire');
        const theme = req.params.theme;

        if (!questionnaires[theme]) {
            return res.status(404).json({ error: 'Nincs ilyen kérdőív: ' + theme });
        }

        res.json(questionnaires[theme]);
    } catch (e) {
        console.error("❌ Hiba a kérdőív beolvasásakor:", e);
        res.status(500).json({ error: 'Hiba a kérdőív értelmezésekor.' });
    }
});

// --- RBAC middleware ---
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Bejelentkezés szükséges' });
    next();
}
function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.session.user) return res.status(401).json({ error: 'Bejelentkezés szükséges' });
        if (!roles.includes(req.session.user.role)) {
            return res.status(403).json({ error: 'Nincs jogosultság' });
        }
        next();
    };
}

// --- Audit napló ---
async function logAudit(req, { action, entity_type = null, entity_id = null, meta = null }) {
    try {
        const userId = req?.session?.user?.id || null;
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
        const ua = req.headers['user-agent'] || '';
        await run(
            `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, meta, ip, user_agent)
             VALUES (?,?,?,?,?,?,?)`,
            [userId, action, entity_type, entity_id, meta ? JSON.stringify(meta) : null, ip, ua]
        );
    } catch (e) {
        console.error('Audit log hiba:', e.message);
    }
}

async function logAuditSystem(action, { entity_type = null, entity_id = null, meta = null } = {}) {
    try {
        const ip = '127.0.0.1';
        const ua = 'cron';
        await run(
            `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, meta, ip, user_agent)
             VALUES (?,?,?,?,?,?,?)`,
            [null, action, entity_type, entity_id, meta ? JSON.stringify(meta) : null, ip, ua]
        );
    } catch (e) {
        console.error('Audit log (system) hiba:', e.message);
    }
}

async function is24hOpen(phone) {
    const row = await get(`
        SELECT MAX(messages.received_at) AS last
        FROM messages
            JOIN contacts ON contacts.id = messages.contact_id
        WHERE contacts.wa_id = ?
    `, [phone]);
    if (!row || !row.last) return false;
    return (Date.now() - Date.parse(row.last)) <= 24 * 60 * 60 * 1000;
}

function asArray(x){ return Array.isArray(x) ? x : [x].filter(Boolean); }

function enforce24hForFreeform() {
    return async (req, res, next) => {
        const phones = asArray(req.body.phone);
        if (!phones.length) return res.status(400).json({ error: 'phone kötelező' });
        for (const p of phones) {
            const open = await is24hOpen(p);
            if (!open) {
                return res.status(403).json({
                    error: `A 24 órás ablak zárva ennél: ${p}. Ilyenkor csak sablon (template) küldhető.`
                });
            }
        }
        next();
    };
}

// --- Admin első tulaj (owner) létrehozása ---
app.post('/admin/setup/owner', async (req, res) => {
    try {
        const token = req.get('x-setup-token');
        if (!token || token !== (process.env.ADMIN_SETUP_TOKEN || '')) {
            return res.status(403).json({ error: 'Érvénytelen setup token' });
        }
        const existing = await get(`SELECT COUNT(1) as c FROM users`);
        if (existing && existing.c > 0) {
            return res.status(400).json({ error: 'Már létezik felhasználó, a setup lezárult' });
        }

        const { email, password, username, display_name } = req.body || {};
        if (!email || !password || !display_name)
            return res.status(400).json({ error: 'email, password, display_name kötelező' });
        if (!validateDisplayName(display_name))
            return res.status(400).json({ error: 'A név 2–70 karakter legyen.' });

        // ⬇️ opcionális felhasználónév
        let uname = null;
        if (username && String(username).trim()) {
            uname = String(username).trim().toLowerCase();
            if (!validateUsername(uname)) {
                return res.status(400).json({ error: 'Érvénytelen felhasználónév.' });
            }
            const existsU = await get(`SELECT id FROM users WHERE lower(username)=lower(?)`, [uname]);
            if (existsU) return res.status(409).json({ error: 'Ez a felhasználónév már foglalt' });
        }

        const hash = await bcrypt.hash(password, 12);
        const { id } = await run(
            `INSERT INTO users (email, username, display_name, display_name_changed_at, password_hash, role)
           VALUES (?,?,?,?,?, 'owner')`,
            [email.toLowerCase(), uname, display_name.trim(), new Date().toISOString(), hash]
        );
        await logAudit(req, { action: 'SETUP_OWNER', entity_type: 'user', entity_id: String(id) });
        return res.json({ ok: true, user_id: id });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Szerver hiba' });
    }
});

// --- Bejelentkezés/Kilépés/Me ---
app.post('/admin/auth/login', async (req, res) => {
    try {
        const { identifier, email, password } = req.body || {};
        const loginId = (identifier || email || '').trim();
        if (!loginId || !password) return res.status(400).json({ error: 'azonosító és jelszó kötelező' });

        let user = null;
        if (loginId.includes('@')) {
            user = await get(`SELECT * FROM users WHERE email = ?`, [loginId.toLowerCase()]);
        } else {
            user = await get(`SELECT * FROM users WHERE username = ?`, [loginId.toLowerCase()]);
        }
        if (!user) return res.status(401).json({ error: 'Hibás bejelentkezési adatok' });

        const ok = await bcrypt.compare(String(password), user.password_hash);
        if (!ok) return res.status(401).json({ error: 'Hibás bejelentkezési adatok' });

        req.session.user = { id: user.id, email: user.email, role: user.role, username: user.username || null };
        await run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);
        await logAudit(req, { action: 'LOGIN', entity_type: 'user', entity_id: String(user.id) });

        res.json({ ok: true, me: req.session.user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// --- Saját fiók: lekérés
app.get('/admin/account', requireAuth, async (req, res) => {
    try{
        const row = await get(
            `SELECT id, email, username, role, display_name, avatar_url,
              created_at, last_login,
              privacy_accepted_at, privacy_version, privacy_accepted_ip,
              display_name_changed_at
         FROM users
        WHERE id = ?`,
            [req.session.user.id]
        );
        if (!row) return res.status(404).json({ error: 'Felhasználó nem található' });

        // átkonvertált időpontok megjelenítéshez
        const me = {
            id: row.id,
            email: row.email,
            username: row.username,
            role: row.role,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            created_at: toAppTz(row.created_at),
            last_login: toAppTz(row.last_login),
            privacy_accepted_at: toAppTz(row.privacy_accepted_at),
            privacy_version: row.privacy_version,
            privacy_accepted_ip: row.privacy_accepted_ip,
            display_name_changed_at: toAppTz(row.display_name_changed_at)
        };

        // 30 napos lock
        let name_change_locked = false, name_locked_until = null;
        if (row.display_name_changed_at) {
            const nextMs = Date.parse(row.display_name_changed_at) + 30*24*60*60*1000;
            name_change_locked = Date.now() < nextMs;
            name_locked_until  = toAppTz(new Date(nextMs).toISOString());
        }

        return res.json({ me: { ...me, name_change_locked, name_locked_until } });
    }catch(e){
        console.error(e);
        return res.status(500).json({ error:'Szerver hiba' });
    }
});

// --- Saját fiók: profil (display_name + username) frissítés
app.patch('/admin/account', requireAuth, async (req, res) => {
    try{
        const { display_name, username } = req.body || {};
        const me = await get(`SELECT id, display_name, display_name_changed_at FROM users WHERE id=?`, [req.session.user.id]);
        if (!me) return res.status(404).json({ error:'Felhasználó nem található' });

        // username (opcionális)
        let uname = null;
        if (username && String(username).trim()) {
            uname = String(username).trim().toLowerCase();
            if (!validateUsername(uname)) {
                return res.status(400).json({ error:'Érvénytelen felhasználónév. 3–32 karakter; betű/szám, ".", "_", "-" engedélyezett; duplák tiltva.' });
            }
            const exists = await get(`SELECT id FROM users WHERE lower(username)=lower(?) AND id<>?`, [uname, req.session.user.id]);
            if (exists) return res.status(409).json({ error:'Ez a felhasználónév már foglalt.' });
        }

        // display_name (kötelező)
        if (typeof display_name !== 'string' || !validateDisplayName(display_name)) {
            return res.status(400).json({ error:'A név 2–70 karakter legyen.' });
        }
        const newName = display_name.trim();
        const isNameChange = (newName !== (me.display_name || ''));

        // 30 napos limit – első beállítás (ha eddig nem volt) bármikor mehet
        if (isNameChange && me.display_name && me.display_name_changed_at) {
            const nextMs = Date.parse(me.display_name_changed_at) + 30*24*60*60*1000;
            if (Date.now() < nextMs) {
                const until = toAppTz(new Date(nextMs).toISOString());
                return res.status(400).json({ error:`A név 30 naponta módosítható. Következő leghamarabb: ${until}` });
            }
        }

        if (isNameChange) {
            await run(`UPDATE users SET display_name=?, display_name_changed_at=CURRENT_TIMESTAMP, username=? WHERE id=?`,
                [newName, uname, req.session.user.id]);
        } else {
            await run(`UPDATE users SET username=? WHERE id=?`, [uname, req.session.user.id]);
        }

        await logAudit(req, {
            action: 'ACCOUNT_UPDATE',
            entity_type: 'user',
            entity_id: String(req.session.user.id),
            meta: { display_name: newName, username: uname || null }
        });
        req.session.user.username = uname || null;

        // vissza a friss me + lock infók
        const fresh = await get(`SELECT * FROM users WHERE id=?`, [req.session.user.id]);
        const rsp = {
            id: fresh.id,
            email: fresh.email,
            username: fresh.username,
            role: fresh.role,
            display_name: fresh.display_name,
            created_at: toAppTz(fresh.created_at),
            last_login: toAppTz(fresh.last_login),
            privacy_accepted_at: toAppTz(fresh.privacy_accepted_at),
            privacy_version: fresh.privacy_version,
            privacy_accepted_ip: fresh.privacy_accepted_ip,
            display_name_changed_at: toAppTz(fresh.display_name_changed_at)
        };
        let name_change_locked = false, name_locked_until = null;
        if (fresh.display_name_changed_at) {
            const nextMs = Date.parse(fresh.display_name_changed_at) + 30*24*60*60*1000;
            name_change_locked = Date.now() < nextMs;
            name_locked_until  = toAppTz(new Date(nextMs).toISOString());
        }
        return res.json({ me: { ...rsp, name_change_locked, name_locked_until } });
    }catch(e){
        console.error(e);
        return res.status(500).json({ error:'Szerver hiba' });
    }
});

// --- Saját fiók: jelszó módosítás
app.post('/admin/account/change-password', requireAuth, async (req, res) => {
    try {
        const { current_password, new_password } = req.body || {};
        if (!current_password || !new_password)
            return res.status(400).json({ error: 'current_password és new_password kötelező' });

        const user = await get(`SELECT id, password_hash FROM users WHERE id = ?`, [req.session.user.id]);
        if (!user) return res.status(404).json({ error: 'Felhasználó nem található' });

        const ok = await bcrypt.compare(String(current_password), user.password_hash);
        if (!ok) return res.status(400).json({ error: 'Hibás jelenlegi jelszó' });

        if (!validatePassword(new_password)) {
            return res.status(400).json({ error: 'Gyenge jelszó. Min. 8 karakter, kis- és nagybetű, szám szükséges.' });
        }

        const hash = await bcrypt.hash(String(new_password), 12);
        await run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hash, req.session.user.id]);
        await logAudit(req, { action: 'ACCOUNT_PASSWORD_CHANGE', entity_type: 'user', entity_id: String(req.session.user.id) });

        return res.json({ ok: true, message: 'Jelszó frissítve' });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Szerver hiba' });
    }
});

// --- Saját fiók: email csere (opcionális)
app.post('/admin/account/change-email', requireAuth, async (req, res) => {
    try {
        const { new_email, password } = req.body || {};
        if (!new_email || !password)
            return res.status(400).json({ error: 'new_email és password kötelező' });

        // csak megengedett domain
        if (!isEmailAllowed(new_email)) {
            return res.status(400).json({ error: 'Ez az email domain nem engedélyezett.' });
        }

        const user = await get(`SELECT id, email, password_hash FROM users WHERE id = ?`, [req.session.user.id]);
        if (!user) return res.status(404).json({ error: 'Felhasználó nem található' });
        const ok = await bcrypt.compare(String(password), user.password_hash);
        if (!ok) return res.status(400).json({ error: 'Hibás jelszó' });

        // egyediség
        const exists = await get(`SELECT id FROM users WHERE email = ?`, [String(new_email).toLowerCase()]);
        if (exists) return res.status(409).json({ error: 'Ez az email már használatban van' });

        await run(`UPDATE users SET email = ? WHERE id = ?`, [String(new_email).toLowerCase(), req.session.user.id]);

        // session frissítés
        req.session.user.email = String(new_email).toLowerCase();

        await logAudit(req, {
            action: 'ACCOUNT_EMAIL_CHANGE',
            entity_type: 'user',
            entity_id: String(req.session.user.id),
            meta: { old: user.email, new: String(new_email).toLowerCase() }
        });

        return res.json({ ok: true, me: req.session.user });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.post('/admin/account/delete', requireAuth, async (req, res) => {
    try{
        const meId = req.session.user.id;
        const me = await get(`SELECT * FROM users WHERE id=?`, [meId]);
        if (!me) return res.status(404).json({ error: 'Felhasználó nem található' });

        const ownersLeft = await get(`SELECT COUNT(1) AS c FROM users WHERE role='owner' AND id <> ?`, [meId]);
        if ((ownersLeft?.c || 0) === 0) {
            return res.status(400).json({ error: 'Az utolsó ownert nem lehet törölni.' });
        }

        await run(
            `INSERT INTO deleted_users (id,email,display_name,role,created_at,last_login,deleted_at,deleted_by,reason)
       VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP,?,?)`,
            [me.id, me.email, me.display_name || null, me.role, me.created_at, me.last_login, meId, 'self-delete']
        );
        await run(`DELETE FROM users WHERE id=?`, [meId]);

        await killUserSessions(meId);
        await logAudit(req, { action: 'ACCOUNT_SELF_DELETE', entity_type: 'user', entity_id: String(meId) });

        req.session.destroy(() => res.json({ ok:true }));
    }catch(e){
        console.error(e);
        return res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.post('/admin/auth/logout', requireAuth, async (req, res) => {
    await logAudit(req, { action: 'LOGOUT' });
    req.session.destroy(() => res.json({ ok: true }));
});

app.get('/admin/me', requireAuth, (req, res) => {
    res.json({ me: req.session.user });
});

// --- (opcionális) új user létrehozása adminnak ---
app.post('/admin/users', requireRole('owner','admin'), async (req, res) => {
    try {
        const { email, password, role = 'viewer' } = req.body || {};
        if (!email || !password) return res.status(400).json({ error: 'email és password kötelező' });
        if (!['owner','admin','operator','analyst','viewer'].includes(role)) {
            return res.status(400).json({ error: 'Ismeretlen szerepkör' });
        }
        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Gyenge jelszó. Min. 8 karakter, kis- és nagybetű, szám szükséges.' });
        }
        const hash = await bcrypt.hash(password, 12);
        const { id } = await run(
            `INSERT INTO users (email, password_hash, role) VALUES (?,?,?)`,
            [email.toLowerCase(), hash, role]
        );
        await logAudit(req, { action: 'CREATE_USER', entity_type: 'user', entity_id: String(id), meta: { role } });
        res.json({ ok: true, id });
    } catch (e) {
        if (String(e.message || '').includes('UNIQUE')) {
            return res.status(409).json({ error: 'Ez az email már létezik' });
        }
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// --- Audit logok listázása (owner/admin) ---
app.get('/admin/audit', requireRole('owner','admin'), async (req,res)=>{
    try{
        const { q = '', action = '', user_id = '', limit = 200 } = req.query;

        const where = [];
        const args  = [];

        if (action) {
            where.push('action = ?');
            args.push(action);
        }
        if (user_id) {
            where.push('user_id = ?');
            args.push(Number(user_id));
        }
        if (q) {
            where.push('(entity_type LIKE ? OR entity_id LIKE ? OR meta LIKE ? OR ip LIKE ? OR user_agent LIKE ?)');
            args.push(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`);
        }

        const sql = `
      SELECT id, user_id, action, entity_type, entity_id, meta, ip, user_agent,
             datetime(created_at,'localtime') AS created_at
      FROM audit_logs
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY created_at DESC
      LIMIT ?
    `;
        args.push(Math.min(Number(limit) || 200, 1000)); // ne lehessen túl nagy

        const rows = await all(sql, args);
        res.json({ items: rows });
    }catch(e){
        res.status(500).json({ error:'Szerver hiba' });
    }
});

// --- Consents (opt-in) ---
app.get('/admin/consents', requireRole('owner','admin','analyst','operator'), async (req, res) => {
    try {
        const { wa_id, scope } = req.query;
        const conds = [];
        const args = [];
        if (wa_id) { conds.push('wa_id = ?'); args.push(wa_id); }
        if (scope) { conds.push('scope = ?'); args.push(scope); }
        const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
        const rows = await all(
            `SELECT id, wa_id, phone, source, scope, proof, granted_at, revoked_at
             FROM consents
                      ${where}
             ORDER BY granted_at DESC`,
            args
        );
        for (const r of rows) {
            r.granted_at = toAppTz(r.granted_at);
            r.revoked_at = toAppTz(r.revoked_at);
        }
        res.json({ items: rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// Felhasználók listája (owner/admin)
app.get('/admin/users', requireRole('owner','admin'), async (req, res) => {
    try {
        const rows = await all(
            `SELECT id, email, username, display_name, role, created_at, last_login
             FROM users
             ORDER BY id ASC`
        );
        for (const r of rows) {
            r.created_at = toAppTz(r.created_at);
            r.last_login = toAppTz(r.last_login);
        }
        res.json({ items: rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// Szerep módosítása (owner/admin) – owner szerep nem írható felül
app.patch('/admin/users/:id', requireRole('owner','admin'), async (req, res) => {
    try {
        const id = Number(req.params.id);
        const { role } = req.body || {};
        if (!['viewer','analyst','operator','admin','owner'].includes(role)) {
            return res.status(400).json({ error: 'Ismeretlen szerep' });
        }
        const target = await get(`SELECT id, role FROM users WHERE id = ?`, [id]);
        if (!target) return res.status(404).json({ error: 'Nincs ilyen felhasználó' });
        if (target.role === 'owner' && role !== 'owner') {
            return res.status(400).json({ error: 'Owner szerep nem módosítható' });
        }
        await run(`UPDATE users SET role = ? WHERE id = ?`, [role, id]);
        await logAudit(req, { action: 'UPDATE_USER_ROLE', entity_type: 'user', entity_id: String(id), meta: { role } });
        res.json({ ok: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.delete('/admin/users/:id', requireRole('owner'), async (req, res) => {
    try{
        const id = Number(req.params.id);
        const { reason } = req.body || {};

        const target = await get(`SELECT * FROM users WHERE id = ?`, [id]);
        if (!target) return res.status(404).json({ error: 'Nincs ilyen felhasználó' });

        if (target.role === 'owner') {
            const ownersLeft = await get(`SELECT COUNT(1) AS c FROM users WHERE role='owner' AND id <> ?`, [id]);
            if ((ownersLeft?.c || 0) === 0) {
                return res.status(400).json({ error: 'Az utolsó ownert nem lehet törölni.' });
            }
        }

        await run(
            `INSERT INTO deleted_users (id,email,display_name,role,created_at,last_login,deleted_at,deleted_by,reason)
             VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP,?,?)`,
            [target.id, target.email, target.display_name || null, target.role, target.created_at, target.last_login, req.session.user.id, reason || null]
        );
        await run(`DELETE FROM users WHERE id = ?`, [id]);

        await killUserSessions(id);

        await logAudit(req, {
            action: 'DELETE_USER',
            entity_type: 'user',
            entity_id: String(id),
            meta: { email: target.email, role: target.role, reason: reason || null }
        });

        return res.json({ ok:true });
    }catch(e){
        console.error(e);
        return res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.post('/admin/consents', requireRole('owner','admin','operator'), async (req, res) => {
    try {
        const { wa_id, phone, source, scope, proof, granted_at } = req.body || {};
        if (!wa_id || !scope) return res.status(400).json({ error: 'wa_id és scope kötelező' });
        const when = granted_at || new Date().toISOString();
        const { id } = await run(
            `INSERT INTO consents (wa_id, phone, source, scope, proof, granted_at)
             VALUES (?,?,?,?,?,?)`,
            [wa_id, phone || null, source || null, scope, proof || null, when]
        );
        await logAudit(req, { action: 'CREATE_CONSENT', entity_type: 'consent', entity_id: String(id), meta: { wa_id, scope } });
        res.json({ ok: true, id });
    } catch (e) {
        if (String(e.message || '').includes('UNIQUE')) {
            return res.status(409).json({ error: 'Duplikált hozzájárulás (wa_id/scope/granted_at)' });
        }
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.post('/admin/consents/:id/revoke', requireRole('owner','admin','operator'), async (req, res) => {
    try {
        const id = req.params.id;
        const when = req.body?.revoked_at || new Date().toISOString();
        const { changes } = await run(`UPDATE consents SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, [when, id]);
        if (!changes) return res.status(404).json({ error: 'Nem található vagy már visszavont' });
        await logAudit(req, { action: 'REVOKE_CONSENT', entity_type: 'consent', entity_id: String(id) });
        res.json({ ok: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// Első indítás állapot – ha nincs még user, a regisztráció owner módba vált
app.get('/admin/setup/state', async (req, res) => {
    try {
        const row = await get(`SELECT COUNT(1) AS c FROM users`);
        const users = Number(row?.c || 0);
        res.json({ users, needs_owner: users === 0 });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

// WhatsApp/Meta beállítások lekérdezése (owner)
app.get('/admin/config/whatsapp', requireRole('owner'), (req, res) => {
    const cfg = {
        WHATSAPP_BUSINESS_ACCOUNT_ID: process.env.WHATSAPP_BUSINESS_ACCOUNT_ID || '',
        PHONE_NUMBER_ID: process.env.PHONE_NUMBER_ID || '',
        ACCESS_TOKEN_MASKED: maskSecret(process.env.ACCESS_TOKEN || ''),
        VERIFY_TOKEN_MASKED: maskSecret(process.env.VERIFY_TOKEN || '')
    };
    res.json({ config: cfg });
});

// WhatsApp/Meta beállítások mentése (owner)
app.put('/admin/config/whatsapp', requireRole('owner'), async (req, res) => {
    try {
        const { WHATSAPP_BUSINESS_ACCOUNT_ID, PHONE_NUMBER_ID, ACCESS_TOKEN, VERIFY_TOKEN } = req.body || {};
        if (!WHATSAPP_BUSINESS_ACCOUNT_ID || !PHONE_NUMBER_ID) {
            return res.status(400).json({ error: 'WHATSAPP_BUSINESS_ACCOUNT_ID és PHONE_NUMBER_ID kötelező.' });
        }
        const ok = updateEnvFile({
            WHATSAPP_BUSINESS_ACCOUNT_ID,
            PHONE_NUMBER_ID,
            // tokenek opcionálisan frissíthetők – csak akkor írjuk, ha tényleg kaptunk újat
            ...(ACCESS_TOKEN ? { ACCESS_TOKEN } : {}),
            ...(VERIFY_TOKEN ? { VERIFY_TOKEN } : {})
        });
        if (!ok) return res.status(500).json({ error: '.env frissítés sikertelen' });

        await logAudit(req, { action: 'UPDATE_WHATSAPP_CONFIG', entity_type: 'config' });
        res.json({ ok: true, message: 'Beállítások frissítve (.env is)!' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba (config save)' });
    }
});

// ── .env: listázás (owner) ──────────────────────────────────────────────────
app.get('/admin/config/env', requireRole('owner'), (req, res) => {
    const items = readEnvItems().map(({ key, value }) => ({
        key,
        value: isSensitiveKey(key) ? maskSecret(value) : value,
        sensitive: isSensitiveKey(key),
        restart: needsRestartKey(key)      // ⬅️ ÚJ
    }));
    items.sort((a,b) => Number(b.sensitive) - Number(a.sensitive) || a.key.localeCompare(b.key));
    res.json({ items });
});

// ── .env: mentés (owner) ────────────────────────────────────────────────────
// Body: { updates: { KEY: "ertek", ... } }
// Titkos mezőknél a frontend csak akkor küld értéket, ha tényleg cserélni akarja.
app.put('/admin/config/env', requireRole('owner'), async (req, res) => {
    const updates = req.body?.updates || {};
    if (typeof updates !== 'object') {
        return res.status(400).json({ error: 'updates objektum kell' });
    }

    // csak a .env-ben már létező kulcsokat engedjük írni
    const existing = new Set(readEnvItems().map(i => i.key));
    const filtered = {};
    for (const [k, v] of Object.entries(updates)) {
        if (!existing.has(k)) continue;                         // csak meglévő kulcs
        if (isSensitiveKey(k) && (v === '' || v == null)) continue; // titoknál üres = ne írd felül
        filtered[k] = String(v);
    }

    if (!Object.keys(filtered).length) {
        return res.json({ ok: true, message: 'Nincs mentendő változás', restartNeeded: false, restartKeys: [] });
    }

    const ok = updateEnvFile(filtered);
    if (!ok) return res.status(500).json({ error: '.env frissítés sikertelen' });

    const restartKeys = Object.keys(filtered).filter(k => needsRestartKey(k));

    await logAudit(req, { action: 'UPDATE_ENV', entity_type: 'config', meta: Object.keys(filtered) });

    res.json({
        ok: true,
        message: 'Beállítások frissítve (.env)!',
        restartNeeded: restartKeys.length > 0,
        restartKeys
    });
});

// 🆕 Publikus regisztráció (opcionális, .env ALLOW_SELF_SIGNUP=true esetén)
app.post('/auth/register', async (req, res) => {
    try {
        if (process.env.ALLOW_SELF_SIGNUP !== 'true') {
            return res.status(403).json({ error: 'A regisztráció le van tiltva.' });
        }
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).json({ error: 'email és password kötelező' });

        const role = process.env.DEFAULT_ROLE_ON_SIGNUP || 'viewer';
        if (!['viewer','analyst','operator','admin','owner'].includes(role)) return res.status(400).json({ error: 'Rossz alap szerep' });

        const existing = await get(`SELECT id FROM users WHERE email = ?`, [email.toLowerCase()]);
        if (existing) return res.status(409).json({ error: 'Ez az email már regisztrált' });

        const hash = await bcrypt.hash(password, 12);
        const { id } = await run(`INSERT INTO users (email, password_hash, role) VALUES (?,?,?)`,
            [email.toLowerCase(), hash, role]);

        // automatikus beléptetés
        req.session.user = { id, email: email.toLowerCase(), role };
        await logAudit(req, { action: 'SELF_REGISTER', entity_type: 'user', entity_id: String(id), meta: { role } });

        res.json({ ok: true, me: req.session.user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba' });
    }
});

app.post('/auth/signup/request', async (req,res)=>{
    try{
        const { email } = req.body || {};
        if (!email) return res.status(400).json({ error:'email kötelező' });
        if (!isEmailAllowed(email)) return res.status(400).json({ error:'Ez az email domain nem engedélyezett.' });

        const existing = await get(`SELECT id FROM users WHERE email=?`, [email.toLowerCase()]);
        if (existing) return res.status(409).json({ error:'Ez az email már regisztrált' });

        const code = generateCode();
        const code_hash = await bcrypt.hash(code, 12);
        const expires_at = new Date(Date.now()+10*60*1000).toISOString(); // 10 perc

        await run(`
            INSERT INTO signup_verifications (email, code_hash, expires_at, attempts_left)
            VALUES (?,?,?,5)
                ON CONFLICT(email) DO UPDATE SET
                code_hash=excluded.code_hash,
                                          expires_at=excluded.expires_at,
                                          attempts_left=5,
                                          created_at=CURRENT_TIMESTAMP
        `, [email.toLowerCase(), code_hash, expires_at]);

        await sendSignupCodeEmail(email, code);
        await logAudit(req, { action:'SIGNUP_CODE_SENT', entity_type:'user', entity_id: email.toLowerCase() });
        res.json({ ok:true, message:'A kódot elküldtük az email címedre.' });
    }catch(e){
        console.error(e);
        res.status(500).json({ error:'Szerver hiba a kód küldésekor' });
    }
});

app.post('/auth/signup/verify', async (req,res)=>{
    try{
        const { email, code, password, acceptPrivacy, username, display_name } = req.body || {};
        if (acceptPrivacy !== true) {
            return res.status(400).json({ error: 'A regisztrációhoz el kell fogadni az adatkezelési tájékoztatót.' });
        }
        if (!email || !code || !password) {
            return res.status(400).json({ error:'email, code, password kötelező' });
        }

        if (!display_name || !validateDisplayName(display_name))
            return res.status(400).json({ error:'Adj meg egy 2–70 karakter hosszú nevet.' });

        const row = await get(`SELECT * FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
        if (!row) return res.status(400).json({ error:'Nincs aktív kód ehhez az emailhez' });
        if (Date.parse(row.expires_at) < Date.now()){
            await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error:'A kód lejárt. Kérj újat.' });
        }
        if (row.attempts_left <= 0){
            await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error:'Túl sok hibás próbálkozás. Kérj új kódot.' });
        }

        const okCode = await bcrypt.compare(String(code), row.code_hash);
        if (!okCode){
            await run(`UPDATE signup_verifications SET attempts_left=attempts_left-1 WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error:'Hibás kód' });
        }

        if (!isEmailAllowed(email)) return res.status(400).json({ error:'Ez az email domain nem engedélyezett.' });
        const already = await get(`SELECT id FROM users WHERE email=?`, [email.toLowerCase()]);
        if (already) {
            await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
            return res.status(409).json({ error:'Ez az email már regisztrált' });
        }

        // ⬇️ opcionális felhasználónév ellenőrzése + egyediség
        let uname = null;
        if (username && String(username).trim()) {
            uname = String(username).trim().toLowerCase();
            if (!validateUsername(uname)) {
                return res.status(400).json({ error: 'Érvénytelen felhasználónév. 3–32 karakter; betűk/számok, ".", "_", "-" engedélyezett; duplák (.. __ --) tiltva.' });
            }
            const existsU = await get(`SELECT id FROM users WHERE lower(username)=lower(?)`, [uname]);
            if (existsU) return res.status(409).json({ error: 'Ez a felhasználónév már foglalt.' });
        }

        const hash = await bcrypt.hash(password, 12);
        const defaultRole = process.env.DEFAULT_ROLE_ON_SIGNUP || 'viewer';
        const { id } = await run(
            `INSERT INTO users (email, username, display_name, display_name_changed_at, password_hash, role)
             VALUES (?,?,?,?,?,?)`,
            [email.toLowerCase(), uname, display_name.trim(), new Date().toISOString(), hash, defaultRole]
        );

        // elfogadás mentése
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.socket.remoteAddress || null;
        await run(
            `UPDATE users
             SET privacy_accepted_at=CURRENT_TIMESTAMP,
                 privacy_version=?,
                 privacy_accepted_ip=?
             WHERE id=?`,
            [PRIVACY_VERSION, clientIp, id]
        );
        await logAudit(req, {
            action:'PRIVACY_ACCEPT',
            entity_type:'user',
            entity_id:String(id),
            meta:{ version: PRIVACY_VERSION }
        });

        await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);

        // ⬇️ session tartalmazza a felhasználónevet is
        req.session.user = { id, email: email.toLowerCase(), role: defaultRole, username: uname };
        await logAudit(req, { action:'SIGNUP_COMPLETED', entity_type:'user', entity_id:String(id) });

        res.json({ ok:true, me:req.session.user });
    }catch(e){
        console.error(e);
        res.status(500).json({ error:'Szerver hiba a regisztráció befejezésekor' });
    }
});

// Első Owner regisztráció befejezése (OTP kód + WABA adatok) — csak ha még nincs user
app.post('/auth/first-owner/verify', async (req, res) => {
    try {
        const rc = await get(`SELECT COUNT(1) AS c FROM users`);
        if (Number(rc?.c || 0) > 0) {
            return res.status(400).json({ error: 'Már létezik felhasználó, az első owner létrehozása lezárult.' });
        }

        const { email, code, password, acceptPrivacy, username, display_name,
            waba_id, phone_number_id, access_token, verify_token } = req.body || {};

        if (acceptPrivacy !== true) return res.status(400).json({ error: 'El kell fogadni az adatkezelési tájékoztatót.' });
        if (!email || !code || !password || !display_name) return res.status(400).json({ error: 'Hiányzó kötelező mezők.' });
        if (!waba_id || !phone_number_id || !access_token || !verify_token) {
            return res.status(400).json({ error: 'Hiányoznak a WhatsApp/Meta mezők (WABA_ID, PHONE_NUMBER_ID, ACCESS_TOKEN, VERIFY_TOKEN).' });
        }

        // OTP ellenőrzés – ugyanaz a logika, mint /auth/signup/verify
        const row = await get(`SELECT * FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
        if (!row) return res.status(400).json({ error: 'Nincs aktív kód ehhez az emailhez' });
        if (Date.parse(row.expires_at) < Date.now()) {
            await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error: 'A kód lejárt. Kérj újat.' });
        }
        if (row.attempts_left <= 0) {
            await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error: 'Túl sok hibás próbálkozás. Kérj új kódot.' });
        }
        const okCode = await bcrypt.compare(String(code), row.code_hash);
        if (!okCode) {
            await run(`UPDATE signup_verifications SET attempts_left=attempts_left-1 WHERE email=?`, [email.toLowerCase()]);
            return res.status(400).json({ error: 'Hibás kód' });
        }

        // opcionális username ellenőrzés
        let uname = null;
        if (username && String(username).trim()) {
            uname = String(username).trim().toLowerCase();
            if (!validateUsername(uname)) return res.status(400).json({ error: 'Érvénytelen felhasználónév.' });
            const existsU = await get(`SELECT id FROM users WHERE lower(username)=lower(?)`, [uname]);
            if (existsU) return res.status(409).json({ error: 'Ez a felhasználónév már foglalt.' });
        }

        const hash = await bcrypt.hash(password, 12);
        const { id } = await run(
            `INSERT INTO users (email, username, display_name, display_name_changed_at, password_hash, role)
             VALUES (?,?,?,?,?,'owner')`,
            [email.toLowerCase(), uname, display_name.trim(), new Date().toISOString(), hash]
        );

        // privacy log
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null;
        await run(
            `UPDATE users SET privacy_accepted_at=CURRENT_TIMESTAMP, privacy_version=?, privacy_accepted_ip=? WHERE id=?`,
            [PRIVACY_VERSION, clientIp, id]
        );
        await run(`DELETE FROM signup_verifications WHERE email=?`, [email.toLowerCase()]);
        await logAudit(req, { action: 'FIRST_OWNER_CREATED', entity_type: 'user', entity_id: String(id) });

        // .env frissítése
        const ok = updateEnvFile({
            WHATSAPP_BUSINESS_ACCOUNT_ID: waba_id,
            PHONE_NUMBER_ID: phone_number_id,
            ACCESS_TOKEN: access_token,
            VERIFY_TOKEN: verify_token
        });
        if (!ok) return res.status(500).json({ error: '.env frissítés sikertelen' });

        // beléptetés
        req.session.user = { id, email: email.toLowerCase(), role: 'owner', username: uname || null };
        return res.json({ ok: true, me: req.session.user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Szerver hiba (first-owner verify)' });
    }
});

app.post('/send-message', requireRole('operator','admin','owner'), enforce24hForFreeform(), async (req, res) => {
    const phoneInput = req.body.phone;
    const message = req.body.message;
    const contentId = req.body.content || message;
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    if (!phoneInput || !message) {
        return res.status(400).json({ message: 'Hiányzó adat (telefonszám vagy üzenet)' });
    }

    const phones = Array.isArray(phoneInput) ? phoneInput : [phoneInput];
    const results = [];

    for (const phone of phones) {
        try {
            const sendRes = await axios.post(
                `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
                {
                    messaging_product: 'whatsapp',
                    to: phone,
                    type: 'text',
                    text: { preview_url: false, body: message }
                },
                {
                    headers: {
                        Authorization: `Bearer ${accessToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            const msgId = sendRes.data?.messages?.[0]?.id;
            if (msgId) {
                await logAudit(req, {
                    action: 'SEND_MESSAGE',
                    entity_type: 'message',
                    entity_id: String(msgId),
                    meta: { type: 'text', phone, contentPreview: (message || '').slice(0, 120) }
                });
                db.run(
                    `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [
                        msgId,
                        phone,
                        'text',            // <-- szöveges üzenet
                        message || '',
                        new Date().toISOString(),
                        null,              // <-- nincs media_url
                        req.body?.theme || null
                    ],
                    (err) => { if (err) console.error('❌ DB insert hiba (send-message):', err); }
                );
            }

            results.push({ phone, status: 'success', response: sendRes.data });
        } catch (error) {
            console.error(`❌ Hiba ${phone} esetén:`, error.response?.data || error.message);
            results.push({ phone, status: 'error', error: error.response?.data || error.message });
        }
    }
    res.json({ message: 'Az üzenetküldés sikeresen lezárult', results });
});

async function sendTextMessage(phone, message, contentId = null, theme = null) {
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    try {
        const sendRes = await axios.post(
            `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
            {
                messaging_product: 'whatsapp',
                to: phone,
                type: 'text',
                text: { preview_url: false, body: message }
            },
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const waMessageId = sendRes.data.messages?.[0]?.id;
        if (waMessageId) {
            db.run(
                `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    waMessageId,
                    phone,
                    'text',
                    contentId || message,
                    new Date().toISOString(),
                    null,
                    theme
                ]
            );
        }

        console.log(`✅ Időzített üzenet elküldve: ${phone}`);
    } catch (error) {
        console.error(`❌ Hiba időzített üzenetnél (${phone}):`, error.response?.data || error.message);
    }
}
// ====== TEMPLATE KÜLDÉS FALLBACK KAL ======
async function sendTemplateWithFallback(phone, templateName, parameters = [], preferredLang = 'hu') {
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken   = process.env.ACCESS_TOKEN;
    const wabaId        = process.env.WHATSAPP_BUSINESS_ACCOUNT_ID;

    const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };
    const buildPayload = (lang) => ({
        messaging_product: 'whatsapp',
        to: phone,
        type: 'template',
        template: {
            name: templateName,
            language: { code: lang },
            components: [{ type: 'body', parameters: parameters.map(p => ({ type: 'text', text: p })) }]
        }
    });

    async function trySend(lang) {
        const resp = await axios.post(
            `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
            buildPayload(lang),
            { headers }
        );
        return { resp, usedLang: lang };
    }

    try {
        // 1) próba a preferált nyelvvel
        return await trySend(preferredLang);
    } catch (err) {
        const code = err?.response?.data?.error?.code;
        // csak akkor fallback-eljünk, ha a hiba a "nincs ilyen fordítás" (132001)
        if (code !== 132001) throw err;

        // 2) lekérjük, milyen nyelveken létezik a sablon
        const list = await axios.get(
            `https://graph.facebook.com/v19.0/${wabaId}/message_templates`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const variants = (list.data?.data || []).filter(t => t.name === templateName);
        const langs = variants.map(v => v.language).filter(Boolean);

        if (!langs.length) throw err; // nincs fordítás → marad az eredeti hiba

        const fallbackLang = langs.includes(preferredLang) ? preferredLang : langs[0];
        // 3) újrapróba elérhető nyelvvel
        return await trySend(fallbackLang);
    }
}

app.post('/send-template', requireRole('operator','admin','owner'), async (req, res) => {
    const phoneInput = req.body.phone;
    const templateName = req.body.templateName;
    const languageCode = req.body.languageCode || 'hu';
    const parameters = req.body.parameters || [];
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    if (!phoneInput || !templateName) {
        return res.status(400).json({ message: 'Hiányzó adat (telefonszám vagy sablon név)' });
    }

    const phones = Array.isArray(phoneInput) ? phoneInput : [phoneInput];
    const results = [];

    for (const phone of phones) {
        try {
            const prefLang = languageCode || 'hu';
            const { resp, usedLang } = await sendTemplateWithFallback(phone, templateName, parameters, prefLang);

            const msgId = resp.data?.messages?.[0]?.id;
            if (msgId) {
                await logAudit(req, {
                    action: 'SEND_MESSAGE',
                    entity_type: 'message',
                    entity_id: String(msgId),
                    meta: { type: 'template', phone, templateName, parameters }
                });
                db.run(
                    `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [
                        msgId,
                        phone,
                        'template',
                        templateName,
                        new Date().toISOString(),
                        null,
                        req.body.theme || null
                    ]
                );
            }

            console.log(`✅ Sablon elküldve: ${phone} (nyelv=${usedLang})`);
            results.push({ phone, status: 'success', response: resp.data });

        } catch (error) {
            console.error(`❌ Hiba ${phone} sablonküldésénél:`, error.response?.data || error.message);
            results.push({ phone, status: 'error', error: error.response?.data || error.message });
        }
    }


    res.json({ message: 'A sablonküldés sikeresen lezárult', results });
});

async function sendTemplateMessage(phone, templateName, parameters = [], theme = null, preferredLang = 'hu') {
    try {
        const { resp, usedLang } = await sendTemplateWithFallback(phone, templateName, parameters, preferredLang);
        const waMessageId = resp.data.messages?.[0]?.id;
        if (waMessageId) {
            db.run(
                `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [waMessageId, phone, 'template', templateName, new Date().toISOString(), null, theme]
            );
        }
        console.log(`✅ Időzített sablon elküldve: ${phone} (${templateName}, nyelv=${usedLang})`);
    } catch (error) {
        console.error(`❌ Hiba időzített sablonnál (${phone}):`, error.response?.data || error.message);
    }
}

const upload = multer({ dest: 'uploads/' });

app.post('/send-file-message',
    requireRole('operator','admin','owner'),
    upload.single('file'),           // ← előbb a multer, hogy legyen req.body
    enforce24hForFreeform(),
    async (req, res) => {
        const phoneInput = req.body.phone;
        const message = req.body.message || '';
        const file = req.file;
        const phoneNumberId = process.env.PHONE_NUMBER_ID;
        const accessToken = process.env.ACCESS_TOKEN;

        if (!phoneInput || !file) {
            return res.status(400).json({ message: '❌ Hiányzó telefonszám(ok) vagy fájl' });
        }

        const MAX_IMAGE_SIZE = 10 * 1024 * 1024;    // 10 MB
        const MAX_DOC_SIZE = 100 * 1024 * 1024;     // 100 MB

        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        const allowedDocTypes = [
            'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain', 'text/csv', 'application/zip', 'application/x-rar-compressed'
        ];

        const phones = Array.isArray(phoneInput) ? phoneInput : [phoneInput];
        const results = [];

        try {
            // Ellenőrzés 1: MIME típus
            const isImage = allowedImageTypes.includes(file.mimetype);
            const isDocument = allowedDocTypes.includes(file.mimetype);
            if (!isImage && !isDocument) {
                return res.status(400).json({ message: '❌ A fájl formátuma nem támogatott a WhatsApp API által.' });
            }

            // Ellenőrzés 2: méret
            if (isImage && file.size > MAX_IMAGE_SIZE) {
                return res.status(400).json({ message: '❌ A kép mérete meghaladja a 10 MB-os korlátot.' });
            }
            if (isDocument && file.size > MAX_DOC_SIZE) {
                return res.status(400).json({ message: '❌ A fájl mérete meghaladja a 100 MB-os korlátot.' });
            }

            // Média feltöltése WhatsApp-ra
            const form = new FormData();
            form.append('messaging_product', 'whatsapp');
            form.append('file', fs.createReadStream(file.path), {
                filename: file.originalname,
                contentType: file.mimetype
            });

            const uploadRes = await axios.post(
                `https://graph.facebook.com/v19.0/${phoneNumberId}/media`,
                form,
                { headers: { Authorization: `Bearer ${accessToken}`, ...form.getHeaders() } }
            );

            const mediaId = uploadRes.data.id;
            const mediaType = isImage ? 'image' : 'document';

            // Mozgatás a public/sent_media mappába
            const localFilename = `${Date.now()}_${file.originalname}`;
            const localPath = path.join(__dirname, 'public/sent_media', localFilename);
            const mediaUrl = `/sent-media/${localFilename}`;
            fs.mkdirSync(path.dirname(localPath), { recursive: true });
            fs.renameSync(file.path, localPath);

            for (const phone of phones) {
                try {
                    const mediaPayload =
                        mediaType === 'image'
                            ? { id: mediaId, caption: message }
                            : { id: mediaId, caption: message, filename: file.originalname };

                    const sendRes = await axios.post(
                        `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
                        {
                            messaging_product: 'whatsapp',
                            to: phone,
                            type: mediaType,
                            [mediaType]: mediaPayload
                        },
                        { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
                    );

                    // HELYES:
                    if (sendRes.data.messages && sendRes.data.messages[0]?.id) {
                        db.run(
                            `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                             VALUES (?, ?, ?, ?, ?, ?, ?)`,
                            [
                                sendRes.data.messages[0].id,
                                phone,
                                mediaType,              // 'image' vagy 'document'
                                message || '',
                                new Date().toISOString(),
                                mediaUrl,               // pl. /sent-media/1700000000_fajlnev.jpg
                                null
                            ],
                            (err) => { if (err) console.error('❌ DB insert hiba (send-file-message):', err); }
                        );
                        logAudit(req, {
                            action: 'SEND_MESSAGE',
                            entity_type: 'message',
                            entity_id: String(sendRes.data.messages[0].id),
                            meta: { type: mediaType, phone, filename: file.originalname, mediaUrl }
                        });
                    }

                    results.push({ phone, status: 'success', response: sendRes.data }); // <-- csak ez maradjon, ne legyen még egy success push
                } catch (err) {
                    console.error(`❌ Hiba fájlküldéskor ${phone}:`, err.response?.data || err.message);
                    results.push({ phone, status: 'error', error: err.response?.data || err.message });
                }
            }

            res.json({ message: '📤 A fájlküldés sikeresen lezárult', results });
        } catch (error) {
            console.error('❌ Média feltöltési hiba:', error.response?.data || error.message);
            res.status(500).json({ message: '🚫 Hiba a fájl feltöltésénél vagy küldésnél' });
        }
    });

async function sendScheduledMediaMessage(phone, content) {
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    const mediaPath = path.join(__dirname, 'public/sent_media', content.filename);
    if (!fs.existsSync(mediaPath)) {
        console.warn(`❌ Nincs ilyen fájl: ${mediaPath}`);
        return;
    }

    try {
        const form = new FormData();
        form.append('messaging_product', 'whatsapp');
        form.append('file', fs.createReadStream(mediaPath), {
            filename: content.filename,
            contentType: content.media_type === 'image' ? 'image/jpeg' : 'application/pdf' // vagy amit szeretnél
        });

        const uploadRes = await axios.post(
            `https://graph.facebook.com/v19.0/${phoneNumberId}/media`,
            form,
            { headers: { Authorization: `Bearer ${accessToken}`, ...form.getHeaders() } }
        );

        const mediaId = uploadRes.data.id;
        const mediaPayload =
            content.media_type === 'image'
                ? { id: mediaId, caption: content.message }
                : { id: mediaId, caption: content.message, filename: content.filename };

        const sendRes = await axios.post(
            `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
            {
                messaging_product: 'whatsapp',
                to: phone,
                type: content.media_type,
                [content.media_type]: mediaPayload
            },
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const waMessageId = sendRes.data.messages?.[0]?.id;
        if (waMessageId) {
            db.run(
                `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    waMessageId,
                    phone,
                    content.media_type,
                    content.message,
                    new Date().toISOString(),
                    `/sent-media/${content.filename}`,
                    null
                ]
            );
        }

        console.log(`✅ Időzített fájl elküldve: ${phone}`);
    } catch (error) {
        console.error(`❌ Hiba időzített fájlküldésnél (${phone}):`, error.response?.data || error.message);
    }
}

async function sendScheduledMedia(phone, mediaInfo) {
    const phoneNumberId = process.env.PHONE_NUMBER_ID;
    const accessToken = process.env.ACCESS_TOKEN;
    const { message, filePath, fileName, mimeType } = mediaInfo;

    const form = new FormData();
    form.append('messaging_product', 'whatsapp');
    form.append('file', fs.createReadStream(filePath), {
        filename: fileName,
        contentType: mimeType
    });

    const uploadRes = await axios.post(
        `https://graph.facebook.com/v19.0/${phoneNumberId}/media`,
        form,
        { headers: { Authorization: `Bearer ${accessToken}`, ...form.getHeaders() } }
    );

    const mediaId = uploadRes.data.id;
    const isImage = mimeType.startsWith('image/');
    const mediaType = isImage ? 'image' : 'document';
    const mediaPayload = isImage
        ? { id: mediaId, caption: message }
        : { id: mediaId, caption: message, filename: fileName };

    const sendRes = await axios.post(
        `https://graph.facebook.com/v19.0/${phoneNumberId}/messages`,
        {
            messaging_product: 'whatsapp',
            to: phone,
            type: mediaType,
            [mediaType]: mediaPayload
        },
        {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        }
    );

    const waMessageId = sendRes.data.messages?.[0]?.id;
    if (waMessageId) {
        db.run(
            `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                waMessageId,
                phone,
                mediaType,
                message,
                new Date().toISOString(),
                `/sent-media/${fileName}`
            ]
        );
    }


    console.log(`✅ Időzített ${mediaType} elküldve: ${phone}`);
}

app.post('/save-to-questionnaire', requireRole('admin','owner'), async (req, res) => {
    const { theme, templates, chain } = req.body;

    const wabaId = process.env.WHATSAPP_BUSINESS_ACCOUNT_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    if (!theme || !templates || !chain) {
        return res.status(400).json({ error: '❌ Hiányzó mezők a kérésben' });
    }

    const created = [];
    const failed = [];

    // 1️⃣ Sablonok létrehozása a Meta API-n
    for (const tpl of templates) {
        try {
            // 🔍 Ellenőrizd, létezik-e már ez a sablon
            const check = await axios.get(
                `https://graph.facebook.com/v19.0/${wabaId}/message_templates`,
                {
                    headers: { Authorization: `Bearer ${accessToken}` }
                }
            );

            const exists = (check.data.data || []).some(t => t.name === tpl.name);

            if (exists) {
                console.log(`⚠️ A(z) ${tpl.name} sablon már létezik, kihagyva`);
                continue; // Ne próbáljuk újra létrehozni
            }

            // 💡 Gombok kiszűrése – csak akkor adjuk hozzá, ha tényleg vannak
            const cleanButtons = (tpl.buttons || []).filter(b => b.trim() !== '');

            // 🧱 Alap komponens: BODY
            const components = [
                { type: 'BODY', text: tpl.text }
            ];

            // ➕ Ha van legalább 1 gomb, akkor BUTTONS is jön
            if (cleanButtons.length > 0) {
                components.push({
                    type: 'BUTTONS',
                    buttons: cleanButtons
                        .slice(0, 10)                         // ⬅️ 10 gomb engedélyezve
                        .map(btn => ({
                            type: 'QUICK_REPLY',
                            text: String(btn).trim().slice(0, 20) // ⬅️ óvatos 20 karakter limit
                        }))
                });
            }

            // ✅ Sablon létrehozása
            await axios.post(
                `https://graph.facebook.com/v19.0/${wabaId}/message_templates`,
                {
                    name: tpl.name,
                    language: 'hu',
                    category: 'UTILITY',
                    components
                },
                {
                    headers: {
                        Authorization: `Bearer ${accessToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            created.push(tpl.name);
        } catch (error) {
            console.error(`❌ Hiba a(z) ${tpl.name} sablonnál:`, error.response?.data || error.message);
            failed.push({ name: tpl.name, error: error.response?.data || error.message });
        }
    }

    // 2️⃣ questionnaire.js fájl frissítése
    const filePath = path.join(__dirname, 'questionnaire.js');

    // 2/a. betöltjük a meglévő tartalmat
    let currentObject = {};
    try {
        delete require.cache[require.resolve('./questionnaire')];
        currentObject = require('./questionnaire');
    } catch (e) {
        currentObject = {};
    }

    const flatChain = {};
    for (const [theme, { flow }] of Object.entries(chain)) {
        flatChain[theme] = flow; // csak a flow-t mentjük, nem a start-ot
    }

    const newObject = { ...currentObject, ...flatChain };

    // 2/b. átalakítjuk JS objektummá (nem JSON!)
    function stringifyObject(obj, indent = 2) {
        const spacing = ' '.repeat(indent);
        const entries = Object.entries(obj).map(([key, val]) => {
            const formattedKey = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key) ? key : JSON.stringify(key);

            if (val && typeof val === 'object' && !Array.isArray(val)) {
                return `${spacing}${formattedKey}: ${stringifyObject(val, indent + 2)}`;
            } else if (val === null) {
                return `${spacing}${formattedKey}: null`;
            } else {
                return `${spacing}${formattedKey}: ${JSON.stringify(val)}`;
            }
        });
        return `{\n${entries.join(',\n')}\n${' '.repeat(indent - 2)}}`;
    }

    const finalJs = `const questionnaires = ${stringifyObject(newObject)};\n\nmodule.exports = questionnaires;\n`;

    // 2/c. mentés fájlba
    fs.writeFile(filePath, finalJs, err => {
        if (err) {
            console.error('❌ Mentési hiba questionnaire.js-hez:', err);
            return res.status(500).json({ error: '🚫 Mentés sikertelen', details: err });
        }

        res.json({
            success: true,
            message: `✅ '${theme}' kérdőív mentve és sablonok létrehozva.`,
            created,
            failed
        });
    });
});
function sanitizeTemplateNameServer(name){
    let s = (name || '').trim().toLowerCase();
    s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    s = s.replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
    if (!/^[a-z]/.test(s)) s = 't_' + s;
    return s || 't_default';
}
app.post('/create-template', requireRole('admin','owner'), async (req, res) => {
    // Támogatjuk mindkét bejövő formátumot
    const {
        templateName,               // régi frontend
        languageCode = 'hu',
        bodyText,
        buttons = [],

        name,                       // új frontend
        language,
        category = 'UTILITY',
        components
    } = req.body;

    const wabaId = process.env.WHATSAPP_BUSINESS_ACCOUNT_ID;
    const accessToken = process.env.ACCESS_TOKEN;

    // Normalizálás
    const finalName = templateName || name;
    const finalLang = languageCode || language || 'hu';
    let body = bodyText || '';
    let btns = buttons;

    if (!body && Array.isArray(components)) {
        const bodyComp = components.find(c => c.type === 'BODY');
        body = bodyComp?.text || '';
        const btnComp = components.find(c => c.type === 'BUTTONS');
        if ((!btns || !btns.length) && btnComp?.buttons) {
            btns = btnComp.buttons.map(b => (typeof b === 'string' ? b : (b.text || b.title))).filter(Boolean);
        }
    }

    if (!finalName || !body) {
        return res.status(400).json({ error: 'Hiányzó mezők: templateName/name és bodyText vagy components.BODY.text' });
    }

    const apiComponents = [{ type: 'BODY', text: body }];
    if (btns && btns.length) {
        apiComponents.push({
            type: 'BUTTONS',
            buttons: btns
                .slice(0, 10)                                     // ⬅️ 10-ig
                .map(b => ({
                    type: 'QUICK_REPLY',
                    text: String(typeof b === 'string' ? b : (b.text || '')).trim().slice(0, 20) // ⬅️ 20 char
                }))
        });
    }

    try {
        const response = await axios.post(
            `https://graph.facebook.com/v19.0/${wabaId}/message_templates`,
            { name: finalName, language: finalLang, category, components: apiComponents },
            { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true, result: response.data });
    } catch (error) {
        console.error('❌ Hiba sablon létrehozásakor:', error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data || 'Ismeretlen hiba' });
    }
});


app.post('/save-to-questionnaire', requireRole('admin','owner'), (req, res) => {
    const { theme, templates, chain } = req.body;
    if (!theme || !templates || !chain) {
        return res.status(400).json({ error: '❌ Hiányzó mezők a kérésben' });
    }

    const filePath = path.join(__dirname, 'questionnaire.js');
    let currentContent = '';

    try {
        delete require.cache[require.resolve('./questionnaire')];
        currentContent = fs.readFileSync(filePath, 'utf-8');
    } catch (e) {
        currentContent = 'const questionnaires = {};\n\nmodule.exports = questionnaires;';
    }

    // 1️⃣ Megpróbáljuk értelmezni a meglévő objektumot
    let newObject;
    try {
        const mod = require('./questionnaire');
        newObject = { ...mod, ...chain };
    } catch (e) {
        return res.status(500).json({ error: '❌ Nem sikerült betölteni a questionnaire.js-t', details: e.message });
    }

    // 2️⃣ Készítünk egy JS objektum stringet (nem JSON-t!)
    function stringifyObject(obj, indent = 2) {
        const spacing = ' '.repeat(indent);
        const entries = Object.entries(obj).map(([key, val]) => {
            const formattedKey = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key) ? key : JSON.stringify(key);

            if (val && typeof val === 'object' && !Array.isArray(val)) {
                return `${spacing}${formattedKey}: ${stringifyObject(val, indent + 2)}`;
            } else if (val === null) {
                return `${spacing}${formattedKey}: null`;
            } else {
                return `${spacing}${formattedKey}: ${JSON.stringify(val)}`;
            }
        });
        return `{\n${entries.join(',\n')}\n${' '.repeat(indent - 2)}}`;
    }

    const finalJs = `const questionnaires = ${stringifyObject(newObject)};\n\nmodule.exports = questionnaires;\n`;

    // 3️⃣ Mentés
    fs.writeFile(filePath, finalJs, err => {
        if (err) {
            console.error('❌ Mentési hiba questionnaire.js-hez:', err);
            return res.status(500).json({ error: '🚫 Mentés sikertelen', details: err });
        }

        res.json({ success: true, message: `✅ '${theme}' kérdőív mentve a questionnaire.js fájlba.` });
    });
});

function startQuestionnaire(phone, theme) {
    const questionnaires = loadTemplateQuestionnaires();

    if (!questionnaires[theme]) {
        console.warn(`❌ Ismeretlen kérdőív: ${theme}`);
        return;
    }

    const flow = questionnaires[theme];
    const allKeys = Object.keys(flow);
    const allTargets = new Set();

    for (const qId in flow) {
        const nextMap = flow[qId]?.next || {};
        Object.values(nextMap).forEach(target => {
            if (target) allTargets.add(target);
        });
    }

    const first = allKeys.find(id => !allTargets.has(id));
    if (!first || !flow[first]) {
        console.warn(`❌ Nem található első kérdés a kérdőívhez: ${theme}`);
        return;
    }

    const question = flow[first];

    axios.post(
        `https://graph.facebook.com/v19.0/${process.env.PHONE_NUMBER_ID}/messages`,
        {
            messaging_product: 'whatsapp',
            to: phone,
            type: 'template',
            template: {
                name: first,
                language: { code: 'hu' },
                components: []
            }
        },
        {
            headers: {
                Authorization: `Bearer ${process.env.ACCESS_TOKEN}`,
                'Content-Type': 'application/json'
            }
        }
    ).then(response => {
        const waMsgId = response.data.messages?.[0]?.id;
        if (waMsgId) {
            db.run(
                `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, theme)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [waMsgId, phone, 'template', first, new Date().toISOString(), theme]
            );
        }

        console.log(`✅ Kérdőív (${theme}) időzítve és elindítva: ${phone}`);
    }).catch(err => {
        console.error(`❌ Hiba kérdőív indításnál (${phone}):`, err.response?.data || err.message);
    });
}


// Webhook POST - üzenet és kontakt mentése
fs.mkdirSync(path.join(__dirname, 'public/uploads'), { recursive: true });   // Biztos, hogy létezik a mappa

app.post('/schedule', requireRole('operator','admin','owner'), (req, res) => {
    const { phone, type, content, scheduled_time } = req.body;

    if (!phone || !type || !content || !scheduled_time) {
        return res.status(400).json({ error: 'Hiányzó adat' });
    }

    const requestedMs = Date.parse(scheduled_time); // ISO -> ms (UTC)
    const minMs = Date.now() + 60 * 1000;
    if (!requestedMs || requestedMs < minMs) {
        return res.status(400).json({
            status: 'error',
            error: '⛔ Az időzített küldés csak a következő 1 percen túli időpontra engedélyezett.'
        });
    }

    db.run(
        "INSERT INTO scheduled_messages (phone, type, content, scheduled_time) VALUES (?, ?, ?, ?)",
        [phone, type, (typeof content === 'string' ? content : JSON.stringify(content)), scheduled_time],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            logAudit(req, {
                action: 'CREATE_SCHEDULE',
                entity_type: 'scheduled_message',
                entity_id: String(this.lastID),
                meta: { type, phone, scheduled_time }
            });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.post('/schedule-media',
    requireRole('operator','admin','owner'),
    upload.single('file'),           // ← előbb a multer
    enforce24hForFreeform(),         // (opcionális – időzítésnél akár el is hagyható)
    (req, res) => {
        const { phone, scheduled_time, message = '' } = req.body;
        const file = req.file;

        if (!phone || !scheduled_time || !file) {
            return res.status(400).json({ error: 'Hiányzó telefon, időpont vagy fájl.' });
        }

        const requestedMs = Date.parse(scheduled_time);
        const minMs = Date.now() + 60 * 1000;
        if (!requestedMs || requestedMs < minMs) {
            return res.status(400).json({
                status: 'error',
                error: '⛔ Az időzített küldés csak a következő 1 percen túli időpontra engedélyezett.'
            });
        }

        // fájl áthelyezés a public/sent_media mappába
        const destDir = path.join(__dirname, 'public/sent_media');
        fs.mkdirSync(destDir, { recursive: true });
        const fileName = `${Date.now()}_${file.originalname}`;
        const absPath = path.join(destDir, fileName);
        fs.renameSync(file.path, absPath);

        const mediaInfo = {
            message,
            filePath: absPath,   // ABSZOLÚT útvonal a feltöltéshez
            fileName,
            mimeType: file.mimetype
        };

        db.run(
            "INSERT INTO scheduled_messages (phone, type, content, scheduled_time) VALUES (?, ?, ?, ?)",
            [phone, 'media', JSON.stringify(mediaInfo), new Date(scheduled_time).toISOString()],
            function (err) {
                if (err) return res.status(500).json({ error: err.message });
                logAudit(req, {
                    action: 'CREATE_SCHEDULE',
                    entity_type: 'scheduled_message',
                    entity_id: String(this.lastID),
                    meta: { type: 'media', phone, scheduled_time, filename: fileName }
                });
                res.json({ success: true, id: this.lastID });
            }
        );
    });


app.post('/webhook', async (req, res) => {
    console.log("📨 Webhook kérés érkezett:", JSON.stringify(req.body, null, 2));

    let responded = false;
    function safeRespond(code = 200) {
        if (!responded) {
            responded = true;
            res.sendStatus(code);
        }
    }

    function loadQuestionnairesFromFolder() {
        const dir = path.join(__dirname, 'kerdoivek');
        const all = {};
        if (fs.existsSync(dir)) {
            fs.readdirSync(dir).forEach(filename => {
                if (filename.endsWith('.json')) {
                    const raw = fs.readFileSync(path.join(dir, filename), 'utf-8');
                    const data = JSON.parse(raw);
                    Object.assign(all, data);
                }
            });
        }
        return all;
    }

    const entry = req.body.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value;

    const contactsData = value?.contacts?.[0];
    const wa_id = contactsData?.wa_id || null;
    const name = contactsData?.profile?.name || null;

    if (wa_id) {
        if (name) {
            db.run(
                `INSERT INTO contacts (wa_id, name)
                 VALUES (?, ?)
                     ON CONFLICT(wa_id) DO UPDATE SET name = excluded.name`,
                [wa_id, name],
                (err) => {
                    if (err) console.error("❌ DB hiba (contacts - névvel):", err);
                }
            );
        } else {
            db.run(
                `INSERT INTO contacts (wa_id)
                 VALUES (?)
                     ON CONFLICT(wa_id) DO NOTHING`,
                [wa_id],
                (err) => {
                    if (err) console.error("❌ DB hiba (contacts - név nélkül):", err);
                }
            );
            console.warn(`⚠️ Név nem érkezett a webhook üzenetben (wa_id: ${wa_id})`);
        }
    }

    const messages = value?.messages;

    if (messages) {
        const message = messages[0];
        const messageType = message.type;
        const wa_message_id = message.id;
        const timestamp = new Date().toISOString();

        let messageBody = '';

        // 💡 GOMBOS VÁLASZ KEZELÉS
        if (messageType === 'button') {
            const from = message.from;
            const originalMsgId = message.context?.id; // erre válaszolt a user
            const buttonText =
                message.button?.text ||
                message.button?.payload ||
                message.interactive?.button_reply?.title ||
                message.interactive?.button_reply?.id ||
                '(gomb válasz)';

            if (!originalMsgId) {
                console.warn("⚠️ Nincs originalMsgId a gombos válasznál.");
                return safeRespond(200);
            }

            // 🔒 egyszerre csak egy futás
            if (!acquireLock(originalMsgId)) {
                console.warn("⏳ Már folyamatban van ez a válasz:", originalMsgId);
                return safeRespond(200);
            }

            // 0) ha már volt válasz erre az üzenetre, lépjünk ki
            db.get(`SELECT 1 FROM messages WHERE in_reply_to = ? LIMIT 1`, [originalMsgId], (err, exists) => {
                if (err) { console.error('❌ DB hiba ellenőrzésnél:', err); return safeRespond(200); }
                if (exists) { console.warn('⚠️ Már érkezett válasz erre az üzenetre:', originalMsgId); return safeRespond(200); }

                // 1) most rögzítjük a gombnyomást (unique index is védi)
                db.get('SELECT id FROM contacts WHERE wa_id = ?', [wa_id], (errC, rowC) => {
                    if (errC || !rowC) { console.error('❌ Nem található kontakt:', errC); return safeRespond(200); }

                    const contact_id = rowC.id;
                    db.run(
                        `INSERT INTO messages (contact_id, message_body, message_type, received_at, wa_message_id, in_reply_to)
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        [contact_id, buttonText, 'button', new Date().toISOString(), wa_message_id, originalMsgId],
                        function (insErr) {
                            if (insErr) {
                                console.warn('⚠️ Dupla gombnyomás, insert elutasítva:', insErr.message);
                                return safeRespond(200);
                            }

                            // 2) előző sablon → következő lépés kiderítése
                            db.get('SELECT * FROM sent_messages WHERE wa_message_id = ?', [originalMsgId], async (errS, rowS) => {
                                if (errS || !rowS) { console.error('❌ Nem található az előző sablon:', errS); return safeRespond(200); }

                                const currentTemplate = rowS.content;

                                // questionnaires szerkezete lehet {theme:{...}} vagy {theme:{flow:{...}}}
                                let detectedTheme = null;
                                const questionnaires = loadTemplateQuestionnaires();
                                for (const [theme, config] of Object.entries(questionnaires)) {
                                    const flow = config.flow || config;
                                    if (currentTemplate in flow) { detectedTheme = theme; break; }
                                }
                                if (!detectedTheme) { console.warn('⚠️ Nincs sablonlánc ehhez:', currentTemplate); return safeRespond(200); }

                                const fullFlow = questionnaires[detectedTheme].flow || questionnaires[detectedTheme];
                                const currentStep = fullFlow[currentTemplate];
                                if (!currentStep || !currentStep.next) { console.log('🔚 Nincs következő lépés.'); return safeRespond(200); }

                                const nextTemplate = currentStep.next[buttonText] || null;
                                if (!nextTemplate) { console.log(`🛑 A válasz (“${buttonText}”) nem indít új sablont.`); return safeRespond(200); }

                                // 3) küldjük a következő sablont — ez csak egyszer fog megtörténni
                                try {
                                    const sendRes = await axios.post(
                                        `https://graph.facebook.com/v19.0/${process.env.PHONE_NUMBER_ID}/messages`,
                                        {
                                            messaging_product: 'whatsapp',
                                            to: from,
                                            type: 'template',
                                            template: { name: nextTemplate, language: { code: 'hu' }, components: [] }
                                        },
                                        { headers: { Authorization: `Bearer ${process.env.ACCESS_TOKEN}`, 'Content-Type': 'application/json' } }
                                    );

                                    const newMsgId = sendRes.data.messages?.[0]?.id || null;
                                    db.run(
                                        `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url, theme)
                                         VALUES (?, ?, ?, ?, ?, ?, ?)`,
                                        [newMsgId, from, 'template', nextTemplate, new Date().toISOString(), null, rowS.theme]
                                    );
                                } catch (e) {
                                    console.error('❌ Hiba automatikus sablonküldéskor:', e.response?.data || e.message);
                                }

                                return safeRespond(200);
                            });
                        }
                    );
                });
            });

            return; // ne fusson tovább a webhook
        }

        // 🖼️ vagy 📄 média
        if (messageType === 'image' || messageType === 'document') {
            const mediaId = message[messageType]?.id;
            const caption = message[messageType]?.caption || '';
            const from = message.from;

            // lekérés a WhatsApp API-n keresztül
            try {
                const mediaRes = await axios.get(
                    `https://graph.facebook.com/v19.0/${mediaId}`,
                    {
                        headers: { Authorization: `Bearer ${process.env.ACCESS_TOKEN}` }
                    }
                );

                const mediaUrl = mediaRes.data.url;

                const mediaData = await axios.get(mediaUrl, {
                    headers: { Authorization: `Bearer ${process.env.ACCESS_TOKEN}` },
                    responseType: 'arraybuffer'
                });

                const ext = messageType === 'image' ? '.jpg' : '.pdf'; // vagy más MIME-típus alapján
                const filename = `${Date.now()}_${mediaId}${ext}`;
                const savePath = path.join(__dirname, 'public/uploads', filename);
                fs.writeFileSync(savePath, mediaData.data);

                // adatbázisba mentés
                db.get('SELECT id FROM contacts WHERE wa_id = ?', [wa_id], (err, row) => {
                    if (err || !row) return;

                    const contact_id = row.id;
                    const storedPath = `/uploads/${filename}`;

                    db.run(
                        `INSERT INTO messages (contact_id, message_body, message_type, received_at, wa_message_id)
                         VALUES (?, ?, ?, ?, ?)`,
                        [contact_id, storedPath, messageType, new Date().toISOString(), wa_message_id]
                    );
                });

                console.log(`✅ Média mentve: ${filename}`);
            } catch (e) {
                console.error('❌ Média letöltés hiba:', e.response?.data || e.message);
            }

            return safeRespond(200);
        }

        // 📝 szöveges üzenet
        if (messageType === 'text') {
            const userText = message.text?.body?.trim();
            const from = message.from;
            const wa_message_id = message.id;
            const timestamp = new Date().toISOString();

            // 1️⃣ Elmentjük az üzenetet a DB-be
            db.get('SELECT id FROM contacts WHERE wa_id = ?', [wa_id], (err, row) => {
                if (err || !row) return;
                const contact_id = row.id;

                db.run(
                    `INSERT INTO messages (contact_id, message_body, message_type, received_at, wa_message_id)
                     VALUES (?, ?, ?, ?, ?)`,
                    [contact_id, userText, 'text', timestamp, wa_message_id]
                );
            });

            // 2️⃣ Lekérjük a legutóbbi kiküldött kérdést
            const questionnaires = loadTemplateQuestionnaires();

            db.get(
                `SELECT content, theme FROM sent_messages WHERE phone = ? ORDER BY timestamp DESC LIMIT 1`,
                [from],
                (err, row) => {
                    if (err || !row) return;

                    const lastNode = row.content;
                    const theme = row.theme;
                    const cfg = questionnaires[theme];
                    const flow = cfg?.flow || cfg;

                    if (!flow || !flow[lastNode]) return safeRespond(200);

                    const current = flow[lastNode];
                    const nextKey = current.next?.[userText];
                    const nextNode = flow[nextKey];

                    if (!nextNode) return safeRespond(200);

                    // 3️⃣ Küldjük a következő kérdést
                    axios
                        .post(
                            `https://graph.facebook.com/v19.0/${process.env.PHONE_NUMBER_ID}/messages`,
                            {
                                messaging_product: 'whatsapp',
                                to: from,
                                type: 'text',
                                text: {
                                    preview_url: false,
                                    body: nextNode.text
                                }
                            },
                            {
                                headers: {
                                    Authorization: `Bearer ${process.env.ACCESS_TOKEN}`,
                                    'Content-Type': 'application/json'
                                }
                            }
                        )
                        .then(res2 => {
                            const waMsgId = res2.data.messages?.[0]?.id;
                            if (waMsgId) {
                                db.run(
                                    `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, theme)
                                     VALUES (?, ?, ?, ?, ?, ?)`,
                                    [waMsgId, from, 'text', nextKey, new Date().toISOString(), theme]
                                );
                            }
                        })
                        .catch(e =>
                            console.error(
                                '❌ Hiba automatikus kérdésküldéskor:',
                                e.response?.data || e.message
                            )
                        );
                }
            );

            return safeRespond(200);
        }
        // Mentés (text / image / doc)
        db.get('SELECT id FROM contacts WHERE wa_id = ?', [wa_id], (err, row) => {
            if (err || !row) {
                console.error('❌ Nem található kontakt (text/image):', err);
                return;
            }

            const contact_id = row.id;

            db.run(
                `INSERT INTO messages (contact_id, message_body, message_type, received_at, wa_message_id)
                 VALUES (?, ?, ?, ?, ?)`,
                [contact_id, messageBody, messageType, timestamp, wa_message_id],
                function (err) {
                    if (err) {
                        console.error('❌ DB hiba (általános mentés):', err);
                    } else {
                        console.log('✅ Üzenet mentve, ID:', this.lastID);
                    }
                }
            );
        });
    }

    function continueWithTemplateLogic() {
        const questionnaires = loadTemplateQuestionnaires();
        db.get('SELECT * FROM sent_messages WHERE wa_message_id = ?', [originalMsgId], async (err, row) => {
            if (err || !row) {
                console.error('❌ Nem található az előző sablon:', err);
                return safeRespond(200);
            }

            const currentTemplate = row.content;
            let detectedTheme = null;

            for (const [theme, config] of Object.entries(questionnaires)) {
                const flow = config.flow || config;
                if (currentTemplate in flow) {
                    detectedTheme = theme;
                    break;
                }
            }

            if (!detectedTheme) {
                console.warn(`⚠️ Nincs sablonlánc ehhez: ${currentTemplate}`);
                return safeRespond(200);
            }

            const fullFlow = questionnaires[detectedTheme].flow || questionnaires[detectedTheme];
            const currentStep = fullFlow[currentTemplate];

            if (!currentStep || !currentStep.next) {
                console.log('🔚 Nincs elérhető következő lépés.');
                return safeRespond(200);
            }

            const nextTemplate = currentStep.next[buttonText] || null;

            if (!nextTemplate) {
                console.log(`🛑 A válasz (“${buttonText}”) nem indít új sablont.`);
                return safeRespond(200);
            }

            console.log(`➡️ Válasz alapján küldöm: ${nextTemplate}`);

            try {
                const sendRes = await axios.post(
                    `https://graph.facebook.com/v19.0/${process.env.PHONE_NUMBER_ID}/messages`,
                    {
                        messaging_product: 'whatsapp',
                        to: from,
                        type: 'template',
                        template: {
                            name: nextTemplate,
                            language: { code: 'hu' },
                            components: []
                        }
                    },
                    {
                        headers: {
                            Authorization: `Bearer ${process.env.ACCESS_TOKEN}`,
                            'Content-Type': 'application/json'
                        }
                    }
                );

                const newMsgId = sendRes.data.messages?.[0]?.id || null;

                db.run(
                    `INSERT INTO sent_messages (wa_message_id, phone, type, content, timestamp, media_url)
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [newMsgId, from, 'template', nextTemplate, new Date().toISOString(), null]
                );

            } catch (e) {
                console.error('❌ Hiba automatikus sablonküldéskor:', e.response?.data || e.message);
            }

            return safeRespond(200);
        });
    }
})

function safeParse(v) {
    try {
        const once = (typeof v === 'string') ? JSON.parse(v) : v;
        return (typeof once === 'string') ? JSON.parse(once) : once;
    } catch {
        return v;
    }
}

cron.schedule('* * * * *', () => {
    const now = new Date().toISOString();
    function safeParse(v) {
        try {
            const once = (typeof v === 'string') ? JSON.parse(v) : v;
            return (typeof once === 'string') ? JSON.parse(once) : once;
        } catch {
            return v;
        }
    }

    db.run(
        "DELETE FROM signup_verifications WHERE expires_at < CURRENT_TIMESTAMP OR attempts_left <= 0",
        err => { if (err) console.error('OTP cleanup hiba:', err); }
    );

    db.all("SELECT * FROM scheduled_messages WHERE sent = 0 AND scheduled_time <= ?", [now], (err, rows) => {
        if (err) return console.error('⛔ Cron error:', err);

        rows.forEach(async (msg) => {
            let delivered = false;   // <- csak akkor lesz true, ha tényleg küldtünk valamit
            try {
                console.log(`⏰ DUE job #${msg.id}: type=${msg.type}, phone=${msg.phone}`);

                if (msg.type === 'message') {
                    await sendTextMessage(msg.phone, msg.content);
                    delivered = true;
                    console.log(`📩 Időzített szöveg elküldve: ${msg.phone}`);

                } else if (msg.type === 'template') {
                    const parsed = safeParse(msg.content);
                    const { templateName, parameters = [], languageCode = 'hu', theme = null } = parsed || {};

                    if (!templateName) {
                        console.error(`❌ Hiányzó templateName (job #${msg.id})`);
                    } else {
                        await sendTemplateMessage(msg.phone, templateName, parameters, theme, languageCode || 'hu');
                        delivered = true;
                        console.log(`📨 Időzített sablon elküldve: ${msg.phone} (${templateName})`);
                    }

                } else if (msg.type === 'questionnaire') {
                    const parsed = safeParse(msg.content);
                    console.log(`🧩 Questionnaire payload:`, parsed);

                    // Szöveges kérdőív indítás
                    if (parsed?.message && parsed?.content && parsed?.theme) {
                        await sendTextMessage(msg.phone, parsed.message, parsed.content, parsed.theme);
                        delivered = true;
                        console.log(`📝 Időzített szöveges kérdőív elküldve: ${msg.phone}`);

                        // Sablonos kérdőív indítás
                    }  else if (parsed?.templateName && parsed?.theme) {
                        const { templateName, parameters = [], theme, languageCode = 'hu' } = parsed;
                        await sendTemplateMessage(msg.phone, templateName, parameters, theme, languageCode || 'hu');

                        delivered = true;
                        console.log(`📋 Időzített sablonos kérdőív elküldve: ${msg.phone} (${templateName}, theme=${theme})`);

                    } else {
                        console.warn(`❓ Ismeretlen questionnaire formátum (job #${msg.id}):`, parsed);
                    }

                } else if (msg.type === 'media') {
                    const mediaInfo = safeParse(msg.content);
                    await sendScheduledMedia(msg.phone, mediaInfo);
                    delivered = true;
                    console.log(`🖼️ Időzített média elküldve: ${msg.phone}`);

                } else {
                    console.warn(`⚠️ Ismeretlen üzenettípus: ${msg.type} (job #${msg.id})`);
                }

            } catch (e) {
                console.error(`❌ Hiba időzített küldés során (job #${msg.id}):`, e.message || e);
            } finally {
                if (delivered) {
                    db.run("UPDATE scheduled_messages SET sent = 1 WHERE id = ?", [msg.id]);
                    logAuditSystem('CRON_DELIVER', {
                        entity_type: 'scheduled_message',
                        entity_id: String(msg.id),
                        meta: { phone: msg.phone, type: msg.type }
                    });
                } else {
                    console.warn(`⏳ Job #${msg.id} NEM lett elküldve; sent=0 marad (következő cron futásnál újrapróbáljuk).`);
                }
            }
        });
    });
});

// JSON válasz: Összes kontakt
app.get('/contacts', (req, res) => {
    const query = `
        SELECT id AS ID, wa_id AS Phone_number, name AS Name
        FROM contacts
        ORDER BY id ASC
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('❌ Hiba a kontaktok lekérdezésekor:', err);
            return safeRespond(500);
        }
        res.json(rows);
    });
});

// JSON válasz: Összes üzenet
app.get('/messages', (req, res) => {
    const query = `
        SELECT messages.id AS ID,
               contacts.wa_id AS Phone_number,
               contacts.name AS Name,
               messages.message_body AS Body,
               messages.message_type AS Type,
               messages.received_at AS Received_at
        FROM messages
                 JOIN contacts ON messages.contact_id = contacts.id
        ORDER BY messages.received_at DESC
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Adatbázis hiba' });
        for (const r of rows) r.Received_at = toAppTz(r.Received_at);
        res.json(rows);
    });
});

// JSON válasz: Üzenet státusz metaadatok
app.get('/message-metadata', (req, res) => {
    const query = `
        SELECT id AS ID, message_id AS Message_ID, status AS Status,
            timestamp AS Timestamp, error_code AS Error_Code, error_message AS Error_Message
        FROM message_metadata
        ORDER BY id ASC
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Adatbázis hiba' });
        for (const r of rows) r.Timestamp = toAppTz(r.Timestamp);
        res.json(rows);
    });
});

app.get('/sent-messages', (req, res) => {
    db.all(
        `SELECT id, phone, type, content, timestamp, media_url, wa_message_id, theme
         FROM sent_messages
         ORDER BY timestamp DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ message: 'Adatbázis hiba' });
            for (const r of rows) r.timestamp = toAppTz(r.timestamp);
            res.json(rows);
        }
    );
});

app.get('/questionnaire-themes', (req, res) => {
    try {
        delete require.cache[require.resolve('./questionnaire')];
        const questionnaires = require('./questionnaire');
        const themes = Object.keys(questionnaires);
        res.json(themes);
    } catch (e) {
        console.error('❌ Nem sikerült beolvasni a kérdőíveket:', e);
        res.status(500).json({ error: 'Nem sikerült beolvasni a témákat.' });
    }
});

app.get('/all-questionnaires', (req, res) => {
    try {
        delete require.cache[require.resolve('./questionnaire')];
        const questionnaires = require('./questionnaire');
        res.json(questionnaires);
    } catch (e) {
        console.error('❌ Hiba a questionnaire.js betöltésekor:', e);
        res.status(500).json({ error: 'Nem sikerült betölteni a kérdőíveket.' });
    }
});

// Adatbázis fájl letöltése
app.get('/download-db', (req, res) => {
    fs.access(dbPath, fs.constants.F_OK, (err) => {
        if (err) {
            console.error('❌ Az adatbázis fájl nem található.');
            return res.status(404).send('Fájl nem található.');
        }

        res.download(dbPath, 'whatsapp_messages.db', (err) => {
            if (err) {
                console.error('❌ Hiba a fájl letöltésénél:', err);
            } else {
                console.log('✅ Adatbázis fájl sikeresen letöltve.');
            }
        });
    });
});

// Szerver indítása
app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Szerver fut a http://0.0.0.0:${port} címen`);
});