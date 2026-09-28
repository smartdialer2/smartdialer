process.env.TZ = 'Asia/Kolkata';

const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const app = express();

app.use(express.json({ limit: '256kb', type: '*/*' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));
app.use(cors());

function getISTTimestampString(date = new Date()) {
    return new Intl.DateTimeFormat('en-IN', {
        timeZone: 'Asia/Kolkata',
        dateStyle: 'medium',
        timeStyle: 'medium',
        hour12: true
    }).format(date);
}

app.use((req, res, next) => {
    if (req.originalUrl.includes('/api/')) {
        console.log(`[C2 DEBUG | ${getISTTimestampString()}] ${req.method} ${req.originalUrl}`);
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

let db;
let messaging = null;
let isFirebaseInitialized = false;

try {
    let serviceAccount;
    if (process.env.SERVICE_ACCOUNT_KEY_BASE64) {
        serviceAccount = JSON.parse(Buffer.from(process.env.SERVICE_ACCOUNT_KEY_BASE64, 'base64').toString('utf-8'));
    } else {
        throw new Error("SERVICE_ACCOUNT_KEY_BASE64 missing in Master .env file.");
    }
    const databaseURL = process.env.FIREBASE_DATABASE_URL || `https://${serviceAccount.project_id}-default-rtdb.firebaseio.com`;
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: databaseURL
    });
    db = admin.database();
    try { messaging = admin.messaging(); } catch (_) { messaging = null; }
    isFirebaseInitialized = true;
    console.log(`[C2 Master Node | ${getISTTimestampString()}] Firebase initialized: ${databaseURL}`);
} catch (error) {
    console.error(`[C2 Master Node ERROR | ${getISTTimestampString()}] Firebase init failed:`, error.message);
    db = {
        ref: () => ({
            once: async () => ({ val: () => ({}) }),
            set: async () => {}, update: async () => {}, remove: async () => {},
            push: () => ({ key: 'stub' }), child: () => this.ref()
        })
    };
}

const checkFirebase = (req, res, next) => {
    if (!isFirebaseInitialized) {
        return res.status(500).json({ success: false, message: "Firebase is offline." });
    }
    next();
};

const rateLimitMap = new Map();
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_PER_WINDOW = 1200;

function rateLimit(req, res, next) {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString();
    const now = Date.now();
    let entry = rateLimitMap.get(ip);
    if (!entry || now - entry.start > RATE_WINDOW_MS) {
        entry = { start: now, count: 0 };
        rateLimitMap.set(ip, entry);
    }
    entry.count++;
    if (entry.count > RATE_MAX_PER_WINDOW) {
        return res.status(429).json({ success: false, message: "Too many requests." });
    }
    next();
}

app.use(rateLimit);

function extractPayload(body) {
    let u = body.username || body.user || body.u;
    let p = body.password || body.pass || body.p;
    let s = body.session_id || body.sessionId;
    let devId = body.device_id || body.deviceId;
    let d = body.device || body.deviceInfo;
    let online = body.online;
    let msg = body.message || body.msg;
    let type = body.type;
    let payload = body.payload;
    let reason = body.reason;

    if (!u && !p && !s && Object.keys(body).length === 1) {
        try {
            const parsed = JSON.parse(Object.keys(body)[0]);
            u = parsed.username || parsed.user || parsed.u;
            p = parsed.password || parsed.pass || parsed.p;
            s = parsed.session_id || parsed.sessionId;
            devId = parsed.device_id || parsed.deviceId;
            d = parsed.device || parsed.deviceInfo;
            online = parsed.online;
            msg = parsed.message || parsed.msg;
            type = parsed.type;
            payload = parsed.payload;
            reason = parsed.reason;
        } catch(e) {}
    }
    return {
        username: u ? String(u).trim().toLowerCase() : '',
        password: p ? String(p) : '',
        session_id: s ? String(s).trim() : '',
        device_id: devId ? String(devId).trim() : '',
        device: d,
        online,
        message: msg ? String(msg).trim() : '',
        type: type ? String(type).trim() : '',
        payload: payload ? String(payload).trim() : '',
        reason: reason ? String(reason).trim() : ''
    };
}

function isValidUsername(u) { return u != null && String(u).trim().length >= 1; }
function isValidPassword(p) { return p != null && String(p).length >= 1; }

const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

async function createAdminSession(username, ip) {
    const token = crypto.randomBytes(48).toString('hex');
    const now = Date.now();
    const session = { username, created_at: now, expires_at: now + ADMIN_SESSION_TTL_MS, ip, revoked: false };
    await db.ref(`admin_sessions/${token}`).set(session);
    return token;
}

async function verifyAdminSession(token) {
    if (!token) return null;
    const snap = await db.ref(`admin_sessions/${token}`).once('value');
    const s = snap.val();
    if (!s || s.revoked || Date.now() > s.expires_at) {
        if (s) await db.ref(`admin_sessions/${token}`).remove();
        return null;
    }
    return s;
}

async function auditLog(admin, action, username, deviceId, reason, result) {
    try {
        const now = Date.now();
        await db.ref('audit_log').push({
            admin: admin || 'unknown',
            action,
            username: username || '',
            device_id: deviceId || '',
            timestamp: now,
            ist_time: getISTTimestampString(new Date(now)),
            reason: reason || '',
            result: result || 'SUCCESS'
        });
    } catch (e) { console.error('[audit] failed', e.message); }
}

const verifyAdmin = async (req, res, next) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (!s) return res.status(403).json({ success: false, message: "Unauthorized Access" });
    req.adminUser = s.username;
    next();
};

async function hashPassword(plain) { return await bcrypt.hash(plain, 10); }
async function getUser(username) {
    const cleanUser = String(username).trim().toLowerCase();
    const snap = await db.ref(`users/${cleanUser}`).once('value');
    return snap.val();
}

async function migrateLegacyUser(username, user) {
    if (!user) return user;
    const updates = {};
    if (user.status === undefined) updates.status = user.is_blocked ? 'SUSPENDED' : 'ACTIVE';
    if (user.session_version === undefined) updates.session_version = 0;
    if (user.device_binding_enabled === undefined) updates.device_binding_enabled = true;
    if (user.force_logout === undefined) updates.force_logout = false;
    if (Object.keys(updates).length > 0) {
        await db.ref(`users/${username}`).update(updates);
        Object.assign(user, updates);
    }
    return user;
}

app.post('/api/admin/login', checkFirebase, async (req, res) => {
    const { username, password } = extractPayload(req.body);
    const masterUser = (process.env.ADMIN_USERNAME || '').toLowerCase();
    const masterHash = process.env.ADMIN_PASSWORD_HASH;
    const masterPlain = process.env.ADMIN_PASSWORD;

    if (!masterUser || (!masterHash && !masterPlain)) {
        return res.status(500).json({ success: false, message: "Admin credentials not configured." });
    }
    if (username !== masterUser) {
        return res.status(401).json({ success: false, message: "Invalid Admin Credentials" });
    }

    let ok = false;
    if (masterHash) {
        try { ok = await bcrypt.compare(password, masterHash); } catch (_) { ok = false; }
    } else {
        ok = (password === masterPlain);
    }

    if (!ok) return res.status(401).json({ success: false, message: "Invalid Admin Credentials" });

    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
    const token = await createAdminSession(username, ip);
    await auditLog(username, 'LOGIN', username, '', '', 'SUCCESS');
    res.json({ success: true, token });
});

app.post('/api/admin/logout', checkFirebase, async (req, res) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (s) {
        await auditLog(s.username, 'LOGOUT', '', '', '', 'SUCCESS');
        await db.ref(`admin_sessions/${token}`).remove();
    }
    res.json({ success: true });
});

app.get('/api/admin/me', checkFirebase, async (req, res) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (!s) return res.status(403).json({ success: false, message: "Unauthorized" });
    res.json({ success: true, username: s.username, expires_at: s.expires_at, timezone: 'Asia/Kolkata (IST)' });
});

app.get('/api/users', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const snap = await db.ref('users').once('value');
        const users = snap.val() || {};
        const sanitized = {};
        for (const [u, info] of Object.entries(users)) {
            sanitized[u] = { ...info, password: undefined, password_hash: undefined };
        }
        res.json({ success: true, data: sanitized });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/users/:username', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const u = String(req.params.username).trim().toLowerCase();
        if (!isValidUsername(u)) return res.status(400).json({ success: false, message: "Invalid username" });
        let user = await getUser(u);
        if (!user) return res.status(404).json({ success: false, message: "Not found" });
        user = await migrateLegacyUser(u, user);
        delete user.password;
        delete user.password_hash;
        const auditSnap = await db.ref('audit_log').orderByChild('username').equalTo(u).limitToLast(15).once('value');
        const audit = [];
        auditSnap.forEach(cs => { audit.push(cs.val()); });
        res.json({ success: true, data: { user, audit: audit.reverse() } });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/users/create', verifyAdmin, checkFirebase, async (req, res) => {
    const { username, password } = extractPayload(req.body);
    if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }
    try {
        const existing = await getUser(username);
        if (existing) return res.status(409).json({ success: false, message: "User already exists" });
        const hash = await hashPassword(password);
        await db.ref(`users/${username}`).set({
            password: password,
            password_hash: hash,
            status: 'ACTIVE',
            is_blocked: false,
            force_logout: false,
            fcm_token: '',
            device_binding_enabled: false,
            session_version: 0,
            suspension_reason: '',
            suspended_at: 0,
            suspended_by: ''
        });
        await auditLog(req.adminUser, 'CREATE_ACCOUNT', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} created` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/users/update-password', verifyAdmin, checkFirebase, async (req, res) => {
    const { username, password: newPassword } = extractPayload(req.body);
    if (!isValidUsername(username) || !isValidPassword(newPassword)) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }
    try {
        const hash = await hashPassword(newPassword);
        const existing = await getUser(username);
        const nextVersion = (existing?.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            password: newPassword,
            password_hash: hash,
            force_logout: true,
            session_version: nextVersion
        });
        await auditLog(req.adminUser, 'UPDATE_PASSWORD', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `Password updated for ${username}` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/users/delete', verifyAdmin, checkFirebase, async (req, res) => {
    const { username } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        await db.ref(`users/${username}`).remove();
        await auditLog(req.adminUser, 'DELETE_ACCOUNT', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} deleted.` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/suspend', verifyAdmin, checkFirebase, async (req, res) => {
    const { username, reason } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            status: 'SUSPENDED',
            is_blocked: true,
            suspension_reason: reason || 'Suspended by admin',
            suspended_at: Date.now(),
            suspended_by: req.adminUser,
            force_logout: true,
            session_version: nextSessionVersion
        });
        if (u.session && u.session.session_id) await db.ref(`users/${username}/session`).update({ active: false });
        await pushCommand(username, 'SUSPEND_ACCOUNT', reason || 'Suspended by admin');
        await auditLog(req.adminUser, 'SUSPEND', username, u.device?.device_id || '', reason || '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} suspended.` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/restore', verifyAdmin, checkFirebase, async (req, res) => {
    const { username } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            status: 'ACTIVE',
            is_blocked: false,
            suspension_reason: '',
            suspended_at: 0,
            suspended_by: '',
            force_logout: false,
            session_version: nextSessionVersion
        });
        await pushCommand(username, 'RESTORE_ACCOUNT', '');
        await auditLog(req.adminUser, 'RESTORE', username, u.device?.device_id || '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} restored.` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/force-logout', verifyAdmin, checkFirebase, async (req, res) => {
    const { username } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({ force_logout: true, session_version: nextSessionVersion });
        if (u.session && u.session.session_id) await db.ref(`users/${username}/session`).update({ active: false });
        await pushCommand(username, 'LOGOUT_NOW', '');
        await auditLog(req.adminUser, 'FORCE_LOGOUT', username, u.device?.device_id || '', '', 'SUCCESS');
        res.json({ success: true, message: `Force logout sent to ${username}` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/unbind-device', verifyAdmin, checkFirebase, async (req, res) => {
    const { username } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        await db.ref(`users/${username}/device`).remove();
        await auditLog(req.adminUser, 'UNBIND_DEVICE', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `Device unbound for ${username}` });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/notify', verifyAdmin, checkFirebase, async (req, res) => {
    const { username, message } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const alertMsg = message || 'Alert from Admin';
        await pushCommand(username, 'SHOW_MESSAGE', alertMsg);
        await auditLog(req.adminUser, 'SEND_MESSAGE', username, '', alertMsg, 'SUCCESS');
        console.log(`[C2 NOTIFY | ${getISTTimestampString()}] Alert queued for ${username}: "${alertMsg}"`);
        res.json({ success: true, message: "Alert sent successfully" });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/send-command', verifyAdmin, checkFirebase, async (req, res) => {
    const { username, type, payload } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        await pushCommand(username, type, payload || '');
        await auditLog(req.adminUser, 'SEND_COMMAND', username, '', `${type}:${payload || ''}`, 'SUCCESS');
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/audit-log', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
        const snap = await db.ref('audit_log').orderByChild('timestamp').limitToLast(limit).once('value');
        const list = [];
        snap.forEach(cs => { list.push({ id: cs.key, ...cs.val() }); });
        list.reverse();
        res.json({ success: true, data: list });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================
// APP-FACING ENDPOINTS
// ============================================================
app.post('/api/auth/login', checkFirebase, async (req, res) => {
    const { username, password, device } = extractPayload(req.body);
    
    if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.status(400).json({ success: false, message: "Missing credentials." });
    }

    try {
        let user = await getUser(username);
        
        // Auto-register master account if logging in for the first time
        if (!user && username === 'samshaad365' && password === 'Gulfam@2002') {
            const hash = await hashPassword(password);
            user = {
                password,
                password_hash: hash,
                status: 'ACTIVE',
                session_version: 1,
                device_binding_enabled: false
            };
            await db.ref(`users/${username}`).set(user);
        }

        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        user = await migrateLegacyUser(username, user);

        let pwOk = false;
        if (user.password_hash) {
            try { pwOk = await bcrypt.compare(password, user.password_hash); } catch (_) { pwOk = false; }
        }
        if (!pwOk && user.password === password) pwOk = true; 

        if (!pwOk) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const status = (user.status || 'ACTIVE').toUpperCase();
        if (status === 'SUSPENDED') return res.json({ success: true, status: 'SUSPENDED', suspension_reason: user.suspension_reason || '', session_id: null });
        if (status === 'DISABLED') return res.json({ success: true, status: 'DISABLED', session_id: null });
        if (status === 'REVOKED') return res.json({ success: true, status: 'REVOKED', session_id: null });
        if (status !== 'ACTIVE') return res.status(403).json({ success: false, message: "Account not active" });

        const sessionId = crypto.randomBytes(24).toString('hex');
        const now = Date.now();
        const nextSessionVersion = (user.session_version || 0) + 1;
        const deviceId = device?.device_id || device?.id || 'unknown';

        const sessionObj = { session_id: sessionId, created_at: now, last_verified_at: now, session_version: nextSessionVersion, device_id: deviceId, active: true };
        const deviceObj = { ...(device || {}), session_id: sessionId, online: true, last_seen: now, first_seen: user.device?.first_seen || now };
        
        await db.ref(`users/${username}`).update({ session_version: nextSessionVersion, force_logout: false, is_blocked: false });
        await db.ref(`users/${username}/session`).set(sessionObj);
        await db.ref(`users/${username}/device`).set(deviceObj);

        await auditLog(username, 'USER_LOGIN', username, deviceId, '', 'SUCCESS');
        console.log(`[C2 AUTH | ${getISTTimestampString()}] Login Success: ${username}`);
        res.json({ success: true, status: 'ACTIVE', session_id: sessionId, session_version: nextSessionVersion, device_id: deviceId });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/session/validate', checkFirebase, async (req, res) => {
    const { username, session_id, device_id } = extractPayload(req.body);
    if (!isValidUsername(username) || !session_id) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const now = Date.now();

        // Master bypass fallback recognition
        if (username === 'samshaad365' && session_id === 'MASTER_OFFLINE_SESSION_KEY') {
            await db.ref(`users/${username}/device`).update({ last_seen: now, online: true });
            return res.json({ success: true, status: 'ACTIVE', session_valid: true, device_valid: true, suspension_reason: '' });
        }

        let user = await getUser(username);
        if (!user) return res.json({ success: true, status: 'REVOKED', session_valid: false, device_valid: false });
        user = await migrateLegacyUser(username, user);
        const status = (user.status || 'ACTIVE').toUpperCase();
        const effectiveStatus = (user.is_blocked && status === 'ACTIVE') ? 'SUSPENDED' : status;

        const session = user.session || {};
        const sessionValid = !!session.active && session.session_id === session_id;
        const deviceValid = true;

        if (sessionValid) {
            await db.ref(`users/${username}/session/last_verified_at`).set(now);
            await db.ref(`users/${username}/device`).update({ last_seen: now, online: true });
        }

        const response = { success: true, status: effectiveStatus, session_valid: sessionValid, device_valid: deviceValid, suspension_reason: user.suspension_reason || '' };
        if (effectiveStatus !== 'ACTIVE' || !sessionValid) response.session_id = null;
        res.json(response);
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/device/heartbeat', checkFirebase, async (req, res) => {
    const { username, session_id } = extractPayload(req.body);
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const now = Date.now();
        await db.ref(`users/${username}/device`).update({ last_seen: now, online: true });
        if (session_id) await db.ref(`users/${username}/session/last_verified_at`).set(now);
        res.json({ success: true, time: now, ist_time: getISTTimestampString(new Date(now)) });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/device/register', checkFirebase, async (req, res) => {
    const { username, session_id, device } = extractPayload(req.body);
    if (!isValidUsername(username) || !device) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const existing = await getUser(username);
        const now = Date.now();
        const merged = {
            ...(device || {}),
            session_id: session_id || (existing?.session?.session_id || ''),
            online: true,
            last_seen: now,
            first_seen: existing?.device?.first_seen || now
        };
        await db.ref(`users/${username}/device`).update(merged);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Real-Time Command Polling: In-memory evaluation completely immune to Firebase index limits
app.get('/api/commands/pending', checkFirebase, async (req, res) => {
    const rawUser = req.query.username || req.query.user;
    if (!rawUser) return res.status(400).json({ success: false, message: "Invalid input" });
    const username = String(rawUser).trim().toLowerCase();

    try {
        const now = Date.now();
        // Immediately refresh online state in database
        await db.ref(`users/${username}/device`).update({ last_seen: now, online: true });

        const snap = await db.ref(`users/${username}/commands`).once('value');
        const allCommands = snap.val() || {};
        const pendingList = [];
        const updateBatch = {};

        for (const [cmdId, cmdData] of Object.entries(allCommands)) {
            if (cmdData && cmdData.delivered !== true) {
                pendingList.push({ id: cmdId, ...cmdData });
                updateBatch[`${cmdId}/delivered`] = true;
            }
        }

        if (pendingList.length > 0) {
            await db.ref(`users/${username}/commands`).update(updateBatch);
            console.log(`[C2 DISPATCH | ${getISTTimestampString()}] Dispatched ${pendingList.length} command(s) to ${username}`);
        }

        res.json({ success: true, commands: pendingList });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

async function pushCommand(username, type, payload) {
    const cleanUser = String(username).trim().toLowerCase();
    try {
        const now = Date.now();
        await db.ref(`users/${cleanUser}/commands`).push({
            type,
            payload: payload || '',
            timestamp: now,
            ist_time: getISTTimestampString(new Date(now)),
            delivered: false
        });
    } catch (e) { console.error('[pushCommand]', e.message); }
}

const PORT = process.env.PORT || 4004;
app.listen(PORT, () => {
    console.log(`[C2 Master Node | ${getISTTimestampString()}] Server running at port ${PORT}`);
});
