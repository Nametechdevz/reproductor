const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const app = express();

// --- 1. CONFIGURACIÓN INICIAL ---
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = new Database('./data/users.db');

// --- 2. BASE DE DATOS (Esquema Completo) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user',
    expires_at DATETIME, is_active INTEGER DEFAULT 1, is_demo INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS iptv_playlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server TEXT, username TEXT, password TEXT, is_default INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS custom_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, url TEXT, logo TEXT, folder TEXT, sort_order INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER, item_id TEXT, item_type TEXT, item_name TEXT, item_logo TEXT, item_data TEXT,
    PRIMARY KEY (user_id, item_id, item_type)
  );
`);

// Crear admin inicial si no existe (admin / 1234)
if (!db.prepare('SELECT * FROM users WHERE username = ?').get('admin')) {
    db.prepare("INSERT INTO users (username, password, role, expires_at) VALUES ('admin', ?, 'admin', '2099-12-31')")
      .run(bcrypt.hashSync('1234', 10));
}

// --- 3. MIDDLEWARES ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'megatv_premium_vps_2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const authRequired = (req, res, next) => {
    if (req.session.user) next();
    else res.status(401).json({ error: 'Sesión expirada' });
};

// --- 4. RUTAS DEL SISTEMA ---

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (user && bcrypt.compareSync(password, user.password)) {
        if (!user.is_active) return res.status(403).json({ error: 'Cuenta desactivada' });
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ success: true, user: { id: user.id, username: user.username, role: user.role, expires_at: user.expires_at } });
    } else res.status(401).json({ error: 'Credenciales incorrectas' });
});

app.get('/api/session', (req, res) => {
    if (req.session.user) {
        const user = db.prepare('SELECT id, username, role, expires_at FROM users WHERE id = ?').get(req.session.user.id);
        res.json({ authenticated: true, user });
    } else res.json({ authenticated: false });
});

// Configuración IPTV para el Reproductor
app.get('/api/config', authRequired, (req, res) => {
    const config = db.prepare('SELECT server, username, password FROM iptv_playlists ORDER BY is_default DESC LIMIT 1').get();
    res.json(config || { server: '', username: '', password: '' });
});

// Guardar DNS (Detección automática de M3U)
app.put('/api/admin/iptv-config', authRequired, (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send();
    let { server, username, password } = req.body;

    if (server.includes('get.php')) {
        try {
            const urlObj = new URL(server);
            username = urlObj.searchParams.get('username') || username;
            password = urlObj.searchParams.get('password') || password;
            server = urlObj.origin;
        } catch (e) { console.error("Error parseando URL M3U"); }
    }

    db.prepare('UPDATE iptv_playlists SET is_default = 0').run();
    db.prepare('INSERT INTO iptv_playlists (server, username, password, is_default) VALUES (?, ?, ?, 1)').run(server, username, password);
    res.json({ success: true });
});

// --- 5. PROXY DE VIDEO (LA SOLUCIÓN PARA LIVE TV) ---
// Esta ruta redirige el video para saltar bloqueos de CORS
app.get('/live-proxy/:streamId', async (req, res) => {
    const config = db.prepare('SELECT server, username, password FROM iptv_playlists ORDER BY is_default DESC LIMIT 1').get();
    if (!config) return res.status(404).send("DNS no configurada");

    const { streamId } = req.params;
    const ext = req.query.ext || 'ts';
    const streamUrl = `${config.server}/live/${config.username}/${config.password}/${streamId}.${ext}`;

    res.redirect(streamUrl);
});

// Proxy de Datos (Para que carguen las listas de canales sin error CORS)
app.get('/api/proxy/iptv', authRequired, async (req, res) => {
    const config = db.prepare('SELECT server, username, password FROM iptv_playlists ORDER BY is_default DESC LIMIT 1').get();
    if (!config) return res.status(400).json({ error: "Sin DNS" });

    const { action, category_id, series_id } = req.query;
    let target = `${config.server}/player_api.php?username=${config.username}&password=${config.password}&action=${action}`;
    if (category_id) target += `&category_id=${category_id}`;
    if (series_id) target += `&series_id=${series_id}`;

    try {
        const response = await axios.get(target, { timeout: 10000 });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: "El servidor IPTV no responde" });
    }
});

// --- 6. GESTIÓN DE USUARIOS (Panel Admin) ---
app.get('/api/admin/users', authRequired, (req, res) => {
    res.json(db.prepare('SELECT * FROM users').all());
});

app.post('/api/admin/users', authRequired, (req, res) => {
    const { username, password, expiresAt, isDemo } = req.body;
    try {
        const hash = bcrypt.hashSync(password, 10);
        const expiry = isDemo ? new Date(Date.now() + 30*60000).toISOString() : expiresAt;
        db.prepare("INSERT INTO users (username, password, role, expires_at, is_demo) VALUES (?, ?, 'user', ?, ?)")
          .run(username, hash, expiry, isDemo ? 1 : 0);
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: 'Usuario ya existe' }); }
});

app.delete('/api/admin/users/:id', authRequired, (req, res) => {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ success: true });
});

// --- 7. APIS COMPLEMENTARIAS ---
app.get('/api/local/status', (req, res) => res.json({ available: true }));
app.get('/api/s3/status', (req, res) => res.json({ available: false }));
app.get('/api/s3/browse', (req, res) => res.json({ currentPath: '', folders: [], videos: [] }));
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.post('/api/heartbeat', (req, res) => res.json({ success: true }));

app.get('/api/local/categories', authRequired, (req, res) => {
    res.json([
        { type: 'live', name: '📺 LIVE TV', count: 'ONLINE' },
        { type: 'movies', name: '🎬 PELÍCULAS', count: 'VOD' },
        { type: 'series', name: '🍿 SERIES', count: 'TV' }
    ]);
});

// --- ARRANQUE ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    ==================================================
    🚀 REPRODUCTOR MEGA IPTV ACTIVO
    🌐 URL: http://104.248.236.242:${PORT}
    ==================================================
    `);
});
