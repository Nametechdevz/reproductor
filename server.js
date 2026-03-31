const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = new Database('./data/users.db');

// --- 1. BASE DE DATOS ACTUALIZADA ---
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

// Admin inicial
if (!db.prepare('SELECT * FROM users WHERE username = ?').get('admin')) {
    db.prepare("INSERT INTO users (username, password, role, expires_at) VALUES ('admin', ?, 'admin', '2099-12-31')")
      .run(bcrypt.hashSync('1234', 10));
}

// --- 2. MIDDLEWARES ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'megatv_secret_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const authRequired = (req, res, next) => {
    if (req.session.user) next();
    else res.status(401).json({ error: 'No autorizado' });
};

// --- 3. RUTAS PARA LIVE TV Y MULTI-DNS ---

// Configuración que lee el Frontend
app.get('/api/config', authRequired, (req, res) => {
    const config = db.prepare('SELECT server, username, password FROM iptv_playlists ORDER BY is_default DESC LIMIT 1').get();
    res.json(config || { server: '', username: '', password: '' });
});

// Guardar nueva DNS
app.put('/api/admin/iptv-config', authRequired, (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send();
    const { server, username, password } = req.body;
    // Marcamos las anteriores como no predeterminadas e insertamos la nueva
    db.prepare('UPDATE iptv_playlists SET is_default = 0').run();
    db.prepare('INSERT INTO iptv_playlists (server, username, password, is_default) VALUES (?, ?, ?, 1)').run(server, username, password);
    res.json({ success: true });
});

// --- 4. RUTAS DE LA NUBE (S3) - Evita el Error 404 ---
app.get('/api/s3/status', authRequired, (req, res) => {
    res.json({ available: false, message: "Nube no configurada en este servidor" });
});

app.get('/api/s3/browse', authRequired, (req, res) => {
    // Respondemos con una lista vacía para que el Frontend no explote
    res.json({ currentPath: '', folders: [], videos: [] });
});

// --- 5. CATEGORÍAS (Para que aparezca "Live TV") ---
app.get('/api/local/categories', authRequired, (req, res) => {
    res.json([
        { type: 'live', name: '📺 TV EN VIVO', count: 'ONLINE' },
        { type: 'movies', name: '🎬 PELÍCULAS', count: 'VOD' },
        { type: 'series', name: '🍿 SERIES', count: 'TV' },
        { type: 'megatv', name: '⭐ PANEL MEGA', count: db.prepare('SELECT count(*) as c FROM custom_channels').get().c }
    ]);
});

// --- 6. GESTIÓN DE USUARIOS ---
app.get('/api/admin/users', authRequired, (req, res) => {
    const users = db.prepare('SELECT id, username, role, is_active, expires_at, is_demo FROM users').all();
    res.json(users);
});

app.post('/api/admin/users', authRequired, (req, res) => {
    const { username, password, expiresAt, isDemo } = req.body;
    try {
        const hash = bcrypt.hashSync(password, 10);
        db.prepare("INSERT INTO users (username, password, role, expires_at, is_demo) VALUES (?, ?, 'user', ?, ?)")
          .run(username, hash, isDemo ? new Date(Date.now() + 30*60000).toISOString() : expiresAt, isDemo ? 1 : 0);
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: 'Error: El usuario ya existe' }); }
});

// --- RESTO DE RUTAS ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (user && bcrypt.compareSync(password, user.password)) {
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

app.get('/api/local/status', (req, res) => res.json({ available: true }));
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.post('/api/heartbeat', (req, res) => res.json({ success: true }));

const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Motor MegaTV en http://localhost:${PORT}`));