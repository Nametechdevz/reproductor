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
`);

// Admin inicial (admin / 1234)
if (!db.prepare('SELECT * FROM users WHERE username = ?').get('admin')) {
    db.prepare("INSERT INTO users (username, password, role, expires_at) VALUES ('admin', ?, 'admin', '2099-12-31')")
      .run(bcrypt.hashSync('1234', 10));
}

// --- 2. MIDDLEWARES ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'megatv_premium_key_88',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const authRequired = (req, res, next) => {
    if (req.session.user) next();
    else res.status(401).json({ error: 'No autorizado' });
};

// --- 3. LÓGICA DE DETECCIÓN DE M3U / DNS ---

// Configuración que lee el Frontend
app.get('/api/config', authRequired, (req, res) => {
    const config = db.prepare('SELECT server, username, password FROM iptv_playlists ORDER BY is_default DESC LIMIT 1').get();
    res.json(config || { server: '', username: '', password: '' });
});

// Guardar nueva Lista (Detecta si es M3U o DNS directa)
app.put('/api/admin/iptv-config', authRequired, (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send();
    
    let { server, username, password } = req.body;

    // Si el usuario pega una URL completa de M3U en el campo de "Servidor"
    if (server.includes('get.php')) {
        try {
            const urlObj = new URL(server);
            username = urlObj.searchParams.get('username') || username;
            password = urlObj.searchParams.get('password') || password;
            // Limpiamos el servidor para que solo quede la DNS (ej: http://mgoplus.org:2086)
            server = urlObj.origin;
        } catch (e) {
            console.log("Error parseando M3U URL");
        }
    }

    db.prepare('UPDATE iptv_playlists SET is_default = 0').run();
    db.prepare('INSERT INTO iptv_playlists (server, username, password, is_default) VALUES (?, ?, ?, 1)')
      .run(server, username, password);
    
    console.log(`✅ Nueva Lista Agregada: ${server} | Usuario: ${username}`);
    res.json({ success: true });
});

// --- 4. CATEGORÍAS LOCALES ---
app.get('/api/local/categories', authRequired, (req, res) => {
    res.json([
        { type: 'live', name: '📺 TV EN VIVO', count: 'PRO' },
        { type: 'movies', name: '🎬 PELÍCULAS', count: 'VOD' },
        { type: 'series', name: '🍿 SERIES', count: 'TV' },
        { type: 'megatv', name: '⭐ PANEL MEGA', count: db.prepare('SELECT count(*) as c FROM custom_channels').get().c }
    ]);
});

// --- 5. GESTIÓN DE USUARIOS ---
app.get('/api/admin/users', authRequired, (req, res) => {
    res.json(db.prepare('SELECT id, username, role, is_active, expires_at, is_demo FROM users').all());
});

app.post('/api/admin/users', authRequired, (req, res) => {
    const { username, password, expiresAt, isDemo } = req.body;
    try {
        const hash = bcrypt.hashSync(password, 10);
        const expiry = isDemo ? new Date(Date.now() + 30*60000).toISOString() : expiresAt;
        db.prepare("INSERT INTO users (username, password, role, expires_at, is_demo) VALUES (?, ?, 'user', ?, ?)")
          .run(username, hash, expiry, isDemo ? 1 : 0);
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: 'Error: El usuario ya existe' }); }
});

app.delete('/api/admin/users/:id', authRequired, (req, res) => {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ success: true });
});

// --- APIS BÁSICAS ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ success: true, user: { ...user, password: '' } });
    } else res.status(401).json({ error: 'Credenciales incorrectas' });
});

app.get('/api/session', (req, res) => {
    if (req.session.user) {
        const user = db.prepare('SELECT id, username, role, expires_at FROM users WHERE id = ?').get(req.session.user.id);
        res.json({ authenticated: true, user });
    } else res.json({ authenticated: false });
});

app.get('/api/local/status', (req, res) => res.json({ available: true }));
app.get('/api/s3/status', (req, res) => res.json({ available: false }));
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.post('/api/heartbeat', (req, res) => res.json({ success: true }));

// --- ARRANQUE ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 SERVIDOR ACTIVO EN: http://104.248.236.242:${PORT}`);
});
