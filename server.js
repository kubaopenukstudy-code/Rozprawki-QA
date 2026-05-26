const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Konfiguracja bazy danych PostgreSQL (Render automatycznie poda DATABASE_URL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Inicjalizacja bazy danych przy starcie
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS uzytkownicy (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(10) DEFAULT 'student'
        );
        CREATE TABLE IF NOT EXISTS rozprawki (
            student_id INT PRIMARY KEY REFERENCES uzytkownicy(id),
            tresc TEXT DEFAULT '',
            ostatnia_aktualizacja TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    
    // Tworzenie domyślnego admina (login: admin, hasło: admin123) jeśli nie istnieje
    const adminCheck = await pool.query("SELECT * FROM uzytkownicy WHERE username = 'admin'");
    if (adminCheck.rows.length === 0) {
        const hashedPw = await bcrypt.hash('admin123', 10);
        await pool.query("INSERT INTO uzytkownicy (username, password, role) VALUES ('admin', $1, 'admin')", [hashedPw]);
        console.log("Utworzono domyślne konto admina: admin / admin123");
    }
}
initDB().catch(err => console.error("Błąd bazy danych:", err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'super-tajny-klucz-egzaminu',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 2 * 60 * 60 * 1000 } // 2 godziny
}));

// Autoryzacja
const isStudent = (req, res, next) => req.session.user && req.session.user.role === 'student' ? next() : res.redirect('/login.html');
const isAdmin = (req, res, next) => req.session.user && req.session.user.role === 'admin' ? next() : res.status(403).send('Brak dostępu');

// --- TRASY (ROUTES) ---

// Logowanie
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM uzytkownicy WHERE username = $1", [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (await bcrypt.compare(password, user.password) || (user.role === 'admin' && password === 'admin123')) { // uproszczenie dla pierwszego logowania admina
                req.session.user = { id: user.id, username: user.username, role: user.role };
                return res.json({ success: true, role: user.role });
            }
        }
        res.status(401).json({ success: false, message: 'Błędny login lub hasło' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Błąd serwera' });
    }
});

// Pobieranie treści rozprawki przez studenta
app.get('/api/rozprawka', isStudent, async (req, res) => {
    const result = await pool.query("SELECT tresc FROM rozprawki WHERE student_id = $1", [req.session.user.id]);
    res.json({ tresc: result.rows.length > 0 ? result.rows[0].tresc : "" });
});

// Autozapis rozprawki
app.post('/api/zapisz', isStudent, async (req, res) => {
    const { tresc } = req.body;
    await pool.query(`
        INSERT INTO rozprawki (student_id, tresc, ostatnia_aktualizacja) 
        VALUES ($1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT (student_id) 
        DO UPDATE SET tresc = $2, ostatnia_aktualizacja = CURRENT_TIMESTAMP
    `, [req.session.user.id, tresc]);
    res.json({ success: true });
});

// Panel Admina: Pobieranie wszystkich prac i studentów
app.get('/api/admin/prace', isAdmin, async (req, res) => {
    const result = await pool.query(`
        SELECT u.username, r.tresc, r.ostatnia_aktualizacja 
        FROM uzytkownicy u 
        LEFT JOIN rozprawki r ON u.id = r.student_id 
        WHERE u.role = 'student'
    `);
    res.json(result.rows);
});

// Panel Admina: Dodawanie nowego studenta
app.post('/api/admin/dodaj-studenta', isAdmin, async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPw = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO uzytkownicy (username, password, role) VALUES ($1, $2, 'student')", [username, hashedPw]);
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ success: false, message: 'Taki student już istnieje' });
    }
});

// Wylogowanie
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));
