const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'evote_super_secret_jwt_key_2026';
const DB_PATH = path.join(__dirname, 'evoting.db');

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Support base64 image upload

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database at:', DB_PATH);
        initDatabase();
    }
});

// SQLite Helper Functions for Async/Await
const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});

const dbAll = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});

const dbRun = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) { err ? reject(err) : resolve(this); });
});

async function initDatabase() {
    try {
        // Create Table: Admins
        await dbRun(`
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        `);

        // Create Table: Voters (DPT)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS voters (
                nik TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                has_voted INTEGER DEFAULT 0,
                voted_candidate_id INTEGER DEFAULT NULL,
                voted_at DATETIME DEFAULT NULL
            )
        `);

        // Create Table: Candidates
        await dbRun(`
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                photo TEXT NOT NULL,
                visi TEXT NOT NULL,
                misi TEXT NOT NULL,
                votes INTEGER DEFAULT 0
            )
        `);

        // Seed Admin Account if empty
        const adminCount = await dbGet(`SELECT COUNT(*) as count FROM admins`);
        if (adminCount.count === 0) {
            const hashedPass = await bcrypt.hash('admin123', 10);
            await dbRun(`INSERT INTO admins (username, password_hash) VALUES (?, ?)`, ['admin', hashedPass]);
            console.log('Default Admin created -> Username: admin | Password: admin123');
        }

        // Seed Initial Candidates if empty
        const candCount = await dbGet(`SELECT COUNT(*) as count FROM candidates`);
        if (candCount.count === 0) {
            await dbRun(`
                INSERT INTO candidates (id, name, photo, visi, misi, votes) VALUES 
                (1, '01. Alex & Sarah', 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=300&q=80', 'Mewujudkan organisasi yang transparan, inovatif, dan berdaya saing digital.', '1. Optimalisasi sistem pelayanan digital\n2. Program transparansi anggaran terbuka\n3. Wadah kreativitas generasi muda', 1),
                (2, '02. Budi & Citadel', 'https://images.unsplash.com/photo-1560250097-0b93528c311a?auto=format&fit=crop&w=300&q=80', 'Kepemimpinan solid, inklusif, dan berlandaskan asas kekeluargaan.', '1. Penguatan partisipasi aktif anggota\n2. Pelatihan kepemimpinan berkelanjutan\n3. Efisiensi tata kelola internal', 0),
                (3, '03. Citra & Dimas', 'https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?auto=format&fit=crop&w=300&q=80', 'Mendorong keberlanjutan, aksi nyata, dan kolaborasi lintas sektor.', '1. Program ramah lingkungan & hijau\n2. Kolaborasi strategis mitra luar\n3. Respons cepat aspirasi anggota', 0)
            `);
            console.log('Default candidates seeded.');
        }

        // Seed Initial Voters if empty
        const voterCount = await dbGet(`SELECT COUNT(*) as count FROM voters`);
        if (voterCount.count === 0) {
            await dbRun(`
                INSERT INTO voters (nik, name, has_voted, voted_candidate_id, voted_at) VALUES 
                ('3201234567890001', 'Budi Santoso', 0, NULL, NULL),
                ('3201234567890002', 'Siti Rahmawati', 1, 1, CURRENT_TIMESTAMP),
                ('3201234567890003', 'Andi Wijaya', 0, NULL, NULL),
                ('3201234567890004', 'Dewi Lestari', 0, NULL, NULL)
            `);
            console.log('Default DPT voters seeded.');
        }

    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Akses ditolak: Token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Token tidak valid atau kadaluarsa' });
        }
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ success: false, message: 'Akses terbatas hanya untuk Administrator' });
    }
};


// Voter Login via NIK
app.post('/api/auth/voter-login', async (req, res) => {
    try {
        const { nik } = req.body;
        if (!nik) {
            return res.status(400).json({ success: false, message: 'NIK wajib diisi' });
        }

        const voter = await dbGet(`SELECT * FROM voters WHERE nik = ?`, [nik.trim()]);
        if (!voter) {
            return res.status(404).json({ success: false, message: 'NIK tidak terdaftar dalam DPT' });
        }

        const token = jwt.sign(
            { nik: voter.nik, name: voter.name, role: 'voter' },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        return res.json({
            success: true,
            message: 'Verifikasi NIK berhasil',
            token,
            voter: {
                nik: voter.nik,
                name: voter.name,
                hasVoted: Boolean(voter.has_voted),
                votedCandidateId: voter.voted_candidate_id
            }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Terjadi kesalahan server', error: error.message });
    }
});

// Admin Login via Username & Password
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username dan Password wajib diisi' });
        }

        const admin = await dbGet(`SELECT * FROM admins WHERE username = ?`, [username.trim()]);
        if (!admin) {
            return res.status(401).json({ success: false, message: 'Username atau Password salah' });
        }

        const isMatch = await bcrypt.compare(password, admin.password_hash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Username atau Password salah' });
        }

        const token = jwt.sign(
            { id: admin.id, username: admin.username, role: 'admin' },
            JWT_SECRET,
            { expiresIn: '12h' }
        );

        return res.json({
            success: true,
            message: 'Login Admin berhasil',
            token,
            admin: { username: admin.username, role: 'admin' }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Terjadi kesalahan server', error: error.message });
    }
});


// Get All Candidates
app.get('/api/candidates', async (req, res) => {
    try {
        const candidates = await dbAll(`SELECT * FROM candidates ORDER BY id ASC`);
        return res.json({ success: true, data: candidates });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal mengambil data kandidat', error: error.message });
    }
});

// Add Candidate (Admin Only)
app.post('/api/candidates', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, photo, visi, misi } = req.body;
        if (!name || !visi || !misi) {
            return res.status(400).json({ success: false, message: 'Nama, Visi, dan Misi wajib diisi' });
        }

        const defaultPhoto = photo || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=300&q=80';

        const result = await dbRun(
            `INSERT INTO candidates (name, photo, visi, misi, votes) VALUES (?, ?, ?, ?, 0)`,
            [name.trim(), defaultPhoto, visi.trim(), misi.trim()]
        );

        return res.status(201).json({
            success: true,
            message: 'Kandidat berhasil ditambahkan',
            candidateId: result.lastID
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menambah kandidat', error: error.message });
    }
});

// Delete Candidate (Admin Only)
app.delete('/api/candidates/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const candidateId = req.params.id;
        await dbRun(`DELETE FROM candidates WHERE id = ?`, [candidateId]);
        return res.json({ success: true, message: 'Kandidat berhasil dihapus' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menghapus kandidat', error: error.message });
    }
});


// Get All DPT Voters (Admin Only)
app.get('/api/voters', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const voters = await dbAll(`SELECT nik, name, has_voted, voted_candidate_id, voted_at FROM voters ORDER BY name ASC`);
        return res.json({ success: true, data: voters });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal mengambil data DPT', error: error.message });
    }
});

// Add New DPT Voter (Admin Only)
app.post('/api/voters', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { nik, name } = req.body;
        if (!nik || !name || nik.trim() ){
            return res.status(400).json({ success: false, message: 'NIK wajib diisi' });
        }

        const existing = await dbGet(`SELECT nik FROM voters WHERE nik = ?`, [nik.trim()]);
        if (existing) {
            return res.status(400).json({ success: false, message: 'NIK ini sudah terdaftar dalam DPT' });
        }

        await dbRun(`INSERT INTO voters (nik, name, has_voted) VALUES (?, ?, 0)`, [nik.trim(), name.trim()]);
        return res.status(201).json({ success: true, message: 'DPT baru berhasil ditambahkan' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menambah DPT', error: error.message });
    }
});

// Reset Single Voter's Vote (Admin Only)
app.post('/api/voters/reset/:nik', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const nik = req.params.nik;
        const voter = await dbGet(`SELECT * FROM voters WHERE nik = ?`, [nik]);

        if (!voter) {
            return res.status(404).json({ success: false, message: 'Pemilih tidak ditemukan' });
        }

        if (voter.has_voted && voter.voted_candidate_id) {
            // Decrement vote count for the candidate
            await dbRun(`UPDATE candidates SET votes = MAX(0, votes - 1) WHERE id = ?`, [voter.voted_candidate_id]);
        }

        // Reset voter state
        await dbRun(`UPDATE voters SET has_voted = 0, voted_candidate_id = NULL, voted_at = NULL WHERE nik = ?`, [nik]);

        return res.json({ success: true, message: `Status suara pemilih NIK ${nik} berhasil di-reset` });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal me-reset suara pemilih', error: error.message });
    }
});


// Submit Vote (Voter Only - Double Vote Protection)
app.post('/api/vote', authenticateToken, async (req, res) => {
    try {
        const voterNik = req.user.nik;
        const { candidateId } = req.body;

        if (!candidateId) {
            return res.status(400).json({ success: false, message: 'ID Kandidat wajib disertakan' });
        }

        // Atomic Transaction Simulation: Check current vote status
        const voter = await dbGet(`SELECT * FROM voters WHERE nik = ?`, [voterNik]);
        if (!voter) {
            return res.status(404).json({ success: false, message: 'Pemilih tidak terdaftar' });
        }

        if (voter.has_voted) {
            return res.status(400).json({ success: false, message: 'Anda sudah pernah memberikan suara! Hak pilih hanya 1x.' });
        }

        const candidate = await dbGet(`SELECT * FROM candidates WHERE id = ?`, [candidateId]);
        if (!candidate) {
            return res.status(404).json({ success: false, message: 'Kandidat tidak ditemukan' });
        }

        // Execute Vote Entry
        await dbRun(`UPDATE candidates SET votes = votes + 1 WHERE id = ?`, [candidateId]);
        await dbRun(
            `UPDATE voters SET has_voted = 1, voted_candidate_id = ?, voted_at = CURRENT_TIMESTAMP WHERE nik = ?`,
            [candidateId, voterNik]
        );

        return res.json({
            success: true,
            message: 'Suara Anda berhasil direkam. Terima kasih telah memilih!'
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal memproses suara', error: error.message });
    }
});


// Get Election Statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalVoters = await dbGet(`SELECT COUNT(*) as count FROM voters`);
        const votedCount = await dbGet(`SELECT COUNT(*) as count FROM voters WHERE has_voted = 1`);
        const candidateResults = await dbAll(`SELECT id, name, votes FROM candidates ORDER BY id ASC`);

        const total = totalVoters.count;
        const voted = votedCount.count;
        const unvoted = total - voted;
        const participation = total > 0 ? parseFloat(((voted / total) * 100).toFixed(1)) : 0;

        return res.json({
            success: true,
            stats: {
                totalVoters: total,
                votedCount: voted,
                unvotedCount: unvoted,
                participationRate: participation
            },
            candidates: candidateResults
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal memuat statistik', error: error.message });
    }
});

// Total Reset All Votes (Admin Only)
app.post('/api/admin/reset-all', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await dbRun(`UPDATE candidates SET votes = 0`);
        await dbRun(`UPDATE voters SET has_voted = 0, voted_candidate_id = NULL, voted_at = NULL`);

        return res.json({ success: true, message: 'Seluruh perolehan suara dan status pemilih berhasil di-reset total.' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal me-reset total suara', error: error.message });
    }
});

// Change Admin Password (Admin Only)
app.post('/api/admin/change-password', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Password lama dan password baru wajib diisi' });
        }

        const admin = await dbGet(`SELECT * FROM admins WHERE username = ?`, [req.user.username]);
        const isMatch = await bcrypt.compare(currentPassword, admin.password_hash);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Password saat ini tidak cocok' });
        }

        const newHashed = await bcrypt.hash(newPassword, 10);
        await dbRun(`UPDATE admins SET password_hash = ? WHERE username = ?`, [newHashed, req.user.username]);

        return res.json({ success: true, message: 'Password admin berhasil diperbarui' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal mengubah password', error: error.message });
    }
});


// Start Server
app.listen(PORT, () => {
    console.log(`================================================`);
    console.log(` E-VOTING BACKEND API SERVER RUNNING AT:`);
    console.log(` http://localhost:${PORT}`);
    console.log(`================================================`);
});