const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'evote_super_secret_jwt_key_2026';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Dukung upload foto base64

// Konfigurasi MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 4000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    }
});

// Helper Functions untuk mempermudah query
const dbGet = async (sql, params = []) => {
    const [rows] = await pool.query(sql, params);
    return rows[0] || null;
};

const dbAll = async (sql, params = []) => {
    const [rows] = await pool.query(sql, params);
    return rows;
};

const dbRun = async (sql, params = []) => {
    const [result] = await pool.query(sql, params);
    return result;
};

// Inisialisasi & Seeding Data Awal
async function initDatabase() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Berhasil terhubung ke database MySQL!');
        connection.release();

        // 1. Buat Tabel Admins
        await dbRun(`
            CREATE TABLE IF NOT EXISTS admins (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB;
        `);

        // 2. Buat Tabel Kandidat
        await dbRun(`
            CREATE TABLE IF NOT EXISTS candidates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                photo TEXT NOT NULL,
                visi TEXT NOT NULL,
                misi TEXT NOT NULL,
                votes INT NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB;
        `);

        // 3. Buat Tabel Pemilih (Voters / DPT)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS voters (
                nik VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                has_voted TINYINT(1) NOT NULL DEFAULT 0,
                voted_candidate_id INT DEFAULT NULL,
                voted_at DATETIME DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_voter_candidate FOREIGN KEY (voted_candidate_id) 
                    REFERENCES candidates(id) ON DELETE SET NULL
            ) ENGINE=InnoDB;
        `);

        // Seed Akun Admin Default (admin / admin123) jika belum ada
        const adminCount = await dbGet(`SELECT COUNT(*) as count FROM admins`);
        if (adminCount.count === 0) {
            const hashedPass = await bcrypt.hash('admin123', 10);
            await dbRun(`INSERT INTO admins (username, password_hash) VALUES (?, ?)`, ['admin', hashedPass]);
            console.log('🔑 Akun Admin Default Dibuat -> Username: admin | Password: admin123');
        }

        // Seed Kandidat Awal jika tabel kosong
        const candCount = await dbGet(`SELECT COUNT(*) as count FROM candidates`);
        if (candCount.count === 0) {
            await dbRun(`
                INSERT INTO candidates (id, name, photo, visi, misi, votes) VALUES 
                (1, '01. Alex & Sarah', 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=300&q=80', 'Mewujudkan organisasi yang transparan, inovatif, dan berdaya saing digital.', '1. Optimalisasi sistem pelayanan digital\\n2. Program transparansi anggaran terbuka\\n3. Wadah kreativitas generasi muda', 1),
                (2, '02. Budi & Citadel', 'https://images.unsplash.com/photo-1560250097-0b93528c311a?auto=format&fit=crop&w=300&q=80', 'Kepemimpinan solid, inklusif, dan berlandaskan asas kekeluargaan.', '1. Penguatan partisipasi aktif anggota\\n2. Pelatihan kepemimpinan berkelanjutan\\n3. Efisiensi tata kelola internal', 0),
                (3, '03. Citra & Dimas', 'https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?auto=format&fit=crop&w=300&q=80', 'Mendorong keberlanjutan, aksi nyata, dan kolaborasi lintas sektor.', '1. Program ramah lingkungan & hijau\\n2. Kolaborasi strategis mitra luar\\n3. Respons cepat aspirasi anggota', 0)
            `);
            console.log('👥 Data kandidat awal berhasil di-seed.');
        }

        // Seed DPT Awal jika kosong
        const voterCount = await dbGet(`SELECT COUNT(*) as count FROM voters`);
        if (voterCount.count === 0) {
            await dbRun(`
                INSERT INTO voters (nik, name, has_voted, voted_candidate_id, voted_at) VALUES 
                ('3201234567890001', 'Budi Santoso', 0, NULL, NULL),
                ('3201234567890002', 'Siti Rahmawati', 1, 1, NOW()),
                ('3201234567890003', 'Andi Wijaya', 0, NULL, NULL),
                ('3201234567890004', 'Dewi Lestari', 0, NULL, NULL)
            `);
            console.log('📋 Data DPT awal berhasil di-seed.');
        }
    } catch (error) {
        console.error('❌ Gagal inisialisasi database MySQL:', error.message);
    }
}

// Middleware Autentikasi JWT
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

// ================= API ROUTES =================

// 1. Voter Login via NIK
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

// 2. Admin Login
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

// 3. Ambil Semua Kandidat
app.get('/api/candidates', async (req, res) => {
    try {
        const candidates = await dbAll(`SELECT * FROM candidates ORDER BY id ASC`);
        return res.json({ success: true, data: candidates });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal mengambil data kandidat', error: error.message });
    }
});

// 4. Tambah Kandidat (Admin Only)
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
            candidateId: result.insertId
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menambah kandidat', error: error.message });
    }
});

// 5. Hapus Kandidat (Admin Only)
app.delete('/api/candidates/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const candidateId = req.params.id;
        await dbRun(`DELETE FROM candidates WHERE id = ?`, [candidateId]);
        return res.json({ success: true, message: 'Kandidat berhasil dihapus' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menghapus kandidat', error: error.message });
    }
});

// 6. Ambil Data DPT (Admin Only)
app.get('/api/voters', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const voters = await dbAll(`SELECT nik, name, has_voted, voted_candidate_id, voted_at FROM voters ORDER BY name ASC`);
        return res.json({ success: true, data: voters });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal mengambil data DPT', error: error.message });
    }
});

// 7. Tambah Pemilih DPT Baru (Admin Only)
app.post('/api/voters', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { nik, name, nama } = req.body;
        const voterName = name || nama;

        if (!nik || !voterName || !nik.trim() || !voterName.trim()) {
            return res.status(400).json({ success: false, message: 'NIK dan Nama wajib diisi!' });
        }

        const cleanNik = nik.trim();
        const cleanName = voterName.trim();

        const existing = await dbGet(`SELECT nik FROM voters WHERE nik = ?`, [cleanNik]);
        if (existing) {
            return res.status(400).json({ success: false, message: 'NIK ini sudah terdaftar dalam DPT' });
        }

        await dbRun(`INSERT INTO voters (nik, name, has_voted) VALUES (?, ?, 0)`, [cleanNik, cleanName]);
        return res.status(201).json({ success: true, message: 'DPT baru berhasil ditambahkan' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal menambah DPT', error: error.message });
    }
});

// 8. Reset Hak Suara Pemilih Tunggal (Admin Only)
app.post('/api/voters/reset/:nik', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const nik = req.params.nik;
        const voter = await dbGet(`SELECT * FROM voters WHERE nik = ?`, [nik]);

        if (!voter) {
            return res.status(404).json({ success: false, message: 'Pemilih tidak ditemukan' });
        }

        if (voter.has_voted && voter.voted_candidate_id) {
            await dbRun(`UPDATE candidates SET votes = GREATEST(0, votes - 1) WHERE id = ?`, [voter.voted_candidate_id]);
        }

        await dbRun(`UPDATE voters SET has_voted = 0, voted_candidate_id = NULL, voted_at = NULL WHERE nik = ?`, [nik]);

        return res.json({ success: true, message: `Status suara pemilih NIK ${nik} berhasil di-reset` });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal me-reset suara pemilih', error: error.message });
    }
});

// 9. Submit Voting (Vote Sekali Pakai)
app.post('/api/vote', authenticateToken, async (req, res) => {
    try {
        const voterNik = req.user.nik;
        const { candidateId } = req.body;

        if (!candidateId) {
            return res.status(400).json({ success: false, message: 'ID Kandidat wajib disertakan' });
        }

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

        // Simpan suara ke kandidat dan update status pemilih
        await dbRun(`UPDATE candidates SET votes = votes + 1 WHERE id = ?`, [candidateId]);
        await dbRun(
            `UPDATE voters SET has_voted = 1, voted_candidate_id = ?, voted_at = NOW() WHERE nik = ?`,
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

// 10. Statistik Hasil Pemilihan Realtime
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

// 11. Reset Total Semua Suara (Admin Only)
app.post('/api/admin/reset-all', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await dbRun(`UPDATE candidates SET votes = 0`);
        await dbRun(`UPDATE voters SET has_voted = 0, voted_candidate_id = NULL, voted_at = NULL`);

        return res.json({ success: true, message: 'Seluruh perolehan suara dan status pemilih berhasil di-reset total.' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Gagal me-reset total suara', error: error.message });
    }
});

// 12. Ganti Password Admin
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

// Jalankan Server & Inisialisasi Database
app.listen(PORT, async () => {
    console.log(`================================================`);
    console.log(` E-VOTING BACKEND RUNNING AT: http://localhost:${PORT}`);
    console.log(`================================================`);
    await initDatabase();
});
