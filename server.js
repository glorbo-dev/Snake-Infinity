const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors()); // Allows frontend to communicate with backend
app.use(express.json());

const DB_FILE = path.join(__dirname, 'users.json');

// Create the JSON database file if it doesn't exist
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({}));
}

function readDB() {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// REGISTER ENDPOINT
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

    const db = readDB();
    const uLower = username.toLowerCase();

    if (db[uLower]) {
        return res.status(400).json({ error: 'Username already exists!' });
    }

    // Securely hash password
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

    db[uLower] = {
        originalName: username,
        salt: salt,
        hash: hash,
        scores: {}
    };

    writeDB(db);
    res.json({ message: 'Registered successfully', username: username });
});

// LOGIN ENDPOINT
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

    const db = readDB();
    const uLower = username.toLowerCase();
    const user = db[uLower];

    if (!user) {
        return res.status(400).json({ error: 'User not found. Check your username.' });
    }

    // Verify password
    const testHash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha512').toString('hex');
    if (testHash !== user.hash) {
        return res.status(400).json({ error: 'Invalid password.' });
    }

    res.json({ message: 'Login successful', username: user.originalName, scores: user.scores });
});

// SYNC SCORES ENDPOINT
app.post('/api/scores', (req, res) => {
    const { username, scores } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });

    const db = readDB();
    const uLower = username.toLowerCase();

    if (db[uLower]) {
        // Merge existing scores with new high scores
        db[uLower].scores = { ...db[uLower].scores, ...scores };
        writeDB(db);
        res.json({ message: 'Scores updated' });
    } else {
        res.status(400).json({ error: 'User not found' });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Backend is running! API available at http://localhost:${PORT}`);
});
