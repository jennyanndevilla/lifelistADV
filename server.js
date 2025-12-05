require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());


const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'lifelist_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET || 'devsecret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const [result] = await pool.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashed]);
    res.json({ id: result.insertId, email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.execute('SELECT id, email, password FROM users WHERE email = ?', [email]);
  if (!rows || rows.length === 0) return res.status(400).json({ message: 'Invalid credentials' });
  const user = rows[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || 'devsecret', { expiresIn: '1h' });
  res.json({ token });
});


app.get('/api/items', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const [rows] = await pool.execute('SELECT id, title, note FROM items WHERE user_id = ?', [userId]);
  res.json(rows);
});

app.post('/api/items', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { title, note } = req.body;
  const [result] = await pool.execute('INSERT INTO items (user_id, title, note) VALUES (?, ?, ?)', [userId, title, note]);
  res.json({ id: result.insertId, title, note });
});

app.put('/api/items/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const { title, note } = req.body;
  await pool.execute('UPDATE items SET title = ?, note = ? WHERE id = ? AND user_id = ?', [title, note, id, userId]);
  res.json({ message: 'Item updated' });
});

app.delete('/api/items/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  await pool.execute('DELETE FROM items WHERE id = ? AND user_id = ?', [id, userId]);
  res.json({ message: 'Item deleted' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
