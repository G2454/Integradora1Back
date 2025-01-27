import express from 'express'
import bycrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import sqlite3 from 'sqlite3'

const app = express()

app.use(express.json());

const security = bycrypt

const db = new sqlite3.Database('./db/database.sqlite', (err) => {
    if (err) console.error('Error opening database:', err);
    else {
      db.run(
        `CREATE TABLE IF NOT EXISTS users (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           fullName TEXT,
           email TEXT UNIQUE,
           password TEXT
         );`
      );
      db.run(
        `CREATE TABLE IF NOT EXISTS events (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           name TEXT,
           date TEXT,
           time TEXT,
           place TEXT,
           image TEXT,
           description TEXT
         );`
      );
    }
  });
  
  // Register User
  app.post('/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    const hashedPassword = await security.hash(password, 10);
    db.run(
      `INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)`,
      [fullName, email, hashedPassword],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email already exists' });
        res.json({ message: 'User registered successfully' });
      }
    );
  });
  
  // Login User
  app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
      if (err || !user || !(await security.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      const token = jwt.sign({ id: user.id }, 'secret_key', { expiresIn: '1h' });
      res.json({ token });
    });
  });
  
  // CRUD for Events
  app.post('/events', (req, res) => {
    const { name, date, time, place, image, description } = req.body;
    db.run(
      `INSERT INTO events (name, date, time, place, image, description) VALUES (?, ?, ?, ?, ?, ?)`,
      [name, date, time, place, image, description],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ id: this.lastID, message: 'Event created successfully' });
      }
    );
  });
  
  app.get('/events', (req, res) => {
    db.all(`SELECT * FROM events`, [], (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    });
  });
  
  app.put('/events/:id', (req, res) => {
    const { name, date, time, place, image, description } = req.body;
    const { id } = req.params;
    db.run(
      `UPDATE events SET name = ?, date = ?, time = ?, place = ?, image = ?, description = ? WHERE id = ?`,
      [name, date, time, place, image, description, id],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ message: 'Event updated successfully' });
      }
    );
  });
  
  app.delete('/events/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM events WHERE id = ?`, [id], function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'Event deleted successfully' });
    });
  });
  
  // Start the server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));