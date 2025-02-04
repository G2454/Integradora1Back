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
      db.run(
        `CREATE TABLE IF NOT EXISTS user_favorites (
           user_id INTEGER,
           event_id INTEGER,
           PRIMARY KEY (user_id, event_id),
           FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
           FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
         );`
      );
      
    }
  });

  app.put('/users/:id/favorite-event', (req, res) => {
    const { id } = req.params; // User ID
    const { eventId } = req.body; // Event ID to favorite/unfavorite
  
    if (!eventId) {
      return res.status(400).json({ error: 'Event ID is required' });
    }
  
    // Check if the favorite already exists
    db.get(
      `SELECT * FROM user_favorites WHERE user_id = ? AND event_id = ?`,
      [id, eventId],
      (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
  
        if (row) {
          // If it exists, remove it (unfavorite)
          db.run(
            `DELETE FROM user_favorites WHERE user_id = ? AND event_id = ?`,
            [id, eventId],
            function (err) {
              if (err) return res.status(500).json({ error: err.message });
              res.json({ message: 'Event unfavorited successfully' });
            }
          );
        } else {
          // If it does not exist, add it (favorite)
          db.run(
            `INSERT INTO user_favorites (user_id, event_id) VALUES (?, ?)`,
            [id, eventId],
            function (err) {
              if (err) return res.status(500).json({ error: err.message });
              res.json({ message: 'Event favorited successfully' });
            }
          );
        }
      }
    );
  });

  app.get('/users/:id/favorite-events', (req, res) => {
    const { id } = req.params; // User ID
  
    db.all(
      `SELECT events.* FROM events
       JOIN user_favorites ON events.id = user_favorites.event_id
       WHERE user_favorites.user_id = ?`,
      [id],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ favoritedEvents: rows });
      }
    );
  });
  
  

  app.put('/change-password/:email', async (req, res) => {
    const { email } = req.params; // Get email from URL
    const { newPassword } = req.body; // Get new password from request body
  
    if (!newPassword) {
      return res.status(400).json({ error: 'New password is required' });
    }
  
    try {
      const hashedPassword = await security.hash(newPassword, 10);
  
      db.run(
        `UPDATE users SET password = ? WHERE email = ?`,
        [hashedPassword, email],
        function (err) {
          if (err) return res.status(500).json({ error: err.message });
  
          if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
          }
  
          res.json({ message: 'Password updated successfully' });
        }
      );
    } catch (error) {
      res.status(500).json({ error: 'Something went wrong' });
    }
  });
  

  app.get('/emails', (req, res) => {
    db.all(`SELECT email FROM users`, [], (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
  
      // Extract only the email field from each row
      const emails = rows.map(row => row.email);
  
      res.json({ emails });
    });
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
      
      // Return full user info along with token
      res.json({
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        token
      });
    });
  });
  
  
  // CRUD for Events
  app.post('/events', (req, res) => {
    const { name, date, time, place, image, description } = req.body;
    db.run(
      `INSERT INTO events (name, date, time, place, image, description) VALUES (?, ?, ?, ?, ?, ?)`,
      [name, date, time, place, image, description],
      function (err) {
        if (err) return res.status(400).json({ error: err.message }) ;
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