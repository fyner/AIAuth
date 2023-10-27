const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const dotenv = require('dotenv');
dotenv.config();

const db = new sqlite3.Database('db.sqlite3', (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the SQLite database.');
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
  }
});

const app = express();

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'defaultsecret',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true } // Set secure to true if using HTTPS
}));

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { realLink: '/login' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error(err.message);
      res.send('Error during login');
    } else if (row) {
      bcrypt.compare(password, row.password, (err, result) => {
        if (result) {
          req.session.userId = row.id;
          req.session.username = row.username;
          res.redirect('/home');
        } else {
          res.send('Invalid username or password');
        }
      });
    } else {
      res.send('Invalid username or password');
    }
  });
});

app.get('/register', (req, res) => {
  res.render('register', { realLink: '/register' });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err.message);
      res.send('Error during registration');
    } else {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
        if (err) {
          console.error(err.message);
          res.send('Error during registration');
        } else {
          res.redirect('/login');
        }
      });
    }
  });
});

app.get('/home', (req, res) => {
  if (req.session.userId) {
    res.render('home', { username: req.session.username, realLink: '/home' });
  } else {
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err.message);
      res.send('Error during logout');
    } else {
      res.redirect('/login');
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
