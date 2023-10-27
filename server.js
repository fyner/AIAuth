﻿const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./database.js');
const path = require('path');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  console.log('GET /');
  res.render('index');
});

app.get('/login', (req, res) => {
  console.log('GET /login');
  res.render('login');
});

app.get('/register', (req, res) => {
  console.log('GET /register');
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /register', { username, password });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
      if (err) {
        console.error('Error registering new user:', err);
        res.send('Error registering new user');
      } else {
        console.log('User registered:', username);
        res.redirect('/login');
      }
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    res.send('Error registering new user');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /login', { username, password });

  db.get('SELECT id, username, password FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error('Error logging in:', err);
      res.send('Error logging in');
    } else if (!row) {
      console.log('User not found:', username);
      res.send('User not found');
    } else {
      const validPassword = await bcrypt.compare(password, row.password);
      if (validPassword) {
        req.session.loggedin = true;
        req.session.username = username;
        console.log('Login successful:', username);
        res.redirect('/home');
      } else {
        console.log('Incorrect password:', username);
        res.send('Incorrect password');
      }
    }
  });
});

app.get('/home', (req, res) => {
  console.log('GET /home');
  if (req.session.loggedin) {
    res.render('home', { username: req.session.username });
  } else {
    res.send('Please login to view this page!');
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
