const express = require('express');
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
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
    if (err) {
      res.send('Error registering new user');
    } else {
      res.redirect('/login');
    }
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, username, password FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      res.send('Error logging in');
    } else if (!row) {
      res.send('User not found');
    } else {
      const validPassword = await bcrypt.compare(password, row.password);
      if (validPassword) {
        req.session.loggedin = true;
        req.session.username = username;
        res.redirect('/home');
      } else {
        res.send('Incorrect password');
      }
    }
  });
});

app.get('/home', (req, res) => {
  if (req.session.loggedin) {
    res.send(`Welcome back, ${req.session.username}!`);
  } else {
    res.send('Please login to view this page!');
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
