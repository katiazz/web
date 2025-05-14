const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const db = require('./database/db');
const helmet = require('helmet');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const PORT = 3004;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware de seguridad
app.use(helmet());  // Protege las cabeceras HTTP
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 30, httpOnly: true, secure: process.env.NODE_ENV === 'production' }
}));

// Middleware para cerrar sesión por inactividad (10 minutos)
app.use((req, res, next) => {
  const maxInactivityTime = 10 * 60 * 1000; // 10 minutos

  if (req.session.user) {
    const now = Date.now();
    if (req.session.lastActivity && now - req.session.lastActivity > maxInactivityTime) {
      req.session.destroy(err => {
        if (err) console.error('Error al destruir la sesión por inactividad:', err);
        return res.redirect('/login');
      });
    } else {
      req.session.lastActivity = now;
      next();
    }
  } else {
    next();
  }
});

// Middleware para evitar que el navegador muestre páginas en caché después de cerrar sesión
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// Limitar intentos de inicio de sesión
//const loginLimiter = rateLimit({
  //windowMs: 5 * 60 * 1000, // 5 minutos
  //max: 5, // Limita a 5 intentos
  //message: "Demasiados intentos de inicio de sesión. Intenta más tarde."
//});
//app.use('/login', loginLimiter);

// AES setup
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}

function decrypt(encryptedText, ivText) {
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivText, 'hex'));
  let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

// Rutas
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err);
      return res.render('login', { error: 'Error interno del servidor' });
    }

    if (results.length === 0) {
      return res.render('login', { error: 'Usuario o contraseña incorrectos' });
    }

    const user = results[0];
    const passwordCorrecta = bcrypt.compareSync(password, user.password);

    if (passwordCorrecta) {
      req.session.regenerate(err => {
        if (err) return res.render('login', { error: 'Error de sesión' });
        req.session.user = user;
        res.redirect('/encrypt');
      });
    } else {
      res.render('login', { error: 'Usuario o contraseña incorrectos' });
    }
  });
});

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed], err => {
    if (err) return res.render('register', { error: 'Usuario ya existe' });
    res.redirect('/login');
  });
});

app.get('/encrypt', requireAuth, (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('encrypt', { result: null });
});

app.post('/encrypt', requireAuth, (req, res) => {
  const { plainText } = req.body;
  const { encrypted, iv } = encrypt(plainText);
  res.render('encrypt', { result: { encrypted, iv } });
});

app.get('/decrypt', requireAuth, (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('decrypt', { result: null, error: null });
});

app.post('/decrypt', requireAuth, (req, res) => {
  const { encryptedText, iv } = req.body;
  try {
    const decrypted = decrypt(encryptedText, iv);
    res.render('decrypt', { result: decrypted, error: null });
  } catch {
    res.render('decrypt', { result: null, error: 'Error al desencriptar' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid'); // Borra la cookie de la sesión
    res.redirect('/login'); // Redirige al login después de cerrar sesión
  });
});


app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

