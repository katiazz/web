const mysql = require('mysql2');

const db = mysql.createConnection({
  host: '127.0.0.1',
  user: 'root',        // usuario de MySQL
  password: 'itson', // contraseña de MySQL
  database: 'encryption_app'
});

db.connect(err => {
  if (err) {
    console.error('Error al conectar a MySQL:', err);
    return;
  }
  console.log('Conectado a MySQL');
});

module.exports = db;
