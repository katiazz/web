const mysql = require('mysql2');
require('dotenv').config(); 

const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,        
  user: process.env.MYSQL_USER,        
  password: process.env.MYSQL_PASSWORD, 
  database: process.env.MYSQL_DB,      
  port: process.env.MYSQL_PORT || 3306 
});

db.connect(err => {
  if (err) {
    console.error('Error al conectar a MySQL:', err);
    return;
  }
  console.log('Conectado a MySQL');
});

module.exports = db;

