const { DB_HOST, DB_USER, DB_PASS, DB_NAME } = process.env;
var mysql = require('mysql');

var conn = mysql.createConnection({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASS,
    database: DB_NAME
});

conn.connect(function(err) {
    if (err) throw err;
    console.log(DB_NAME + " Database Connected!");
});

module.exports = conn;