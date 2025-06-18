const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Es1@2002',
    database: 'esi_evaluation', // Vérifiez que c'est la bonne base de données
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});