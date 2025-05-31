const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require('dotenv').config();

async function hashPassword() {
    const db = await mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'esi_evaluation'
    });

    const username = 'test'; // Remplace par le nom de ton utilisateur
    const password = 'pass'; // Remplace par le mot de passe en clair
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute('UPDATE Utilisateur SET Mot_de_Passe = ? WHERE Nom = ?', [hashedPassword, username]);
    console.log(`Mot de passe hashé pour ${username}: ${hashedPassword}`);
    process.exit();
}

hashPassword().catch(err => console.error(err));