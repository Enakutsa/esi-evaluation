const bcrypt = require('bcrypt');
const password = 'admin123';
const saltRounds = 10;
bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
        console.error('Erreur:', err);
    } else {
        console.log('Hash généré:', hash); // Copie ce hash
    }
});