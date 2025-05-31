const express = require('express');
const router = express.Router();

router.get('/login', (req, res) => {
    res.render('login', { title: 'Connexion', error: null });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Mock : Simuler un utilisateur
    const mockUser = { id: 'USR_0001', role: 'Admin', username: 'admin', password: '1234' };
    if (username === mockUser.username && password === mockUser.password) {
        req.session.user = { id: mockUser.id, role: mockUser.role };
        return res.redirect('/dashboard');
    }
    res.render('login', { title: 'Connexion', error: 'Identifiants incorrects' });
});

router.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/auth/login'));
});

module.exports = router;