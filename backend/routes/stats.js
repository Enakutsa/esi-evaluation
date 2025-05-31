const express = require('express');
const router = express.Router();
const { db } = require('../app');

router.get('/stats', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { id_enseignant, id_classe, date_debut, date_fin } = req.query;

    let query = `
        SELECT e.ID_ENS, e.ID_CLA, AVG(n.Note) as moyenne, c.Nom as critere
        FROM Évaluation e
        JOIN Noter n ON e.ID_EVA = n.ID_EVA
        JOIN Critère c ON n.ID_CRT = c.ID_CRT
        WHERE 1=1
    `;
    const params = [];

    if (id_enseignant) {
        query += ' AND e.ID_ENS = ?';
        params.push(id_enseignant);
    }
    if (id_classe) {
        query += ' AND e.ID_CLA = ?';
        params.push(id_classe);
    }
    if (date_debut && date_fin) {
        query += ' AND e.Date_Évaluation BETWEEN ? AND ?';
        params.push(date_debut, date_fin);
    }
    query += ' GROUP BY e.ID_ENS, e.ID_CLA, c.Nom';

    try {
        const [rows] = await db.execute(query, params);
        res.render('stats', { user: req.session.user, stats: rows, filters: req.query });
    } catch (err) {
        console.error('Erreur stats:', err);
        res.render('stats', { user: req.session.user, stats: [], error: 'Erreur lors du chargement' });
    }
});

module.exports = router;