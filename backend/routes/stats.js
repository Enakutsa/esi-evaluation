const express = require('express');
const router = express.Router();

router.get('/stats', async (req, res) => {
    try {
        const [evalCount] = await req.db.execute('SELECT COUNT(*) as count FROM evaluation');
        const [teacherCount] = await req.db.execute('SELECT COUNT(DISTINCT ev.id_ens) as count FROM evaluation ev');
        const [matiereCount] = await req.db.execute('SELECT COUNT(*) as count FROM matiere');
        const [avgScore] = await req.db.execute(`
            SELECT AVG(n.note) as avg_score FROM evaluation e
            JOIN noter n ON e.id_eva = n.id_eva
        `);
        const avg = avgScore[0].avg_score || 0;
        res.json({
            evaluations: evalCount[0].count,
            teachers: teacherCount[0].count,
            matieres: matiereCount[0].count,
            satisfaction: (avg / 20 * 100).toFixed(0) + '%'
        });
    } catch (err) {
        console.error('Erreur /api/stats:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Ajoute les autres endpoints (scores-by-criteria, rankings, etc.) en remplaçant db par req.db

module.exports = router;