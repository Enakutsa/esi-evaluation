const express = require('express');
const path = require('path');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://www.gstatic.com https://cdn.tailwindcss.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net"
    );
    next();
});

// Configuration de la session
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret',
    resave: false,
    saveUninitialized: false
}));

// Connexion à la base de données
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'esi_evaluation'
});

db.getConnection()
    .then(() => console.log('Connecté à MySQL'))
    .catch(err => console.error('Erreur DB:', err));

// Swagger configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'ESI Évaluation API',
            version: '1.0.0',
            description: 'API pour l\'application d\'évaluation des enseignants de l\'ESI',
        },
        servers: [
            { url: 'https://esi-evaluation.vercel.app', description: 'Serveur de production' },
            { url: 'http://localhost:3000', description: 'Serveur local' },
        ],
    },
    apis: ['./app.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Nouvelle route pour télécharger la spécification OpenAPI
app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Disposition', 'attachment; filename=esi-evaluation-api.json');
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerDocs);
});

// Middleware de validation pour les évaluations
const validateEvaluation = (req, res, next) => {
    const { enseignant, matiere, classe } = req.body;
    if (!enseignant || !matiere || !classe) {
        return res.status(400).json({ success: false, message: 'Tous les champs (enseignant, matière, classe) sont obligatoires' });
    }
    next();
};

// Passer db aux routes API
app.use('/api', (req, res, next) => {
    req.db = db;
    next();
}, require('./routes/stats'));

// Page d'accueil
app.get('/', (req, res) => {
    res.render('index');
});

// Route pour l'inscription
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { nom, prenom, email, password } = req.body;
    if (!nom || !prenom || !email || !password) {
        return res.status(400).send('Tous les champs sont obligatoires');
    }

    try {
        const code_etudiant = `ESI${Math.floor(100000 + Math.random() * 900000)}`;
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO utilisateurs (nom, prenom, email, code_etudiant, mot_de_passe_hash, profil) VALUES (?, ?, ?, ?, ?, ?)',
            [nom, prenom, email, code_etudiant, hashedPassword, 'Étudiant']
        );
        res.redirect('/');
    } catch (err) {
        console.error('Erreur inscription:', err);
        res.status(500).send('Erreur serveur');
    }
});

// Route pour la page de connexion
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Tentative de login avec email:', email); // Débogage
    if (!email || !password) {
        return res.status(400).send('Email et mot de passe requis');
    }

    try {
        const [users] = await db.execute('SELECT * FROM utilisateurs WHERE email = ?', [email]);
        if (users.length === 0) {
            console.log('Utilisateur non trouvé pour email:', email); // Débogage
            return res.status(401).send('Utilisateur non trouvé');
        }

        const user = users[0];
        console.log('Utilisateur trouvé - Profil:', user.profil); // Débogage
        const match = await bcrypt.compare(password, user.mot_de_passe_hash);
        console.log('Correspondance avec le mot de passe:', match); // Débogage
        if (match) {
            req.session.user = { id: user.id, profil: user.profil, email: user.email };
            console.log('Session créée pour profil:', user.profil); // Débogage
            if (user.profil === 'Direction') {
                return res.redirect('/direction');
            } else if (user.profil === 'Admin') {
                return res.redirect('/dashboard');
            } else {
                return res.redirect('/choose-role');
            }
        } else {
            res.status(401).send('Mot de passe incorrect');
        }
    } catch (err) {
        console.error('Erreur login:', err);
        res.status(500).send('Erreur serveur');
    }
});

// Route pour la page de choix de rôle
app.get('/choose-role', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('choose-role', { user: req.session.user });
});

// Route pour la page d'évaluation (Étudiant)
app.get('/evaluation', async (req, res) => {
    try {
        const [enseignants] = await db.execute('SELECT * FROM enseignant');
        const [matieres] = await db.execute('SELECT * FROM matiere');
        const [classes] = await db.execute('SELECT * FROM classe');
        res.render('evaluation', { enseignants, matieres, classes });
    } catch (err) {
        console.error('Erreur chargement évaluation:', err);
        res.status(500).send('Erreur');
    }
});

app.post('/evaluation', validateEvaluation, async (req, res) => {
    const { enseignant, matiere, classe, ...criteria } = req.body;
    const commentaire = req.body.commentaire || '';
    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction();

        const [enseignantCheck] = await connection.execute('SELECT id_ens FROM enseignant WHERE id_ens = ?', [enseignant]);
        const [matiereCheck] = await connection.execute('SELECT id_mat FROM matiere WHERE id_mat = ?', [matiere]);
        const [classeCheck] = await connection.execute('SELECT id_cla FROM classe WHERE id_cla = ?', [classe]);

        if (enseignantCheck.length === 0 || matiereCheck.length === 0 || classeCheck.length === 0) {
            throw new Error('Une des clés étrangères est invalide');
        }

        const [result] = await connection.execute(
            'INSERT INTO evaluation (date_evaluation, id_ens, id_mat, id_cla, id_usr) VALUES (?, ?, ?, ?, ?)',
            [new Date().toISOString().split('T')[0], enseignant, matiere, classe, req.session.user.id]
        );
        const evaluationId = result.insertId;

        const criteriaMap = {
            section1_q1: 'CRT_001', section1_q2: 'CRT_002', section1_q3: 'CRT_003', section1_q4: 'CRT_004',
            section1_q5: 'CRT_005', section1_q6: 'CRT_006', section1_q7: 'CRT_007', section1_q8: 'CRT_008',
            section2_q1: 'CRT_009', section2_q2: 'CRT_010', section2_q3: 'CRT_011', section2_q4: 'CRT_012',
            section3_q1: 'CRT_013', section3_q2: 'CRT_014', section3_q3: 'CRT_015', section3_q4: 'CRT_016',
            section3_q5: 'CRT_017', section3_q6: 'CRT_018', section3_q7: 'CRT_019', section3_q8: 'CRT_020',
            section4_q1: 'CRT_021', section4_q2: 'CRT_022', section4_q3: 'CRT_023', section4_q4: 'CRT_024',
            section4_q5: 'CRT_025', section4_q6: 'CRT_026',
            section5_q1: 'CRT_027', section5_q2: 'CRT_028', section5_q3: 'CRT_029', section5_q4: 'CRT_030',
            section5_q5: 'CRT_031', section5_q6: 'CRT_032', section5_q7: 'CRT_033',
            section6_q1: 'CRT_034', section6_q2: 'CRT_035', section6_q3: 'CRT_036', section6_q4: 'CRT_037',
            section6_q5: 'CRT_038', section6_q6: 'CRT_039', section6_q7: 'CRT_040',
            section7_q1: 'CRT_041', section7_q2: 'CRT_042', section7_q3: 'CRT_043', section7_q4: 'CRT_044'
        };

        for (const [key, value] of Object.entries(criteria)) {
            const critereId = criteriaMap[key];
            const note = parseInt(value);
            if (critereId && !isNaN(note)) {
                await connection.execute(
                    'INSERT INTO noter (id_eva, id_crt, note) VALUES (?, ?, ?)',
                    [evaluationId, critereId, note]
                );
            }
        }

        if (commentaire && commentaire.trim()) {
            await connection.execute(
                'INSERT INTO commentaire (texte, date_commentaire, id_eva) VALUES (?, ?, ?)',
                [commentaire, new Date().toISOString().split('T')[0], evaluationId]
            );
        }

        await connection.commit();
        connection.release();
        res.json({ success: true, message: 'Évaluation enregistrée !' });
    } catch (err) {
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        console.error('Erreur évaluation:', err);
        res.status(500).json({ success: false, message: `Erreur: ${err.message || 'Erreur inconnue'}` });
    }
});

// Route pour la connexion Admin
app.get('/admin-login', (req, res) => {
    if (req.session.user && req.session.user.profil === 'Admin') {
        return res.redirect('/dashboard');
    }
    res.render('admin-login');
});

app.post('/admin-login', async (req, res) => {
    const { password } = req.body;
    console.log('Mot de passe saisi (Admin):', password); // Débogage
    const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '$2b$10$69XqJYjhQv4P/31YLW84e.hKkMV..5po.QaFwXo7KUN42r4VxxC8O';
    try {
        const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        console.log('Correspondance (Admin):', match); // Débogage
        if (match) {
            req.session.user = { profil: 'Admin' };
            res.redirect('/dashboard');
        } else {
            res.status(401).send('Mot de passe admin incorrect');
        }
    } catch (err) {
        console.error('Erreur admin login:', err);
        res.status(500).send('Erreur serveur');
    }
});

// Route pour le tableau de bord (Admin)
app.get('/dashboard', (req, res) => {
    if (!req.session.user || req.session.user.profil !== 'Admin') {
        return res.redirect('/admin-login');
    }
    res.render('dashboard');
});

// Déconnexion
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Erreur lors de la déconnexion:', err);
            return res.status(500).send('Erreur lors de la déconnexion');
        }
        res.redirect('/');
    });
});

// Page pour ajouter des données (protégée pour admin)
app.get('/add-data', (req, res) => {
    if (!req.session.user || req.session.user.profil !== 'Admin') {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'add-data.html'));
});

// Endpoint pour les statistiques
app.get('/api/stats', async (req, res) => {
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

// Endpoint pour les scores moyens par critère
app.get('/api/scores-by-criteria', async (req, res) => {
    try {
        const scores = [
            { name: 'Intérêt pour le cours', range: 'CRT_001-CRT_008' },
            { name: 'Clarté du cours', range: 'CRT_009-CRT_012' },
            { name: 'Relations avec les apprenants', range: 'CRT_013-CRT_020' },
            { name: 'Organisation du cours', range: 'CRT_021-CRT_026' },
            { name: 'Incitation à la participation', range: 'CRT_027-CRT_033' },
            { name: 'Explications', range: 'CRT_034-CRT_040' },
            { name: 'Attitude des apprenants', range: 'CRT_041-CRT_044' }
        ];

        const result = {};
        for (const section of scores) {
            const [rows] = await req.db.execute(`
                SELECT AVG(n.note) as avg_score
                FROM noter n
                WHERE n.id_crt BETWEEN ? AND ?
            `, [section.range.split('-')[0], section.range.split('-')[1]]);
            result[section.name] = rows[0].avg_score || 0;
        }
        res.json(result);
    } catch (err) {
        console.error('Erreur /api/scores-by-criteria:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Endpoint pour le classement des enseignants
app.get('/api/rankings', async (req, res) => {
    try {
        const [rows] = await req.db.execute(`
            SELECT e.id_ens, e.nom, e.prenom,
                   (SELECT m.nom_matiere FROM matiere m JOIN evaluation ev2 ON m.id_mat = ev2.id_mat WHERE ev2.id_ens = e.id_ens ORDER BY ev2.date_evaluation DESC LIMIT 1) AS nom_matiere,
                   (SELECT c.nom_classe FROM classe c JOIN evaluation ev3 ON c.id_cla = ev3.id_cla WHERE ev3.id_ens = e.id_ens ORDER BY ev3.date_evaluation DESC LIMIT 1) AS nom_classe,
                   AVG(n.note) AS score_moyen,
                   COUNT(DISTINCT ev.id_eva) AS eval_count
            FROM enseignant e
            JOIN evaluation ev ON e.id_ens = ev.id_ens
            JOIN noter n ON ev.id_eva = n.id_eva
            GROUP BY e.id_ens, e.nom, e.prenom
            ORDER BY score_moyen DESC
            LIMIT 5
        `);
        res.json(rows);
    } catch (err) {
        console.error('Erreur /api/rankings:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Endpoint pour les rapports
app.get('/api/reports', async (req, res) => {
    try {
        const [totalEvals] = await req.db.execute('SELECT COUNT(*) as count FROM evaluation');
        const total = totalEvals[0].count || 1;
        const [rows] = await req.db.execute(`
            SELECT m.nom_matiere, e.nom, e.prenom,
                   AVG(CASE WHEN n.id_crt LIKE 'CRT_0[2-3][7-8]' THEN n.note ELSE NULL END) AS participation_score,
                   (COUNT(DISTINCT ev.id_eva) / ? * 100) AS interaction_rate,
                   c.nom_classe
            FROM enseignant e
            JOIN evaluation ev ON e.id_ens = ev.id_ens
            JOIN matiere m ON ev.id_mat = m.id_mat
            JOIN classe c ON ev.id_cla = c.id_cla
            JOIN noter n ON ev.id_eva = n.id_eva
            GROUP BY e.id_ens, m.id_mat, c.id_cla
            ORDER BY participation_score DESC
            LIMIT 3
        `, [total]);
        res.json(rows);
    } catch (err) {
        console.error('Erreur /api/reports:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Endpoint pour la liste des enseignants
app.get('/api/teachers', async (req, res) => {
    try {
        const [rows] = await req.db.execute(`
            SELECT e.id_ens, e.nom, e.prenom,
                   GROUP_CONCAT(DISTINCT m.nom_matiere SEPARATOR ', ') AS matieres,
                   GROUP_CONCAT(DISTINCT c.nom_classe SEPARATOR ', ') AS classes,
                   AVG(n.note) AS score_moyen,
                   COUNT(DISTINCT ev.id_eva) AS eval_count
            FROM enseignant e
            JOIN evaluation ev ON e.id_ens = ev.id_ens
            JOIN matiere m ON ev.id_mat = m.id_mat
            JOIN classe c ON ev.id_cla = c.id_cla
            JOIN noter n ON ev.id_eva = n.id_eva
            GROUP BY e.id_ens, e.nom, e.prenom
            ORDER BY score_moyen DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error('Erreur /api/teachers:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Route pour ajouter un enseignant
app.post('/api/add-teacher', async (req, res) => {
    const { nom, prenom } = req.body;
    if (!nom || !prenom) {
        return res.status(400).json({ success: false, message: 'Nom et prénom sont requis' });
    }
    try {
        const [result] = await req.db.execute(
            'INSERT INTO enseignant (id_ens, nom, prenom) VALUES (?, ?, ?)',
            [`ENS_${Date.now()}`, nom, prenom]
        );
        res.json({ success: true, message: 'Enseignant ajouté !' });
    } catch (err) {
        console.error('Erreur ajout enseignant:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Route pour ajouter une matière
app.post('/api/add-matiere', async (req, res) => {
    const { nom_matiere } = req.body;
    if (!nom_matiere) {
        return res.status(400).json({ success: false, message: 'Nom de la matière requis' });
    }
    try {
        const [result] = await req.db.execute(
            'INSERT INTO matiere (id_mat, nom_matiere) VALUES (?, ?)',
            [`MAT_${Date.now()}`, nom_matiere]
        );
        res.json({ success: true, message: 'Matière ajoutée !' });
    } catch (err) {
        console.error('Erreur ajout matière:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Route pour la page Direction
app.get('/direction', (req, res) => {
    if (!req.session.user || req.session.user.profil !== 'Direction') {
        return res.redirect('/login');
    }
    res.render('direction');
});

// Endpoint pour les tendances
app.get('/api/trends', async (req, res) => {
    try {
        const [rows] = await req.db.execute(`
            SELECT DATE_FORMAT(date_evaluation, '%Y-%m') as month, COUNT(*) as count
            FROM evaluation
            GROUP BY DATE_FORMAT(date_evaluation, '%Y-%m')
            ORDER BY month DESC
            LIMIT 6
        `);
        res.json(rows);
    } catch (err) {
        console.error('Erreur /api/trends:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Lancer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur sur http://localhost:${PORT}`));

// Exportation correcte
module.exports = { app, db };