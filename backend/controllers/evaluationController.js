exports.saisie = (req, res) => {
    if (!req.session.user) {
        return res.redirect('/auth/login');
    }
    if (req.method === 'GET') {
        // Mock données pour le formulaire
        const enseignants = [{ ID_ENS: 'ENS_0001', Nom: 'Diallo' }, { ID_ENS: 'ENS_0002', Nom: 'Koné' }];
        const matieres = [{ ID_MAT: 'MAT_0001', Nom_Matière: 'Maths' }, { ID_MAT: 'MAT_0002', Nom_Matière: 'Physique' }];
        const classes = [{ ID_CLA: 'CLA_0001', Nom_Classe: 'A1' }, { ID_CLA: 'CLA_0002', Nom_Classe: 'A2' }];
        const categories = [{ ID_CAT: 'CAT_0001', Nom_Catégorie: 'Intérêt' }, { ID_CAT: 'CAT_0002', Nom_Catégorie: 'Clarté' }];
        const criteres = [
            { ID_CRT: 'CRT_0001', Nom_Critère: 'Arrive à l’heure', ID_CAT: 'CAT_0001' },
            { ID_CRT: 'CRT_0002', Nom_Critère: 'Explications claires', ID_CAT: 'CAT_0002' }
        ];
        return res.render('evaluation', { user: req.session.user, enseignants, matieres, classes, categories, criteres, message: null });
    }
    // POST : Simuler la sauvegarde
    const { enseignant, matiere, classe, criteres, commentaire } = req.body;
    console.log('Données saisies:', { enseignant, matiere, classe, criteres, commentaire });
    return res.render('evaluation', { user: req.session.user, enseignants: [], matieres: [], classes: [], categories: [], criteres: [], message: 'Évaluation enregistrée (mock)!' });
};