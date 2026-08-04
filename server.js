// server.js — backend du scan d'exposition monanonymat.fr
//
// Sources interrogées :
//  - Staan (Qwant / Ecosia) — index de recherche européen, self-service depuis juin 2026
//    https://staan.ai — 1€/1000 requêtes, 1000 gratuites/mois.
//    ⚠️ Le format exact de requête/réponse ci-dessous est une hypothèse raisonnable,
//    pas une copie de la doc officielle (API trop récente pour que je l'aie en mémoire
//    de façon fiable). Vérifie le contrat exact sur staan.ai avant de déployer, et
//    ajuste callStaan() en conséquence.
//  - Brave Search API — index indépendant. https://brave.com/search/api
//    (le free tier a été supprimé en février 2026 — prévoir un budget, environ
//    3 à 5€ pour 1000 requêtes selon l'endpoint)
//
// Ce que ce serveur NE fait PAS et ne doit JAMAIS faire :
//  - Il ne traite, ne classe ni ne stocke jamais de contenu impliquant potentiellement
//    des mineurs. Si un signal de ce type apparaît dans les résultats, on arrête tout
//    et on redirige vers le volet "urgence" (organismes officiels) — jamais vers un
//    rapport généré automatiquement ici. Voir hasHardStopSignal().

const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Anti-abus basique : limite les recherches par IP. Indispensable car l'outil peut
// être utilisé pour chercher quelqu'un d'autre — la case de consentement côté front
// est un premier filtre déclaratif, pas une vraie vérification d'identité.
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
app.use('/api/scan', scanLimiter);

// --- Compteur réel, pas un chiffre inventé pour la preuve sociale ---
// ⚠️ En mémoire : remis à zéro à chaque redémarrage du serveur. Sur le plan
// gratuit Render, le service s'endort et redémarre après inactivité — ce
// compteur repart donc de zéro à ce moment-là. C'est honnête tant que peu de
// volume passe, mais il faudra le persister (fichier, ou une vraie base) dès
// que ce chiffre doit rester fiable sur la durée.
const stats = { scanCount: 0, scoreSum: 0, since: new Date().toISOString() };

app.get('/api/stats', (req, res) => {
  res.json({
    scanCount: stats.scanCount,
    averageScore: stats.scanCount > 0 ? Math.round(stats.scoreSum / stats.scanCount) : null,
    since: stats.since,
  });
});

const STAAN_API_KEY = process.env.STAAN_API_KEY;
const BRAVE_API_KEY = process.env.BRAVE_API_KEY;

// Premier tri "sensible / pas sensible" par mots-clés. À affiner sérieusement
// (voire remplacer par un vrai service de classification) avant toute mise en
// production — ceci est un point de départ, pas un système de modération fiable.
const SENSITIVE_HINTS = [
  'nude', 'intime', 'sextape', 'leak', 'fuite', 'condamn', 'procès',
  'plainte', 'agression', 'délit', 'crime', 'arrestation',
];

// Garde-fou grossier : si ces termes apparaissent, on arrête le traitement
// automatique. Ce n'est PAS un système de détection de contenu impliquant des
// mineurs — un tel système ne doit reposer que sur une infrastructure officielle
// de hachage (NCMEC/Take It Down, PHAROS...), jamais sur un classifieur maison.
const HARD_STOP_HINTS = ['mineur', 'enfant', 'collégien', 'lycéen', ' ado '];

async function callStaan(name) {
  if (!STAAN_API_KEY) return [];
  try {
    const res = await fetch('https://api.staan.ai/v1/search', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${STAAN_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query: `"${name}"`, count: 10 }),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.results || []).map((r) => ({
      title: r.title,
      url: r.url,
      snippet: r.snippet || r.description || '',
      source: 'Staan',
    }));
  } catch (err) {
    console.warn('Staan indisponible :', err.message);
    return [];
  }
}

async function callBrave(name) {
  if (!BRAVE_API_KEY) return [];
  try {
    const url = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(`"${name}"`)}&count=10`;
    const res = await fetch(url, {
      headers: { Accept: 'application/json', 'X-Subscription-Token': BRAVE_API_KEY },
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.web?.results || []).map((r) => ({
      title: r.title,
      url: r.url,
      snippet: r.description || '',
      source: 'Brave',
    }));
  } catch (err) {
    console.warn('Brave indisponible :', err.message);
    return [];
  }
}

function guessType(url = '') {
  const u = url.toLowerCase();
  if (/facebook|instagram|tiktok|linkedin|x\.com|twitter/.test(u)) return 'Réseau social';
  if (/lemonde|lefigaro|actu|presse|news|liberation|ouest-france/.test(u)) return 'Article';
  if (/youtube|dailymotion|vimeo/.test(u)) return 'Vidéo';
  if (/pagesjaunes|118|annuaire/.test(u)) return 'Annuaire';
  if (/forum|discussion|reddit/.test(u)) return 'Forum';
  return 'Page web';
}
function guessSource(url = '') {
  try { return new URL(url).hostname.replace('www.', ''); } catch { return 'source inconnue'; }
}

function classify(items) {
  return items.map((item) => {
    const text = `${item.title} ${item.snippet}`.toLowerCase();
    const sensitive = SENSITIVE_HINTS.some((k) => text.includes(k));
    return { ...item, sensitive };
  });
}
function hasHardStopSignal(items) {
  return items.some((item) => {
    const text = `${item.title} ${item.snippet}`.toLowerCase();
    return HARD_STOP_HINTS.some((k) => text.includes(k));
  });
}
function computeScore(items) {
  const base = items.length * 6;
  const sensitiveBonus = items.filter((i) => i.sensitive).length * 20;
  return Math.min(100, base + sensitiveBonus);
}
function dedupe(items) {
  const seen = new Set();
  return items.filter((i) => {
    const key = (i.url || '').split('?')[0];
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

app.post('/api/scan', async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name || name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: 'Nom invalide' });
  }

  const [staanResults, braveResults] = await Promise.all([callStaan(name), callBrave(name)]);
  const merged = dedupe([...staanResults, ...braveResults]);

  if (hasHardStopSignal(merged)) {
    // Aucun rapport n'est construit dans ce cas : redirection uniquement.
    return res.json({
      hardStop: true,
      redirectTo: '/urgence',
      message: 'Ce cas nécessite une prise en charge spécialisée. Voir le volet urgence.',
    });
  }

  const classified = classify(merged);
  const score = computeScore(classified);

  stats.scanCount += 1;
  stats.scoreSum += score;

  // Version "teaser" : pas de détail exploitable avant email + consentement.
  const teaserResults = classified.slice(0, 6).map((r) => ({
    type: guessType(r.url),
    tag: guessSource(r.url),
    year: '—',
    sensitive: r.sensitive,
  }));

  // Rien n'est stocké ici tant que /api/unlock n'a pas été appelé — rétention minimale.
  res.json({ score, results: teaserResults });
});

app.post('/api/unlock', async (req, res) => {
  const { name, email, consent, ref } = req.body || {};
  if (!consent) return res.status(400).json({ error: 'Consentement requis' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Email invalide' });
  }

  // Tracking affiliation/apporteur d'affaires : le code de parrainage (ex. "mounir",
  // ou le code d'un cabinet d'avocats partenaire) est rattaché au lead ici. À stocker
  // avec le lead en base pour le calcul des commissions — voir affiliation/README.md.
  if (ref) console.log(`Lead ${email} rattaché au code de parrainage : ${ref}`);

  // TODO avant prod :
  //  - stocker le lead (nom, email, score, date, consentement) dans une base
  //    hébergée en Europe (Scaleway, OVHcloud...) avec une politique de
  //    rétention courte et documentée (registre de traitement RGPD)
  //  - déclencher l'envoi du rapport par email via un prestataire européen
  //    (ex. Brevo) plutôt qu'un service US, pour rester cohérent avec le
  //    positionnement "souverain"
  //  - relancer le scan complet ici (ou réutiliser un cache court-terme lié
  //    à la session) pour renvoyer les descriptions détaillées

  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`monanonymat backend sur :${PORT}`));
