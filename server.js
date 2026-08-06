// server.js — backend du scan d'exposition monanonymat.fr
//
// Sources interrogées :
//  - Staan (Qwant / Ecosia) — index de recherche européen, self-service depuis juin 2026
//    https://staan.ai — 1€/1000 requêtes, 1000 gratuites/mois.
//    Endpoint confirmé via docs.staan.ai : POST https://api.staan.ai/v2/search/web,
//    body { q, market }, header Authorization: Bearer <clé>.
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
// Render est derrière un proxy inverse — sans ce réglage, express-rate-limit
// ne peut pas identifier correctement chaque visiteur via X-Forwarded-For.
app.set('trust proxy', 1);
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
  if (!STAAN_API_KEY) { console.warn('STAAN_API_KEY absente — source Staan ignorée'); return { hits: [], status: 'no_key' }; }
  try {
    const res = await fetch('https://api.staan.ai/v2/search/web', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${STAAN_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ q: name, market: 'fr-fr' }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.warn(`Staan a répondu ${res.status} : ${body.slice(0, 300)}`);
      return { hits: [], status: 'error' };
    }
    const data = await res.json();
    const hits = data.web?.results || data.results || data.hits || data.items || [];
    if (hits.length === 0) console.warn('Staan : réponse OK mais 0 résultat extrait — forme de réponse à vérifier :', JSON.stringify(data).slice(0, 300));
    return {
      hits: hits.map((r) => ({ title: r.title, url: r.url, snippet: r.snippet || r.description || '', source: 'Staan' })),
      status: 'ok',
    };
  } catch (err) {
    console.warn('Staan indisponible :', err.message);
    return { hits: [], status: 'error' };
  }
}

async function callBrave(name) {
  if (!BRAVE_API_KEY) { console.warn('BRAVE_API_KEY absente — source Brave ignorée'); return { hits: [], status: 'no_key' }; }
  try {
    const url = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(name)}&count=20`;
    const res = await fetch(url, {
      headers: { Accept: 'application/json', 'X-Subscription-Token': BRAVE_API_KEY },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.warn(`Brave a répondu ${res.status} : ${body.slice(0, 300)}`);
      return { hits: [], status: 'error' };
    }
    const data = await res.json();
    const hits = data.web?.results || [];
    if (hits.length === 0) console.warn('Brave : réponse OK mais 0 résultat extrait — forme de réponse à vérifier :', JSON.stringify(data).slice(0, 300));
    return {
      hits: hits.map((r) => ({ title: r.title, url: r.url, snippet: r.description || '', source: 'Brave' })),
      status: 'ok',
    };
  } catch (err) {
    console.warn('Brave indisponible :', err.message);
    return { hits: [], status: 'error' };
  }
}

// SerpApi (serpapi.com) — service commercial qui interroge Google et renvoie le
// résultat en JSON. Requête en GET, clé passée en paramètre d'URL (pas en en-tête),
// résultats sous "organic_results". Confirmé via leur documentation officielle et
// plusieurs intégrations tierces indépendantes.
const SERPAPI_API_KEY = process.env.SERPAPI_API_KEY || process.env.SERPER_API_KEY; // compat avec l'ancien nom de variable

async function callSerpApi(name) {
  if (!SERPAPI_API_KEY) { console.warn('SERPAPI_API_KEY absente — source Google (via SerpApi) ignorée'); return { hits: [], status: 'no_key' }; }
  try {
    const params = new URLSearchParams({
      engine: 'google', q: name, api_key: SERPAPI_API_KEY, hl: 'fr', gl: 'fr',
    });
    const res = await fetch(`https://serpapi.com/search.json?${params.toString()}`);
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.warn(`SerpApi a répondu ${res.status} : ${body.slice(0, 300)}`);
      return { hits: [], status: 'error' };
    }
    const data = await res.json();
    const hits = data.organic_results || [];
    if (hits.length === 0) console.warn('SerpApi : réponse OK mais 0 résultat extrait — forme de réponse à vérifier :', JSON.stringify(data).slice(0, 300));
    return {
      hits: hits.map((r) => ({ title: r.title, url: r.link, snippet: r.snippet || '', source: 'Google' })),
      status: 'ok',
    };
  } catch (err) {
    console.warn('SerpApi indisponible :', err.message);
    return { hits: [], status: 'error' };
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
// Score pondéré par confiance, pensé pour ne jamais exagérer : beaucoup de
// contenu neutre (profils publics, annuaires...) ne doit PAS, à lui seul,
// faire croire à un risque élevé, et un résultat "confiance moyenne" pèse
// moins qu'un résultat "confiance haute" — pour rester prudent plutôt que de
// traiter un indice incertain comme une certitude.
function computeScore(items) {
  let weightedSensitive = 0;
  let weightedNonSensitive = 0;
  items.forEach((i) => {
    const weight = i.confidence === 'high' ? 1 : 0.6;
    if (i.sensitive) weightedSensitive += weight;
    else weightedNonSensitive += weight;
  });
  const base = Math.min(45, weightedNonSensitive * 5); // plafonné : jamais "élevé" à lui seul
  const sensitiveBonus = weightedSensitive * 22;
  return Math.min(100, Math.round(base + sensitiveBonus));
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

// Normalise (accents retirés, minuscules) pour ne pas rater une correspondance
// à cause d'un simple é/e, tout en restant strict sur le fond.
function normalize(str) {
  return (str || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

// Niveau de confiance, en trois échelons plutôt qu'un simple oui/non :
//  - 'high'   : la phrase (quasi) exacte apparaît telle quelle, ou les mots du
//               nom sont collés les uns aux autres (< 25 caractères d'écart)
//  - 'medium' : tous les mots du nom sont présents mais plus espacés dans le
//               texte (jusqu'à 60 caractères) — probable mais moins certain
//  - 'none'   : rejeté (un mot manque, ou les mots sont trop loin les uns des
//               autres pour qu'on soit sûr qu'ils parlent de la même personne)
function relevance(item, name) {
  const text = normalize(`${item.title || ''} ${item.snippet || ''}`);
  const normName = normalize(name);
  const words = normName.split(/\s+/).filter((w) => w.length > 1);
  if (words.length === 0) return 'none';
  if (!words.every((w) => text.includes(w))) return 'none';
  if (text.includes(normName)) return 'high'; // phrase exacte telle quelle
  if (words.length === 1) return 'medium';
  const positions = words.map((w) => text.indexOf(w));
  const spread = Math.max(...positions) - Math.min(...positions);
  if (spread <= 25) return 'high';
  if (spread <= 60) return 'medium';
  return 'none';
}

// Logique de scan partagée — appelée par /api/scan, qui renvoie directement le rapport
// complet, avec les vraies descriptions).
async function performScan(name) {
  const [staan, brave, serper] = await Promise.all([callStaan(name), callBrave(name), callSerpApi(name)]);
  const merged = dedupe([...staan.hits, ...brave.hits, ...serper.hits])
    .map((r) => ({ ...r, confidence: relevance(r, name) }))
    .filter((r) => r.confidence !== 'none');
  const partial = staan.status !== 'ok' || brave.status !== 'ok' || serper.status !== 'ok';
  const hardStop = hasHardStopSignal(merged);
  const classified = classify(merged);
  const score = computeScore(classified);
  return {
    classified, score, partial, hardStop,
    coverage: { staan: staan.status, brave: brave.status, google: serper.status },
  };
}

app.post('/api/scan', async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name || name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: 'Nom invalide' });
  }

  const { classified, score, partial, hardStop, coverage } = await performScan(name);

  if (hardStop) {
    // Aucun rapport n'est construit dans ce cas : redirection uniquement.
    return res.json({
      hardStop: true,
      redirectTo: '/urgence',
      message: 'Ce cas nécessite une prise en charge spécialisée. Voir le volet urgence.',
    });
  }

  stats.scanCount += 1;
  stats.scoreSum += score;

  // Rapport complet renvoyé directement — le scan est gratuit, pas de raison
  // de garder les vraies descriptions derrière un email. Une seule requête
  // aux sources par scan (avant, une deuxième requête relançait tout une
  // fois), ce qui économise aussi le quota gratuit de Staan/Brave/SerpApi.
  const results = classified.map((r) => ({
    type: guessType(r.url),
    tag: guessSource(r.url),
    year: '—',
    sensitive: r.sensitive,
    confidence: r.confidence,
    full: r.snippet || r.title || 'Contenu trouvé, description non disponible.',
  }));

  res.json({ score, results, partial, coverage });
});

// --- Paiement (Stripe Checkout) ---
// Les prix sont définis ICI, côté serveur, jamais envoyés par le client — sinon
// n'importe qui pourrait modifier le montant avant paiement en trafiquant la requête.
const Stripe = require('stripe');
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://monanonymat.fr';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const OFFERS = {
  ponctuelle: { name: 'Suppression ponctuelle', amount: 14900, mode: 'payment' },
  veille: { name: 'Veille & Protection (mensuel)', amount: 1900, mode: 'subscription' },
  premium: { name: 'Accompagnement Premium', amount: 34900, mode: 'payment' },
};

app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement non configuré (STRIPE_SECRET_KEY absente)' });
  const { tier, ref } = req.body || {};
  const offer = OFFERS[tier];
  if (!offer) return res.status(400).json({ error: 'Offre inconnue' });

  try {
    const priceData = {
      currency: 'eur',
      product_data: { name: offer.name },
      unit_amount: offer.amount,
    };
    if (offer.mode === 'subscription') priceData.recurring = { interval: 'month' };

    const session = await stripe.checkout.sessions.create({
      mode: offer.mode,
      payment_method_types: ['card'],
      line_items: [{ price_data: priceData, quantity: 1 }],
      // Code de parrainage/apporteur d'affaires rattaché ici, au vrai moment où
      // une commission se déclenche (achat effectif) — voir affiliation/README.md.
      metadata: ref ? { ref } : undefined,
      success_url: `${FRONTEND_URL}?paiement=succes`,
      cancel_url: `${FRONTEND_URL}?paiement=annule`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.warn('Stripe indisponible :', err.message);
    res.status(500).json({ error: 'Impossible de créer la session de paiement' });
  }
});

// TODO avant prod : ajouter un endpoint webhook Stripe (/api/stripe-webhook) qui
// écoute l'événement checkout.session.completed pour confirmer le paiement côté
// serveur et déclencher la création réelle du dossier — ne jamais se fier
// uniquement à la redirection success_url, qui peut être atteinte sans paiement réel.

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`monanonymat backend sur :${PORT}`));
