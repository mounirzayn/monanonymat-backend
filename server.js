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
const helmet = require('helmet');
const { Pool } = require('pg');
require('dotenv').config();

// --- Base de données (PostgreSQL) ---
// Nécessaire pour que la Veille soit un vrai service automatisé : sans
// mémoire durable, impossible de savoir qui est abonné et quel était son
// dernier résultat pour détecter un changement. Render propose une base
// PostgreSQL gratuite sur la même plateforme que ce serveur — DATABASE_URL
// est fournie automatiquement si la base est reliée au même projet Render,
// sinon à copier manuellement depuis le tableau de bord de la base.
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

async function initDb() {
  if (!pool) { console.warn('DATABASE_URL absente — la Veille automatisée ne peut pas fonctionner sans base de données.'); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS veille_subscribers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      active BOOLEAN NOT NULL DEFAULT true,
      is_free_trial BOOLEAN NOT NULL DEFAULT false,
      last_score INTEGER,
      last_sensitive_count INTEGER,
      last_scanned_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Dossiers de suppression — le vrai contenu derrière "on lance les démarches",
  // pas juste une promesse. Chaque contenu signalé au moment du paiement reçoit
  // une vraie demande de suppression pré-rédigée, prête à envoyer.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dossiers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT,
      tier TEXT NOT NULL,
      stripe_session_id TEXT,
      status TEXT NOT NULL DEFAULT 'en_attente_paiement',
      items JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      paid_at TIMESTAMPTZ
    );
  `);
  // Index sur les colonnes filtrées à chaque exécution de la tâche planifiée
  // et par le panneau admin — sans eux, ces requêtes redeviendront lentes dès
  // que le nombre de lignes grandira, alors qu'elles tournent en continu.
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_veille_active ON veille_subscribers (active) WHERE active = true;`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_dossiers_status ON dossiers (status);`);

  // Compteur de scans — une seule ligne, mise à jour à chaque scan. Le
  // "ON CONFLICT DO NOTHING" évite de réinitialiser le compte à chaque
  // redémarrage du serveur si la ligne existe déjà. Départ à 16 pour
  // reprendre le vrai compte déjà réalisé, pas repartir de zéro.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS site_stats (
      id INTEGER PRIMARY KEY DEFAULT 1,
      scan_count INTEGER NOT NULL DEFAULT 0,
      score_sum INTEGER NOT NULL DEFAULT 0,
      since TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`INSERT INTO site_stats (id, scan_count, score_sum) VALUES (1, 16, 0) ON CONFLICT (id) DO NOTHING;`);
  console.log('Base de données prête (table veille_subscribers vérifiée).');
}

const app = express();

// Upload en mémoire uniquement — jamais écrit sur disque, jamais conservé.
// L'image transite vers Hive pour analyse puis est immédiatement oubliée,
// cohérent avec le principe "rien n'est gardé" du reste du site.
const multer = require('multer');
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 }, // 12 Mo max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  },
});
// Render est derrière un proxy inverse — sans ce réglage, express-rate-limit
// ne peut pas identifier correctement chaque visiteur via X-Forwarded-For.
app.set('trust proxy', 1);

// En-têtes de sécurité HTTP standard (X-Content-Type-Options, X-Frame-Options,
// désactivation du X-Powered-By qui révèle la techno utilisée, etc.). CSP
// désactivée ici : cette API ne sert pas de HTML, la CSP se règle plutôt côté
// site statique (voir le fichier _headers de Netlify).
app.use(helmet({ contentSecurityPolicy: false }));

// CORS restreint aux vrais domaines du site — laissé ouvert à tous, n'importe
// quel autre site pourrait appeler notre API et consommer notre quota gratuit
// Staan/Brave/SerpApi sans qu'on le sache. ALLOWED_ORIGINS accepte une liste
// séparée par des virgules (ex. "https://monanonymat.fr,https://www.monanonymat.fr").
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://monanonymat.fr,https://www.monanonymat.fr,https://celadon-peony-3f05ff.netlify.app')
  .split(',').map((s) => s.trim());
app.use(cors({
  origin(origin, callback) {
    // "origin" est absent pour les appels directs (ex. curl, tests serveur à
    // serveur) — on les laisse passer ; le filtrage vise les navigateurs.
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('Origine non autorisée'));
  },
}));
// Le parsing JSON est appliqué route par route (pas globalement) : le webhook
// Stripe plus bas a besoin du corps brut de la requête pour vérifier la
// signature — un parsing JSON global l'en empêcherait.

// Anti-abus basique : limite les recherches par IP. Indispensable car l'outil peut
// être utilisé pour chercher quelqu'un d'autre — la case de consentement côté front
// est un premier filtre déclaratif, pas une vraie vérification d'identité.
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
app.use('/api/scan', scanLimiter);

// Même logique pour le paiement — sans ça, quelqu'un pourrait créer des
// centaines de sessions Stripe par minute (spam, pas une perte d'argent en
// soi puisqu'aucune carte n'est débitée sans action sur la page Stripe, mais
// ça peut faire réagir la protection anti-fraude de Stripe pour rien).
const checkoutLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.use('/api/checkout', checkoutLimiter);
app.use('/api/portal', checkoutLimiter);

// --- Compteur réel, pas un chiffre inventé pour la preuve sociale ---
// Compteur de scans persistant en base de données — contrairement à un
// simple objet en mémoire, il survit aux redémarrages du service (fréquents
// sur le plan gratuit Render après une période d'inactivité). Repli en
// mémoire uniquement si la base n'est pas configurée, pour ne jamais planter.
const memStats = { scanCount: 0, scoreSum: 0, since: new Date().toISOString() };

async function incrementStats(score) {
  if (!pool) { memStats.scanCount += 1; memStats.scoreSum += score; return; }
  try {
    await pool.query(
      `UPDATE site_stats SET scan_count = scan_count + 1, score_sum = score_sum + $1 WHERE id = 1`,
      [score]
    );
  } catch (err) {
    console.warn('Échec de la mise à jour du compteur de scans :', err.message);
  }
}

const statsLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.get('/api/stats', statsLimiter, async (req, res) => {
  if (!pool) {
    return res.json({
      scanCount: memStats.scanCount,
      averageScore: memStats.scanCount > 0 ? Math.round(memStats.scoreSum / memStats.scanCount) : null,
      since: memStats.since,
    });
  }
  try {
    const { rows } = await pool.query(`SELECT scan_count, score_sum, since FROM site_stats WHERE id = 1`);
    const row = rows[0] || { scan_count: 0, score_sum: 0, since: memStats.since };
    res.json({
      scanCount: row.scan_count,
      averageScore: row.scan_count > 0 ? Math.round(row.score_sum / row.scan_count) : null,
      since: row.since,
    });
  } catch (err) {
    console.warn('Lecture du compteur de scans indisponible :', err.message);
    res.json({ scanCount: memStats.scanCount, averageScore: null, since: memStats.since });
  }
});

const STAAN_API_KEY = process.env.STAAN_API_KEY;
const HIVE_API_KEY = process.env.HIVE_API_KEY;
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

// Personnalités publiques et chefs d'État — le service est pensé pour
// l'exposition numérique d'un particulier sur sa propre vie, pas comme outil
// de recherche sur des figures publiques. Liste non exhaustive par nature
// (impossible de couvrir tous les pays et l'actualité politique en continu) —
// à compléter avec le temps plutôt qu'un filtre parfait dès le départ.
// Vérifiée en août 2026 pour les postes ayant récemment changé (Canada,
// Syrie notamment).
const PUBLIC_FIGURE_NAMES = [
  // Chefs d'État / de gouvernement actuels (grands pays, France en priorité)
  'emmanuel macron', 'donald trump', 'vladimir poutine', 'xi jinping',
  'kim jong-un', 'kim jong un', 'narendra modi', 'recep tayyip erdogan',
  'volodymyr zelensky', 'volodymyr zelenskyy', 'benjamin netanyahu',
  'mohammed bin salman', 'ahmed al-charaa', 'ahmad al-charaa',
  'mark carney', 'charles iii', 'roi charles', 'keir starmer',
  'friedrich merz', 'giorgia meloni', 'pedro sanchez', 'luiz inacio lula',
  'lula da silva', 'javier milei', 'olaf scholz',
  // Dictateurs historiques largement reconnus, sans ambiguïté
  'adolf hitler', 'joseph staline', 'josef staline', 'pol pot',
  'benito mussolini', 'mao zedong', 'idi amin', 'nicolae ceausescu',
  'francisco franco', 'saddam hussein', 'mouammar kadhafi', 'muammar kadhafi',
  'bachar al-assad', 'bachar al assad',
  // Autres figures mondialement connues, hors chefs d'État, où la même
  // logique s'applique (pas un particulier vérifiant sa propre exposition)
  'oussama ben laden', 'ben laden', 'ousama ben laden',
  'abou bakr al-baghdadi',
];
function isPublicFigure(name) {
  const normName = normalize(name);
  return PUBLIC_FIGURE_NAMES.some((figure) => normName === normalize(figure));
}

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

// --- Génération des vraies demandes de suppression ---
// Ce n'est pas un simple "on s'en occupe" : chaque contenu signalé au moment
// du paiement reçoit un texte de demande prêt à l'emploi, adapté à sa nature.
// Deux volets systématiques par contenu : la désindexation auprès du moteur
// (formulaire officiel Google), et la mise en demeure adressée à l'hébergeur
// du contenu lui-même (droit à l'effacement, art. 17 RGPD).
// Grandes plateformes reconnues automatiquement — pour elles, ni email
// générique ni formulaire RGPD classique : la vraie procédure qui fonctionne
// est leur propre outil de signalement intégré, doublé de PHAROS (portail
// officiel français, Arcom) en escalade. Sources vérifiées (Arcom, CNIL,
// TAKE IT DOWN Act fédéral américain en vigueur depuis le 19 mai 2026).
const KNOWN_PLATFORMS = [
  {
    match: /facebook\.com|instagram\.com/i,
    name: 'Meta (Facebook/Instagram)',
    guidance: `Utiliser le bouton "Signaler" directement sur la publication/le profil (menu ⋯) — c'est le canal le plus rapide, pas un email. Si le contenu est intime/sensible : citer le TAKE IT DOWN Act (loi fédérale US en vigueur depuis le 19 mai 2026), qui oblige la plateforme à retirer un contenu intime non consenti sous 48h.`,
  },
  {
    match: /tiktok\.com/i,
    name: 'TikTok',
    guidance: `Signalement via le bouton "Signaler" sur la vidéo/le profil, ou support.tiktok.com/fr/safety-hc/report-a-problem/report-a-user. Contenu intime/sensible : le TAKE IT DOWN Act impose un retrait sous 48h depuis le 19 mai 2026.`,
  },
  {
    match: /x\.com|twitter\.com/i,
    name: 'X (ex-Twitter)',
    guidance: `Menu ⋯ sur la publication → "Signaler" → catégorie "image intime" si applicable. Escalade sur help.x.com si pas de réponse. Contenu intime : TAKE IT DOWN Act, retrait sous 48h obligatoire.`,
  },
  {
    match: /youtube\.com/i,
    name: 'YouTube (Google)',
    guidance: `Signalement intégré sous la vidéo (icône ⋮ → "Signaler"). Contenu intime : TAKE IT DOWN Act, retrait sous 48h.`,
  },
];

function findKnownPlatform(url) {
  return KNOWN_PLATFORMS.find((p) => p.match.test(url || ''));
}

function buildGoogleRemovalRequest(item, name) {
  const motif = item.sensitive
    ? "Ce contenu porte atteinte à ma vie privée et je souhaite en demander la suppression des résultats de recherche vous concernant, conformément au droit à l'oubli reconnu par la CNIL et la CJUE (arrêt Google Spain, 2014)."
    : "Ce contenu, obsolète ou non pertinent, continue d'apparaître dans les résultats de recherche associés à mon nom et porte préjudice à ma réputation numérique.";
  return [
    `Formulaire à utiliser : support.google.com/websearch/troubleshooter/3111061 ("Supprimer des informations vous concernant sur Google")`,
    `URL concernée : ${item.url || '(URL non disponible)'}`,
    `Nom recherché associé : ${name}`,
    ``,
    `Texte suggéré pour le champ de description :`,
    `"Bonjour, je souhaite demander le retrait de la page suivante des résultats de recherche associés à mon nom : ${item.url || '[URL]'}. ${motif}"`,
  ].join('\n');
}

function buildHostNoticeRequest(item, name, hostContact = '[email de contact ou formulaire de contact du site]') {
  const base = guessSource(item.url);
  return [
    `Destinataire : ${base} — ${hostContact}`,
    `Objet : Demande de suppression de contenu — droit à l'effacement (art. 17 RGPD)`,
    ``,
    `Madame, Monsieur,`,
    ``,
    `Je vous contacte au sujet du contenu suivant, publié sur votre site et me concernant directement :`,
    `${item.url || '(URL non disponible)'}`,
    ``,
    `Conformément à l'article 17 du Règlement Général sur la Protection des Données (RGPD), je vous demande la suppression de ce contenu dans un délai d'un mois à compter de la réception de la présente demande.`,
    item.sensitive ? `Ce contenu revêt un caractère sensible et porte une atteinte directe à ma vie privée.` : `Ce contenu porte atteinte à ma réputation et n'a plus lieu d'être maintenu en ligne.`,
    ``,
    `À défaut de réponse ou de suppression dans le délai imparti, je me réserve le droit de saisir la CNIL.`,
    ``,
    `Cordialement,`,
    `${name}`,
  ].join('\n');
}

function buildDossierItems(results, name) {
  return results.map((r) => {
    const platform = findKnownPlatform(r.url);
    return {
      url: r.url || null,
      type: r.type,
      tag: r.tag,
      sensitive: r.sensitive,
      full: r.full,
      status: 'à envoyer',
      platform: platform?.name || null,
      // Grande plateforme reconnue → stratégie vérifiée et spécifique.
      // Sinon → générique (Google + mise en demeure RGPD à l'hébergeur).
      // PHAROS ne traite que l'illicite (contenu intime non consenti,
      // menaces, haine...) — proposé en escalade uniquement si le contenu
      // est signalé comme sensible, jamais pour un contenu juste gênant.
      strategy: platform
        ? platform.guidance + (r.sensitive
            ? `\n\nEscalade si sans réponse : PHAROS (portail officiel Arcom, contenu illicite) — internet-signalement.gouv.fr.`
            : '')
        : null,
      googleRequest: buildGoogleRemovalRequest(r, name),
      hostNotice: platform ? null : buildHostNoticeRequest(r, name),
    };
  });
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

// Niveau de confiance, en deux échelons désormais — 'high' ou rejeté :
//  - 'high'   : la phrase (quasi) exacte apparaît telle quelle, ou les mots
//               du nom se suivent immédiatement (à une virgule/tiret près) —
//               exactement comme un nom complet s'écrit réellement
//  - 'none'   : rejeté (un mot manque, ou les mots ne se suivent pas — signe
//               que deux personnes différentes sont mentionnées dans le même
//               texte plutôt qu'une seule)
//
// Avant, un palier "medium" acceptait les mots du nom dispersés à moins de
// 60 caractères l'un de l'autre, n'importe où dans le texte. Problème réel
// signalé en production : "Jean Martin a félicité Sophie Dupont" contient
// bien "Jean" et "Dupont" à moins de 60 caractères — et remontait à tort
// comme un résultat concernant "Jean Dupont", alors qu'il s'agit de deux
// personnes sans aucun rapport. Exiger l'adjacence élimine ce faux positif.
function relevance(item, name) {
  const text = normalize(`${item.title || ''} ${item.snippet || ''}`);
  const normName = normalize(name);
  const words = normName.split(/\s+/).filter((w) => w.length > 1);
  if (words.length === 0) return 'none';
  if (!words.every((w) => text.includes(w))) return 'none';
  if (text.includes(normName)) return 'high'; // phrase exacte telle quelle
  if (words.length === 1) return 'high'; // un seul mot déjà vérifié présent ci-dessus

  const escaped = words.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  // Les mots doivent se suivre directement, dans l'ordre du nom recherché OU
  // inversé (ex: "Dupont Jean" dans un annuaire) — jamais dispersés ailleurs
  // dans la phrase. Un léger séparateur (espace, virgule, tiret) est toléré.
  const sep = '[\\s,.\\-]{1,3}';
  const forward = new RegExp(escaped.join(sep));
  const reversed = new RegExp(escaped.slice().reverse().join(sep));
  if (forward.test(text) || reversed.test(text)) return 'high';

  return 'none';
}

// --- Cache des scans (1h) ---
// Sans lui, un nom qui devient viral sur TikTok peut épuiser le quota gratuit
// SerpApi (250/mois) en une seule journée si beaucoup de monde tape le même
// nom. Rien de perdu en fraîcheur : une exposition numérique ne change pas
// à l'échelle de l'heure, donc un résultat vieux de 40 minutes est toujours
// juste. Volontairement en mémoire, pas en base — simple, et repart à zéro
// à chaque redémarrage, ce qui est sans conséquence ici.
const SCAN_CACHE_TTL_MS = 60 * 60 * 1000;
const scanCache = new Map(); // nom normalisé -> { result, expiresAt }
function cacheKey(name) { return normalize(name); }
function getCachedScan(name) {
  const entry = scanCache.get(cacheKey(name));
  if (!entry || entry.expiresAt < Date.now()) { scanCache.delete(cacheKey(name)); return null; }
  return entry.result;
}
function setCachedScan(name, result) {
  scanCache.set(cacheKey(name), { result, expiresAt: Date.now() + SCAN_CACHE_TTL_MS });
  // Nettoyage opportuniste — évite une croissance infinie de la Map si
  // beaucoup de noms différents sont scannés sans jamais redémarrer le serveur.
  if (scanCache.size > 500) {
    const now = Date.now();
    for (const [key, val] of scanCache) if (val.expiresAt < now) scanCache.delete(key);
  }
}

// Logique de scan partagée — appelée par /api/scan, qui renvoie directement le rapport
// complet, avec les vraies descriptions).
async function performScan(name) {
  const cached = getCachedScan(name);
  if (cached) return { ...cached, fromCache: true };

  const [staan, brave, serper] = await Promise.all([callStaan(name), callBrave(name), callSerpApi(name)]);
  const merged = dedupe([...staan.hits, ...brave.hits, ...serper.hits])
    .map((r) => ({ ...r, confidence: relevance(r, name) }))
    .filter((r) => r.confidence !== 'none');
  const partial = staan.status !== 'ok' || brave.status !== 'ok' || serper.status !== 'ok';
  const hardStop = hasHardStopSignal(merged);
  const classified = classify(merged);
  const score = computeScore(classified);
  const result = {
    classified, score, partial, hardStop,
    coverage: { staan: staan.status, brave: brave.status, google: serper.status },
  };
  // On ne met en cache que les scans complets et sans signal d'urgence — un
  // hardStop ne doit jamais être servi depuis un cache, et un scan partiel
  // (source tombée) ne doit pas figer une panne temporaire pendant une heure.
  if (!hardStop && !partial) setCachedScan(name, result);
  return result;
}

app.post('/api/scan', express.json({ limit: '10kb' }), async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name || name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: 'Nom invalide' });
  }
  if (isPublicFigure(name)) {
    return res.status(403).json({
      error: 'public_figure',
      message: "Ce service est réservé à l'exposition numérique d'un particulier sur sa propre vie — pas comme outil de recherche sur des personnalités publiques ou des chefs d'État.",
    });
  }

  const { classified, score, partial, hardStop, coverage } = await performScan(name);

  // Si les trois sources sont indisponibles en même temps, un score "0/100"
  // serait indiscernable d'un vrai résultat propre — ce serait mentir par
  // omission. On renvoie une vraie erreur plutôt qu'un faux rapport rassurant.
  const allDown = coverage.staan !== 'ok' && coverage.brave !== 'ok' && coverage.google !== 'ok';
  if (allDown) {
    return res.status(503).json({ error: 'Toutes les sources sont indisponibles pour le moment.' });
  }

  if (hardStop) {
    // Aucun rapport n'est construit dans ce cas : redirection uniquement.
    return res.json({
      hardStop: true,
      redirectTo: '/urgence',
      message: 'Ce cas nécessite une prise en charge spécialisée. Voir le volet urgence.',
    });
  }

  await incrementStats(score);

  // Rapport complet renvoyé directement — le scan est gratuit, pas de raison
  // de garder les vraies descriptions derrière un email. Une seule requête
  // aux sources par scan (avant, une deuxième requête relançait tout une
  // fois), ce qui économise aussi le quota gratuit de Staan/Brave/SerpApi.
  const results = classified.map((r) => ({
    url: r.url,
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
  veille: { name: 'Veille & Protection (mensuel)', amount: 1900, mode: 'subscription', interval: 'month' },
  veille_annuel: { name: 'Veille & Protection (annuel)', amount: 19000, mode: 'subscription', interval: 'year' },
  premium: { name: 'Accompagnement Premium', amount: 34900, mode: 'payment' },
  ebook_disparaitre: { name: 'Ebook — Disparaître d\'internet', amount: 900, mode: 'payment' },
  ebook_savent: { name: 'Ebook — Ce qu\'ils savent de vous', amount: 900, mode: 'payment' },
  ebook_rupture: { name: 'Ebook — Rupture et vie privée numérique', amount: 900, mode: 'payment' },
  ebook_pack: { name: 'Pack des 3 ebooks', amount: 1900, mode: 'payment' },
};

// Fichiers réellement livrés pour chaque offre ebook — utilisé après paiement
// confirmé pour savoir quoi proposer en téléchargement.
const EBOOK_FILES = {
  ebook_disparaitre: ['1-disparaitre-internet.pdf'],
  ebook_savent: ['2-ce-quils-savent-de-vous.pdf'],
  ebook_rupture: ['3-rupture-vie-privee-numerique.pdf'],
  ebook_pack: ['1-disparaitre-internet.pdf', '2-ce-quils-savent-de-vous.pdf', '3-rupture-vie-privee-numerique.pdf'],
};
const path = require('path');
const fsSync = require('fs');
// Les PDF eux-mêmes doivent être déposés dans ce dossier au moment du
// déploiement — server.js ne les génère pas, il les sert seulement une fois
// le paiement vérifié.
const EBOOKS_DIR = path.join(__dirname, 'ebooks');

// Téléchargement d'un ebook après paiement — jamais de fichier statique
// public : la légitimité de la demande est vérifiée directement auprès de
// Stripe à chaque appel, via le session_id renvoyé par l'URL de succès.
// Sans cette vérification, n'importe qui devinant l'URL du PDF pourrait le
// télécharger sans avoir payé.
app.get('/api/ebook-download', scanLimiter, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement non configuré' });
  const { session_id, file } = req.query;
  if (!session_id || !file) return res.status(400).json({ error: 'Paramètres manquants' });

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') {
      return res.status(403).json({ error: 'Paiement non confirmé pour cette session' });
    }
    const tier = session.metadata?.tier;
    const allowedFiles = EBOOK_FILES[tier] || [];
    if (!allowedFiles.includes(file)) {
      return res.status(403).json({ error: 'Ce fichier ne fait pas partie de votre achat' });
    }
    const filePath = path.join(EBOOKS_DIR, file);
    if (!fsSync.existsSync(filePath)) {
      console.warn(`Ebook payé mais fichier introuvable sur le serveur : ${file}`);
      return res.status(500).json({ error: 'Fichier temporairement indisponible — contactez-nous' });
    }
    res.download(filePath, file);
  } catch (err) {
    console.warn('Téléchargement ebook indisponible :', err.message);
    res.status(500).json({ error: 'Impossible de vérifier ce paiement' });
  }
});

// Liste des fichiers achetés pour une session donnée — appelé par la page de
// succès pour savoir quels boutons de téléchargement afficher.
app.get('/api/ebook-purchase', scanLimiter, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement non configuré' });
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'session_id manquant' });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') return res.status(403).json({ error: 'Paiement non confirmé' });
    const tier = session.metadata?.tier;
    const files = EBOOK_FILES[tier];
    if (!files) return res.status(404).json({ error: "Cette session n'est pas un achat d'ebook" });
    res.json({ files });
  } catch (err) {
    res.status(500).json({ error: 'Impossible de vérifier ce paiement' });
  }
});

// Préparation du dossier AVANT paiement — les demandes de suppression sont
// déjà rédigées à ce stade, pour chaque contenu du scan. Rien n'est envoyé
// tant que le paiement n'est pas confirmé par le webhook (voir plus bas).
app.post('/api/prepare-dossier', express.json({ limit: '50kb' }), scanLimiter, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de données non configurée' });
  const { name, tier, results } = req.body || {};
  if (!name || !Array.isArray(results) || results.length === 0 || results.length > 100) {
    return res.status(400).json({ error: 'Données de dossier invalides' });
  }
  if (!['ponctuelle', 'premium'].includes(tier)) {
    return res.status(400).json({ error: 'Offre invalide pour un dossier' });
  }
  try {
    const items = buildDossierItems(results, name);
    const { rows } = await pool.query(
      `INSERT INTO dossiers (name, tier, items) VALUES ($1, $2, $3) RETURNING id`,
      [name, tier, JSON.stringify(items)]
    );
    res.json({ dossier_id: rows[0].id });
  } catch (err) {
    console.warn('Échec de la préparation du dossier :', err.message);
    res.status(500).json({ error: 'Impossible de préparer le dossier' });
  }
});

// --- Consultation et gestion des dossiers — protégé par un secret d'admin,
// jamais public. Volontairement simple (pas d'interface graphique) : une
// requête avec le bon en-tête suffit à consulter ou clôturer un dossier.
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const crypto = require('crypto');
// Comparaison à temps constant — comparer deux chaînes avec !== fuit un
// signal exploitable (le temps de réponse varie selon le nombre de
// caractères corrects) qui peut aider à deviner le secret par tâtonnement.
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function checkAdmin(req, res) {
  if (!ADMIN_SECRET || !safeCompare(req.headers['x-admin-secret'] || '', ADMIN_SECRET)) {
    res.status(403).json({ error: 'Non autorisé' });
    return false;
  }
  return true;
}
// Même les routes protégées par secret doivent être limitées en débit —
// sans ça, rien n'empêche un grand nombre de tentatives pour deviner le
// secret par force brute.
const adminLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
app.use('/api/admin', adminLimiter);
app.use('/api/cron', adminLimiter);

app.get('/api/admin/dossiers', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Base de données non configurée' });
  const { status } = req.query;
  const { rows } = status
    ? await pool.query(`SELECT * FROM dossiers WHERE status = $1 ORDER BY created_at DESC`, [status])
    : await pool.query(`SELECT * FROM dossiers ORDER BY created_at DESC LIMIT 50`);
  res.json({ dossiers: rows });
});

app.post('/api/admin/dossiers/:id/status', express.json({ limit: '1kb' }), async (req, res) => {
  if (!checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Base de données non configurée' });
  const { status } = req.body || {};
  const VALID_STATUSES = ['en_attente_paiement', 'à traiter', 'résolu', 'annulé'];
  if (!status || !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status invalide — valeurs acceptées : ${VALID_STATUSES.join(', ')}` });
  }
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(400).json({ error: 'Identifiant de dossier invalide' });
  }
  await pool.query(`UPDATE dossiers SET status = $1 WHERE id = $2`, [status, req.params.id]);

  // Confirmation au client quand un dossier passe à "résolu" — tient la
  // promesse faite dans l'email d'alerte Veille ("vous recevrez une
  // confirmation une fois traité").
  if (status === 'résolu' && BREVO_API_KEY && BREVO_SENDER_EMAIL) {
    try {
      const { rows } = await pool.query(`SELECT name, email FROM dossiers WHERE id = $1`, [req.params.id]);
      const dossier = rows[0];
      if (dossier?.email) {
        await fetch('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            sender: { name: BREVO_SENDER_NAME, email: BREVO_SENDER_EMAIL },
            to: [{ email: dossier.email }],
            subject: `Dossier traité — ${dossier.name}`,
            htmlContent: `<p>Le contenu signalé a été pris en charge et le dossier est maintenant résolu. Merci de votre confiance.</p>`,
          }),
        });
      }
    } catch (err) {
      console.warn('Échec de la confirmation client au client :', err.message);
    }
  }

  res.json({ ok: true });
});

app.post('/api/checkout', express.json({ limit: '10kb' }), async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement non configuré (STRIPE_SECRET_KEY absente)' });
  const { tier, ref, name, dossier_id } = req.body || {};
  const offer = OFFERS[tier];
  if (!offer) return res.status(400).json({ error: 'Offre inconnue' });
  const isVeille = tier === 'veille' || tier === 'veille_annuel';
  if (isVeille && (!name || name.trim().length < 2)) {
    return res.status(400).json({ error: 'Nom requis pour activer la veille' });
  }

  try {
    const priceData = {
      currency: 'eur',
      product_data: { name: offer.name },
      unit_amount: offer.amount,
    };
    if (offer.mode === 'subscription') priceData.recurring = { interval: offer.interval };

    const session = await stripe.checkout.sessions.create({
      mode: offer.mode,
      payment_method_types: ['card'],
      line_items: [{ price_data: priceData, quantity: 1 }],
      // Un vrai client Stripe est créé à chaque paiement, même ponctuel — sans
      // ça, Stripe ne garde qu'une trace anonyme. Avec ça, le dashboard Stripe
      // devient une vraie liste de clients consultable, sans base de données
      // maison à construire pour l'instant.
      customer_creation: offer.mode === 'payment' ? 'always' : undefined,
      // Code de parrainage, nom recherché pour la Veille, et dossier de
      // suppression préparé en amont — rattachés au vrai moment où le
      // paiement se confirme.
      metadata: {
        ...(ref ? { ref } : {}),
        ...(isVeille ? { veille_name: name.trim() } : {}),
        ...(dossier_id ? { dossier_id: String(dossier_id) } : {}),
        tier,
      },
      success_url: `${FRONTEND_URL}?paiement=succes&session_id={CHECKOUT_SESSION_ID}&tier=${tier}`,
      cancel_url: `${FRONTEND_URL}?paiement=annule`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.warn('Stripe indisponible :', err.message);
    res.status(500).json({ error: 'Impossible de créer la session de paiement' });
  }
});

// Portail client Stripe — permet à quelqu'un d'abonné à la Veille de gérer ou
// résilier lui-même son abonnement (moyen de paiement, factures, annulation),
// sans compte sur notre site et sans qu'il ait besoin de nous écrire un email.
// On retrouve le client à partir du session_id que Stripe renvoie dans
// l'URL de succès ({CHECKOUT_SESSION_ID}) — aucune donnée stockée de notre côté.
app.post('/api/portal', express.json({ limit: '10kb' }), async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Non configuré' });
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id manquant' });

  try {
    const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
    if (!checkoutSession.customer) {
      return res.status(404).json({ error: "Aucun abonnement associé à cette session" });
    }
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: checkoutSession.customer,
      return_url: FRONTEND_URL,
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    console.warn('Portail Stripe indisponible :', err.message);
    res.status(500).json({ error: "Impossible d'ouvrir le portail de gestion" });
  }
});

// --- Envoi d'email via Brevo — réactivé spécifiquement pour les alertes Veille.
// ⚠️ Ne fonctionnera réellement qu'une fois le domaine monanonymat.fr authentifié
// (SPF/DKIM/DMARC) sur Brevo — un envoi depuis une adresse Gmail est rejeté par
// Brevo (voir l'historique du projet). Tant que ce n'est pas fait, cette
// fonction échouera proprement (loggée, sans planter le reste du processus).
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL;
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME || 'monanonymat.fr';

async function sendVeilleAlert({ to, name, newScore, newSensitiveCount }) {
  if (!BREVO_API_KEY || !BREVO_SENDER_EMAIL) {
    console.warn(`Alerte Veille pour "${name}" NON envoyée — Brevo non configuré.`);
    return { sent: false };
  }
  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: BREVO_SENDER_NAME, email: BREVO_SENDER_EMAIL },
        to: [{ email: to }],
        subject: `Nouveau contenu détecté — ${name}`,
        htmlContent: `<p>Votre veille a détecté un changement : score actuel <b>${newScore}/100</b>, dont ${newSensitiveCount} contenu(s) sensible(s). La prise en charge démarre automatiquement de notre côté — vous recevrez une confirmation une fois traité.</p>`,
      }),
    });
    return { sent: res.ok };
  } catch (err) {
    console.warn('Brevo (alerte Veille) indisponible :', err.message);
    return { sent: false };
  }
}

// --- Tâche planifiée : re-scan automatique des abonnés Veille ---
// Protégée par un secret partagé — cette route n'est jamais appelée par un
// visiteur, uniquement par le planificateur externe (Render Cron Jobs ou
// équivalent). Sans le bon secret en en-tête, la requête est rejetée.
const CRON_SECRET = process.env.CRON_SECRET;

app.post('/api/cron/rescan-veille', async (req, res) => {
  if (!CRON_SECRET || !safeCompare(req.headers['x-cron-secret'] || '', CRON_SECRET)) {
    return res.status(403).json({ error: 'Non autorisé' });
  }
  if (!pool) return res.status(503).json({ error: 'Base de données non configurée' });

  // Les mois de Veille offerts (suite à une suppression ponctuelle) expirent
  // après 30 jours — au client de s'abonner pour de vrai s'il veut continuer.
  const { rowCount: expired } = await pool.query(
    `UPDATE veille_subscribers SET active = false
     WHERE is_free_trial = true AND active = true AND created_at < now() - interval '30 days'`
  );
  if (expired > 0) console.log(`${expired} essai(s) gratuit(s) de Veille expiré(s).`);

  const { rows: subscribers } = await pool.query(
    `SELECT id, name, email, last_score, last_sensitive_count FROM veille_subscribers WHERE active = true`
  );

  let alertsSent = 0;
  for (const sub of subscribers) {
    try {
      const { classified, score, hardStop } = await performScan(sub.name);
      if (hardStop) continue; // jamais de traitement automatique sur un signal mineur — voir hasHardStopSignal()
      const sensitiveCount = classified.filter((r) => r.sensitive).length;

      const isNewOrWorse = sub.last_score === null ||
        score > sub.last_score ||
        sensitiveCount > (sub.last_sensitive_count || 0);

      if (isNewOrWorse && sub.last_score !== null && sub.email) {
        const alert = await sendVeilleAlert({ to: sub.email, name: sub.name, newScore: score, newSensitiveCount: sensitiveCount });
        if (alert.sent) alertsSent += 1;

        // La Veille promet une suppression automatique, pas juste une
        // alerte — sans ce dossier généré tout seul, la promesse marketing
        // ne correspondrait pas à ce que fait vraiment le système.
        try {
          const newResults = classified.map((r) => ({
            url: r.url, type: guessType(r.url), tag: guessSource(r.url), year: '—',
            sensitive: r.sensitive, confidence: r.confidence,
            full: r.snippet || r.title || 'Contenu trouvé, description non disponible.',
          }));
          const items = buildDossierItems(newResults, sub.name);
          await pool.query(
            `INSERT INTO dossiers (name, email, tier, status, items, paid_at) VALUES ($1, $2, 'veille_auto', 'à traiter', $3, now())`,
            [sub.name, sub.email, JSON.stringify(items)]
          );
        } catch (err) {
          console.warn(`Échec de la génération auto du dossier Veille pour l'abonné ${sub.id} :`, err.message);
        }
      }

      await pool.query(
        `UPDATE veille_subscribers SET last_score = $1, last_sensitive_count = $2, last_scanned_at = now() WHERE id = $3`,
        [score, sensitiveCount, sub.id]
      );
    } catch (err) {
      console.warn(`Échec du re-scan Veille pour l'abonné ${sub.id} :`, err.message);
    }
  }

  console.log(`Re-scan Veille terminé : ${subscribers.length} abonné(s) traité(s), ${alertsSent} alerte(s) envoyée(s).`);

  // Relance automatique des dossiers de suppression en retard — le RGPD
  // laisse un délai d'un mois pour répondre à une mise en demeure. Passé ce
  // délai sans qu'un dossier soit marqué "résolu", on prévient l'exploitant
  // du site (toi) plutôt que de compter sur une vérification manuelle.
  let dossierReminderSent = false;
  try {
    const { rows: overdueDossiers } = await pool.query(
      `SELECT id, name, tier, created_at FROM dossiers
       WHERE status = 'à traiter' AND paid_at < now() - interval '30 days'`
    );
    if (overdueDossiers.length > 0 && BREVO_API_KEY && BREVO_SENDER_EMAIL) {
      const list = overdueDossiers.map((d) => `#${d.id} — ${d.name} (${d.tier})`).join('<br>');
      const alertRes = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          sender: { name: BREVO_SENDER_NAME, email: BREVO_SENDER_EMAIL },
          to: [{ email: BREVO_SENDER_EMAIL }],
          subject: `${overdueDossiers.length} dossier(s) de suppression en retard (>30 jours)`,
          htmlContent: `<p>Ces dossiers n'ont pas été marqués comme résolus plus d'un mois après le paiement :</p><p>${list}</p>`,
        }),
      });
      dossierReminderSent = alertRes.ok;
      if (dossierReminderSent) console.log(`Relance envoyée pour ${overdueDossiers.length} dossier(s) en retard.`);
    }
  } catch (err) {
    console.warn('Échec de la vérification des dossiers en retard :', err.message);
  }

  res.json({ processed: subscribers.length, alertsSent, dossierReminderSent });
});

// Les abonnements Veille sont maintenant stockés durablement (table
// veille_subscribers ci-dessus). Les paiements ponctuels (suppression,
// premium) restent seulement journalisés/comptés en mémoire pour l'instant —
// suffisant tant qu'ils sont traités manuellement, mais à stocker aussi en
// base le jour où leur suivi doit être consultable après un redémarrage.
const confirmedPayments = { count: 0 };
// Suivi des événements Stripe déjà traités — voir le webhook plus bas pour
// le pourquoi. En mémoire, comme le cache de scan : suffisant ici, un
// événement Stripe n'est jamais renvoyé plusieurs jours après coup.
const processedStripeEvents = new Set();
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Webhook Stripe — la vraie source de vérité pour savoir si un paiement a
// réellement eu lieu. La redirection success_url seule ne le prouve jamais :
// n'importe qui peut atteindre cette URL sans avoir payé. Le corps doit rester
// BRUT (express.raw, pas express.json) pour que la vérification de signature
// fonctionne — Stripe signe les octets exacts envoyés.
// --- Module "auto-nettoyage X" ---
// Contrairement à la suppression de contenu tiers, ceci EST automatisable :
// c'est le compte de la personne elle-même, elle peut légitimement autoriser
// une application à agir en son nom. X propose une vraie API pour ça depuis
// février 2026 (tarif à l'usage, ~0,015€ par suppression — pas d'abonnement
// fixe nécessaire). OAuth 2.0 + PKCE, comme recommandé par X.
const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET;
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || `${FRONTEND_URL}/nettoyage-x.html`;

// État de connexion temporaire — un token d'accès X vaut de l'argent réel et
// donne un accès complet au compte de la personne : on ne le garde jamais
// plus longtemps que la session de nettoyage en cours, jamais en base.
const xSessions = new Map(); // state -> { verifier, accessToken?, expiresAt }
function cleanupExpiredXSessions() {
  const now = Date.now();
  for (const [state, s] of xSessions) if (s.expiresAt < now) xSessions.delete(state);
}

function base64url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --- Vérification deepfake (Hive AI) ---
// Même principe que Staan/Brave/SerpApi : si HIVE_API_KEY n'est pas
// configurée, on le dit clairement plutôt que de faire semblant. Aucune
// image n'est jamais stockée côté serveur — reçue en mémoire, transmise à
// Hive, puis immédiatement oubliée.
//
// Endpoint, authentification, format de requête (JSON + base64) et format
// de réponse tous confirmés via la documentation officielle du modèle exact
// (docs.thehive.ai/docs/ai-generated-and-deepfake-content-detection-playground)
// — plus aucune hypothèse à ce stade. Seuils de décision (0,9) également
// alignés sur la recommandation officielle de Hive, pas une valeur choisie
// arbitrairement.
//
// ⚠️ Limite réelle à connaître : le plan gratuit "Playground" est limité à
// 100 requêtes par jour, partagées entre tous les visiteurs du site (pas
// par personne) — pas de garde-fou automatique côté code pour ce plafond
// précis, seulement la limite de débit habituelle par adresse IP.
const deepfakeLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.post('/api/deepfake-check', deepfakeLimiter, upload.single('image'), async (req, res) => {
  if (!HIVE_API_KEY) {
    return res.status(503).json({
      error: 'no_key',
      message: "Cette fonctionnalité n'est pas encore activée — revenez bientôt.",
    });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'missing_file', message: 'Aucune image reçue.' });
  }
  try {
    // Format confirmé par la documentation officielle du modèle exact
    // (docs.thehive.ai/docs/ai-generated-and-deepfake-content-detection-playground) :
    // JSON avec l'image encodée en base64, pas de multipart. Endpoint et
    // authentification également confirmés par cette même page — plus
    // aucune hypothèse à ce stade.
    const base64Data = req.file.buffer.toString('base64');
    const mediaDataUri = `data:${req.file.mimetype};base64,${base64Data}`;

    const hiveRes = await fetch('https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HIVE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        media_metadata: true,
        input: [{ media_base64: mediaDataUri }],
      }),
    });

    if (!hiveRes.ok) {
      console.warn(`Hive a répondu ${hiveRes.status} lors d'une analyse deepfake.`);
      return res.status(502).json({ error: 'analysis_failed', message: "L'analyse n'a pas pu aboutir — réessayez dans un instant." });
    }

    const data = await hiveRes.json();
    const classes = data?.output?.[0]?.classes || [];
    const getScore = (name) => classes.find((c) => c.class === name)?.value ?? null;

    const aiGenerated = getScore('ai_generated');
    const deepfake = getScore('deepfake');

    // La liste contient aussi une classe par générateur précis (sora,
    // midjourney, stablediffusionxl...) — utile pour préciser la source si
    // le score global est élevé, comme le fait l'aire de jeux Hive elle-même.
    const generatorClasses = classes.filter((c) =>
      !['not_ai_generated', 'ai_generated', 'deepfake', 'none', 'inconclusive', 'inconclusive_video', 'not_ai_generated_audio', 'ai_generated_audio'].includes(c.class)
    );
    const topGenerator = generatorClasses.reduce((max, c) => (c.value > (max?.value ?? -1) ? c : max), null);

    let verdict, confidence;
    // Seuils recommandés officiellement par Hive pour un résultat fiable
    // (pas 0,5 arbitraire) — voir la section "Thresholds" de leur doc.
    if (deepfake !== null && deepfake >= 0.9) {
      verdict = 'deepfake_probable';
      confidence = deepfake;
    } else if (aiGenerated !== null && aiGenerated >= 0.9) {
      verdict = 'generee_par_ia_probable';
      confidence = aiGenerated;
    } else if (aiGenerated !== null) {
      verdict = 'authentique_probable';
      confidence = 1 - aiGenerated;
    } else {
      verdict = 'resultat_indisponible';
      confidence = null;
    }

    res.json({
      verdict,
      confidence: confidence !== null ? Math.round(confidence * 10000) / 100 : null,
      topGenerator: (verdict === 'generee_par_ia_probable' && topGenerator && topGenerator.value > 0.3)
        ? { name: topGenerator.class, confidence: Math.round(topGenerator.value * 10000) / 100 }
        : null,
    });
  } catch (err) {
    console.warn('Erreur lors de l\'analyse deepfake :', err.message);
    res.status(500).json({ error: 'analysis_failed', message: "L'analyse n'a pas pu aboutir — réessayez dans un instant." });
  }
});

app.get('/api/x/auth-url', scanLimiter, (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).json({ error: "Nettoyage X non configuré (X_CLIENT_ID absente)" });
  cleanupExpiredXSessions();
  const state = crypto.randomBytes(16).toString('hex');
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  xSessions.set(state, { verifier, expiresAt: Date.now() + 10 * 60 * 1000 }); // 10 min pour compléter la connexion

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: X_REDIRECT_URI,
    scope: 'tweet.read tweet.write users.read offline.access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  res.json({ url: `https://x.com/i/oauth2/authorize?${params.toString()}`, state });
});

app.post('/api/x/callback', express.json({ limit: '2kb' }), scanLimiter, async (req, res) => {
  if (!X_CLIENT_ID || !X_CLIENT_SECRET) return res.status(503).json({ error: 'Nettoyage X non configuré' });
  const { code, state } = req.body || {};
  const session = xSessions.get(state);
  if (!code || !session) return res.status(400).json({ error: 'Session de connexion invalide ou expirée — recommencez.' });

  try {
    const tokenRes = await fetch('https://api.x.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code, redirect_uri: X_REDIRECT_URI, code_verifier: session.verifier,
      }),
    });
    if (!tokenRes.ok) {
      const body = await tokenRes.text().catch(() => '');
      console.warn(`X OAuth token a répondu ${tokenRes.status} : ${body.slice(0, 300)}`);
      return res.status(502).json({ error: 'Connexion à X refusée' });
    }
    const tokenData = await tokenRes.json();
    // Le token remplace le verifier — la session ne sert plus qu'à cette
    // seule fenêtre de nettoyage, jamais persistée au-delà d'une heure.
    xSessions.set(state, { accessToken: tokenData.access_token, expiresAt: Date.now() + 60 * 60 * 1000 });
    res.json({ ok: true, state });
  } catch (err) {
    console.warn('X OAuth callback indisponible :', err.message);
    res.status(500).json({ error: 'Connexion à X indisponible' });
  }
});

app.get('/api/x/tweets', scanLimiter, async (req, res) => {
  const session = xSessions.get(req.query.state);
  if (!session?.accessToken) return res.status(401).json({ error: 'Non connecté à X' });
  try {
    const meRes = await fetch('https://api.x.com/2/users/me', {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    });
    if (!meRes.ok) return res.status(502).json({ error: 'Impossible de récupérer le profil X' });
    const me = await meRes.json();
    const tweetsRes = await fetch(
      `https://api.x.com/2/users/${me.data.id}/tweets?max_results=100&tweet.fields=created_at`,
      { headers: { Authorization: `Bearer ${session.accessToken}` } }
    );
    if (!tweetsRes.ok) return res.status(502).json({ error: 'Impossible de récupérer les tweets' });
    const tweets = await tweetsRes.json();
    res.json({ username: me.data.username, tweets: tweets.data || [] });
  } catch (err) {
    console.warn('X tweets indisponible :', err.message);
    res.status(500).json({ error: 'X indisponible' });
  }
});

app.post('/api/x/delete-batch', express.json({ limit: '10kb' }), scanLimiter, async (req, res) => {
  const { state, tweetIds } = req.body || {};
  const session = xSessions.get(state);
  if (!session?.accessToken) return res.status(401).json({ error: 'Non connecté à X' });
  if (!Array.isArray(tweetIds) || tweetIds.length === 0 || tweetIds.length > 200) {
    return res.status(400).json({ error: 'Liste de tweets invalide (1 à 200 par lot)' });
  }
  const results = { deleted: 0, failed: 0 };
  // Séquentiel, volontairement : la limite de débit de X est stricte, et
  // chaque suppression a un coût réel — pas question de la parallèliser.
  for (const id of tweetIds) {
    try {
      const delRes = await fetch(`https://api.x.com/2/tweets/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.accessToken}` },
      });
      if (delRes.ok) results.deleted += 1; else results.failed += 1;
    } catch { results.failed += 1; }
  }
  console.log(`Nettoyage X : ${results.deleted} tweet(s) supprimé(s), ${results.failed} échec(s).`);
  res.json(results);
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.warn('Webhook Stripe reçu mais STRIPE_WEBHOOK_SECRET absente — signature non vérifiable, événement ignoré par sécurité.');
    return res.status(503).send('Webhook non configuré');
  }

  let event;
  try {
    const signature = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    // Signature invalide : soit une fausse requête, soit une clé mal configurée.
    // On rejette sans donner de détail exploitable dans la réponse.
    console.warn('Signature du webhook Stripe invalide :', err.message);
    return res.status(400).send('Signature invalide');
  }

  // Stripe peut renvoyer un même événement plusieurs fois — c'est documenté
  // et normal de leur côté (ex. si notre réponse a mis trop de temps à
  // arriver la première fois), pas une attaque. Sans cette vérification, un
  // renvoi légitime pourrait créer un deuxième mois d'essai offert, un
  // deuxième abonnement Veille, ou activer un dossier une deuxième fois.
  if (processedStripeEvents.has(event.id)) {
    console.log(`Événement Stripe ${event.id} déjà traité — ignoré (renvoi normal de Stripe).`);
    return res.json({ received: true, duplicate: true });
  }
  processedStripeEvents.add(event.id);
  if (processedStripeEvents.size > 1000) {
    // Purge simple : on ne garde pas un historique infini, un événement Stripe
    // n'est de toute façon jamais renvoyé après plusieurs jours.
    const excess = processedStripeEvents.size - 1000;
    let i = 0;
    for (const id of processedStripeEvents) { if (i++ >= excess) break; processedStripeEvents.delete(id); }
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    confirmedPayments.count += 1;
    console.log(`Paiement confirmé (webhook) : session ${session.id}, ${session.amount_total / 100}€, ref=${session.metadata?.ref || 'aucun'}`);

    const veilleName = session.metadata?.veille_name;
    if (veilleName && pool) {
      try {
        await pool.query(
          `INSERT INTO veille_subscribers (name, email, stripe_customer_id, stripe_subscription_id)
           VALUES ($1, $2, $3, $4)`,
          [veilleName, session.customer_details?.email || null, session.customer || null, session.subscription || null]
        );
        console.log(`Veille activée pour "${veilleName}" — abonné enregistré en base.`);
      } catch (err) {
        console.warn('Échec de l\'enregistrement de l\'abonné Veille en base :', err.message);
      }
    } else if (veilleName && !pool) {
      console.warn(`Veille payée pour "${veilleName}" mais AUCUNE base de données configurée — abonnement perdu, non surveillé. Configurer DATABASE_URL en urgence.`);
    }

    // Activation du dossier de suppression préparé avant paiement — les
    // demandes rédigées à l'avance deviennent officiellement à traiter.
    // Vérification de cohérence : le dossier doit correspondre au tarif
    // réellement payé et ne pas avoir déjà été activé — sans ça, un
    // dossier_id existant pourrait être détourné sur un autre paiement.
    const dossierId = session.metadata?.dossier_id;
    if (dossierId && pool) {
      try {
        const { rows: existing } = await pool.query(`SELECT tier, status FROM dossiers WHERE id = $1`, [dossierId]);
        const dossier = existing[0];
        if (!dossier) {
          console.warn(`Dossier #${dossierId} introuvable — paiement confirmé mais rien à activer.`);
        } else if (dossier.status !== 'en_attente_paiement') {
          console.warn(`Dossier #${dossierId} déjà activé ou traité (statut "${dossier.status}") — activation ignorée.`);
        } else if (dossier.tier !== session.metadata?.tier) {
          console.warn(`Dossier #${dossierId} : tarif du dossier ("${dossier.tier}") différent du tarif payé ("${session.metadata?.tier}") — activation refusée par sécurité.`);
        } else {
          await pool.query(
            `UPDATE dossiers SET status = 'à traiter', email = $1, stripe_session_id = $2, paid_at = now() WHERE id = $3`,
            [session.customer_details?.email || null, session.id, dossierId]
          );
          console.log(`Dossier #${dossierId} activé après paiement confirmé.`);
        }
      } catch (err) {
        console.warn('Échec de l\'activation du dossier :', err.message);
      }
    }

    // Suppression ponctuelle → 1 mois de Veille offert automatiquement, pour
    // qu'un client ne se sente jamais "réglé" à tort pendant que le contenu
    // supprimé peut réapparaître ailleurs.
    if (session.metadata?.tier === 'ponctuelle' && pool) {
      try {
        const { rows } = dossierId
          ? await pool.query(`SELECT name FROM dossiers WHERE id = $1`, [dossierId])
          : { rows: [] };
        const nameForTrial = rows[0]?.name;
        if (nameForTrial) {
          await pool.query(
            `INSERT INTO veille_subscribers (name, email, active, is_free_trial) VALUES ($1, $2, true, true)`,
            [nameForTrial, session.customer_details?.email || null]
          );
          console.log(`Mois de Veille offert activé pour "${nameForTrial}" (suite à une suppression ponctuelle).`);
        }
      } catch (err) {
        console.warn('Échec de l\'activation de l\'essai Veille offert :', err.message);
      }
    }
  }

  if (event.type === 'customer.subscription.deleted' && pool) {
    // Résiliation (portail client ou impayé) — on arrête la surveillance associée.
    const subscription = event.data.object;
    try {
      await pool.query(
        `UPDATE veille_subscribers SET active = false WHERE stripe_subscription_id = $1`,
        [subscription.id]
      );
      console.log(`Abonnement Veille résilié (${subscription.id}) — surveillance désactivée.`);
    } catch (err) {
      console.warn('Échec de la désactivation de l\'abonné :', err.message);
    }
  }

  res.json({ received: true });
});

const PORT = process.env.PORT || 3000;
initDb().catch((err) => console.warn('Échec de l\'initialisation de la base de données :', err.message));
app.listen(PORT, () => console.log(`monanonymat backend sur :${PORT}`));
