// Build the bundled site-logo set shown on item tiles (desktop list, browser
// extension picker, iPhone list) from Simple Icons (CC0, pinned in
// webui/package.json). Nothing is fetched at runtime: the vault never tells a
// site it has an account there just to draw a logo.
//
//   node scripts/build_site_logos.mjs
//
// Writes src/localvault/assets/site_logos.json (the iOS app bundles that file
// directly, see ios/project.yml) and a byte-for-byte copy for the browser
// extension; tests/test_site_logos.py fails if the copy drifts. The iPhone app
// draws the glyphs from ios/App/SiteLogos.xcassets (one vector template image
// per logo, "logo-<slug>"), also written here. Output shape:
//   {"source": ..., "logos": {slug: {"title", "hex", "path"}}, "domains": {domain: slug}}
// "hex" is the brand colour (tile background); "path" is the 24x24 glyph.
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(join(root, 'webui', 'package.json'));
const icons = require('simple-icons');
const { version } = JSON.parse(readFileSync(join(root, 'webui', 'node_modules', 'simple-icons', 'package.json'), 'utf8'));

// Simple Icons slug -> the registrable domains that show it. Brands Simple Icons
// has removed at their owners' request (Microsoft, Amazon, LinkedIn, Slack,
// Adobe, OpenAI, ...) are left out: those sites show the type icon. A domain matches
// itself and every subdomain (accounts.google.com -> google.com).
const SITES = {
  google: ['google.com', 'google.co.uk', 'google.de', 'google.fr', 'google.gr'],
  gmail: ['gmail.com', 'mail.google.com'],
  youtube: ['youtube.com', 'youtu.be'],
  googledrive: ['drive.google.com'],
  apple: ['apple.com', 'icloud.com', 'appleid.apple.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  messenger: ['messenger.com'],
  threads: ['threads.net', 'threads.com'],
  meta: ['meta.com'],
  x: ['x.com', 'twitter.com'],
  bluesky: ['bsky.app'],
  mastodon: ['mastodon.social'],
  reddit: ['reddit.com'],
  tiktok: ['tiktok.com'],
  snapchat: ['snapchat.com'],
  pinterest: ['pinterest.com'],
  tumblr: ['tumblr.com'],
  discord: ['discord.com', 'discord.gg', 'discordapp.com'],
  telegram: ['telegram.org', 't.me'],
  signal: ['signal.org'],
  viber: ['viber.com'],
  wechat: ['wechat.com'],
  line: ['line.me'],
  zoom: ['zoom.us', 'zoom.com'],
  github: ['github.com'],
  gitlab: ['gitlab.com'],
  bitbucket: ['bitbucket.org'],
  stackoverflow: ['stackoverflow.com'],
  npm: ['npmjs.com'],
  pypi: ['pypi.org'],
  docker: ['docker.com', 'hub.docker.com'],
  vercel: ['vercel.com'],
  netlify: ['netlify.com'],
  cloudflare: ['cloudflare.com'],
  digitalocean: ['digitalocean.com'],
  googlecloud: ['cloud.google.com'],
  firebase: ['firebase.google.com'],
  jetbrains: ['jetbrains.com'],
  atlassian: ['atlassian.com', 'atlassian.net'],
  jira: ['jira.com'],
  trello: ['trello.com'],
  notion: ['notion.so', 'notion.com'],
  asana: ['asana.com'],
  clickup: ['clickup.com'],
  linear: ['linear.app'],
  figma: ['figma.com'],
  miro: ['miro.com'],
  dropbox: ['dropbox.com'],
  box: ['box.com'],
  mega: ['mega.nz', 'mega.io'],
  evernote: ['evernote.com'],
  todoist: ['todoist.com'],
  airtable: ['airtable.com'],
  zapier: ['zapier.com'],
  hubspot: ['hubspot.com'],
  shopify: ['shopify.com', 'myshopify.com'],
  wordpress: ['wordpress.com', 'wordpress.org'],
  wix: ['wix.com'],
  squarespace: ['squarespace.com'],
  godaddy: ['godaddy.com'],
  namecheap: ['namecheap.com'],
  medium: ['medium.com'],
  substack: ['substack.com'],
  patreon: ['patreon.com'],
  quora: ['quora.com'],
  wikipedia: ['wikipedia.org'],
  duolingo: ['duolingo.com'],
  coursera: ['coursera.org'],
  udemy: ['udemy.com'],
  khanacademy: ['khanacademy.org'],
  anthropic: ['anthropic.com'],
  claude: ['claude.ai'],
  perplexity: ['perplexity.ai'],
  googlegemini: ['gemini.google.com'],
  huggingface: ['huggingface.co'],
  protonmail: ['proton.me', 'protonmail.com'],
  tuta: ['tuta.com', 'tutanota.com'],
  zoho: ['zoho.com', 'zoho.eu'],
  mailchimp: ['mailchimp.com'],
  duckduckgo: ['duckduckgo.com'],
  brave: ['brave.com'],
  firefox: ['firefox.com'],
  mozilla: ['mozilla.org'],
  opera: ['opera.com'],
  vivaldi: ['vivaldi.com'],
  netflix: ['netflix.com'],
  spotify: ['spotify.com'],
  applemusic: ['music.apple.com'],
  hbo: ['hbo.com', 'hbomax.com', 'max.com'],
  crunchyroll: ['crunchyroll.com'],
  twitch: ['twitch.tv'],
  kick: ['kick.com'],
  soundcloud: ['soundcloud.com'],
  deezer: ['deezer.com'],
  tidal: ['tidal.com'],
  bandcamp: ['bandcamp.com'],
  audible: ['audible.com', 'audible.co.uk'],
  plex: ['plex.tv'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  epicgames: ['epicgames.com'],
  playstation: ['playstation.com'],
  ea: ['ea.com'],
  ubisoft: ['ubisoft.com'],
  battledotnet: ['battle.net', 'blizzard.com'],
  riotgames: ['riotgames.com'],
  roblox: ['roblox.com'],
  gogdotcom: ['gog.com'],
  itchdotio: ['itch.io'],
  paypal: ['paypal.com', 'paypal.me'],
  stripe: ['stripe.com'],
  wise: ['wise.com'],
  revolut: ['revolut.com'],
  n26: ['n26.com'],
  monzo: ['monzo.com'],
  klarna: ['klarna.com'],
  venmo: ['venmo.com'],
  cashapp: ['cash.app'],
  visa: ['visa.com'],
  mastercard: ['mastercard.com'],
  americanexpress: ['americanexpress.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
  ebay: ['ebay.com', 'ebay.co.uk', 'ebay.de'],
  etsy: ['etsy.com'],
  aliexpress: ['aliexpress.com'],
  target: ['target.com'],
  ikea: ['ikea.com'],
  zalando: ['zalando.com', 'zalando.de'],
  vinted: ['vinted.com'],
  airbnb: ['airbnb.com'],
  bookingdotcom: ['booking.com'],
  expedia: ['expedia.com'],
  tripadvisor: ['tripadvisor.com'],
  uber: ['uber.com'],
  lyft: ['lyft.com'],
  ubereats: ['ubereats.com'],
  doordash: ['doordash.com'],
  deliveroo: ['deliveroo.com', 'deliveroo.co.uk'],
  ryanair: ['ryanair.com'],
  lufthansa: ['lufthansa.com'],
  strava: ['strava.com'],
  garmin: ['garmin.com'],
  fitbit: ['fitbit.com'],
  samsung: ['samsung.com'],
  xiaomi: ['mi.com', 'xiaomi.com'],
  huawei: ['huawei.com'],
  sony: ['sony.com'],
  dell: ['dell.com'],
  hp: ['hp.com'],
  lenovo: ['lenovo.com'],
  asus: ['asus.com'],
  nvidia: ['nvidia.com'],
  amd: ['amd.com'],
  intel: ['intel.com'],
  autodesk: ['autodesk.com'],
  grammarly: ['grammarly.com'],
  lastpass: ['lastpass.com'],
  bitwarden: ['bitwarden.com'],
  '1password': ['1password.com'],
  nordvpn: ['nordvpn.com'],
  expressvpn: ['expressvpn.com'],
  mullvad: ['mullvad.net'],
  ovh: ['ovh.com', 'ovhcloud.com'],
  hetzner: ['hetzner.com'],
  vodafone: ['vodafone.com', 'vodafone.co.uk', 'vodafone.gr'],
  deutschetelekom: ['telekom.de'],
  orange: ['orange.com', 'orange.fr'],
  verizon: ['verizon.com'],
  atandt: ['att.com'],
  imdb: ['imdb.com'],
  letterboxd: ['letterboxd.com'],
  goodreads: ['goodreads.com'],
  tinder: ['tinder.com'],
  glassdoor: ['glassdoor.com'],
  indeed: ['indeed.com'],
  upwork: ['upwork.com'],
  fiverr: ['fiverr.com'],
  behance: ['behance.net'],
  dribbble: ['dribbble.com'],
  unsplash: ['unsplash.com'],
  flickr: ['flickr.com'],
  vimeo: ['vimeo.com'],
  calendly: ['calendly.com'],
  typeform: ['typeform.com'],
  surveymonkey: ['surveymonkey.com'],
};

const bySlug = new Map(Object.values(icons).filter((i) => i && i.slug).map((i) => [i.slug, i]));
const logos = {};
const domains = {};
const missing = [];
for (const [slug, list] of Object.entries(SITES)) {
  const icon = bySlug.get(slug);
  if (!icon) { missing.push(slug); continue; }
  logos[slug] = { title: icon.title, hex: `#${icon.hex}`, path: icon.path };
  for (const domain of list) {
    if (domains[domain]) throw new Error(`${domain} listed twice`);
    domains[domain] = slug;
  }
}

if (missing.length) throw new Error(`not in simple-icons ${version}: ${missing.join(', ')}`);

const sortKeys = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
const out = JSON.stringify({
  source: `simple-icons ${version} (CC0-1.0)`,
  logos: sortKeys(logos),
  domains: sortKeys(domains),
}) + '\n';

for (const target of [
  'src/localvault/assets/site_logos.json',
  'browser-extension/site-logos.json',
]) {
  mkdirSync(dirname(join(root, target)), { recursive: true });
  writeFileSync(join(root, target), out);
}
const catalog = join(root, 'ios', 'App', 'SiteLogos.xcassets');
const xcodeInfo = { author: 'xcode', version: 1 };
rmSync(catalog, { recursive: true, force: true });
mkdirSync(catalog, { recursive: true });
writeFileSync(join(catalog, 'Contents.json'), JSON.stringify({ info: xcodeInfo }, null, 2) + '\n');
for (const [slug, logo] of Object.entries(logos)) {
  const set = join(catalog, `logo-${slug}.imageset`);
  mkdirSync(set);
  writeFileSync(join(set, `logo-${slug}.svg`),
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path d="${logo.path}"/></svg>\n`);
  writeFileSync(join(set, 'Contents.json'), JSON.stringify({
    images: [{ filename: `logo-${slug}.svg`, idiom: 'universal' }],
    info: xcodeInfo,
    properties: { 'preserves-vector-representation': true, 'template-rendering-intent': 'template' },
  }, null, 2) + '\n');
}

console.log(`${Object.keys(logos).length} logos, ${Object.keys(domains).length} domains, ${out.length} bytes`);
