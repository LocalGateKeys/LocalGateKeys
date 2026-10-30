# LocalGateKeys website

A static site: plain HTML and one stylesheet. No JavaScript (except the /buy
checkout page, which loads Paddle.js under its own policy), no cookies, no
analytics, no third-party scripts or fonts. `_headers` sets a Content Security
Policy that blocks scripts and every external origin, so nothing can creep in
unnoticed.

```text
website/
  build.py            builds public/ (Python 3.9+, standard library only)
  site.config.json    values for the {{PLACEHOLDER}} tokens
  i18n/<code>.json    page text per language; templates say [[t:key]]. en.json is
                      the source; each other catalog present is built into
                      public/<folder>/ (de, es, it, pl, zh-hans, ja, pt-br, ko, nl)
                      with hreflang links and a footer language switcher. Legal
                      pages and /buy stay English-only.
  src/layout.html     shared header and footer
  src/pages/          page bodies (Home, Features, Pricing, Security,
                      Get started, Download, Support, Your Pro licence, Buy Pro,
                      Legal index, 404)
  src/static/         styles.css, _headers, robots.txt, sitemap.xml, buy.js,
                      screenshots/, .well-known/security.txt
  public/             build output, committed, deployable as is
docs/legal/*.md       legal drafts, rendered into public/legal/
assets/brand, assets/icons   logo and favicons, copied into public/brand/
```

## Build

```powershell
python website/build.py            # rebuild public/ and list unfilled placeholders
python website/build.py --strict   # same, but exit 1 if any placeholder is unfilled
python website/build.py --langs de # English plus only these languages
python scripts/i18n_check.py       # catalog key and markup parity (website/i18n too)
```

Always rebuild and commit `public/` after editing `src/`, `docs/legal/`, the
config or the brand assets.

## Preview locally

```powershell
python -m http.server 8765 --bind 127.0.0.1 --directory website/public
```

Then open `http://127.0.0.1:8765/`. Opening the HTML files directly also
works, because every link is relative (except on the 404 page).

## Deploy to Cloudflare Pages

The site is live at https://localgatekeys.app (since 2026-10-19). The legal drafts
are not lawyer-reviewed yet (`LEGAL_REVIEW_COMPLETE: false`); `HIDE_DRAFT_NOTES: true`
hides their DRAFT banners and owner notes without claiming a review.

**Option A: Git integration (rebuilds on every push)**

1. Cloudflare dashboard > Workers & Pages > Create > Pages > Connect to Git,
   and pick this repository.
2. Production branch: `main`.
3. Framework preset: None.
4. Build command: `python3 website/build.py --strict`
   (or leave it empty to deploy the committed `public/` as is).
5. Build output directory: `website/public`
6. Save and deploy, then add the custom domain under the project's Custom
   domains tab.

**Option B: Direct upload from your PC**

```powershell
npx wrangler login
npx wrangler pages project create localgatekeys-site --production-branch main
python website/build.py --strict
npx wrangler pages deploy website/public --project-name localgatekeys-site
```

**After the first deploy**

- Add `{{DOMAIN}}` as a custom domain and turn on "Always Use HTTPS".
- Leave Cloudflare Web Analytics, Bot Fight Mode, Zaraz and any other feature
  that injects scripts or sets cookies **off**; the privacy policy promises a
  site without them.
- Check the headers: `curl -I https://{{DOMAIN}}/` should show the
  `Content-Security-Policy` from `_headers`.
- Cloudflare Pages serves `pricing.html` at `/pricing` (and redirects the
  `.html` form there); `404.html` is used for missing pages.
- Renew `Expires` in `.well-known/security.txt` (via `SECURITY_TXT_EXPIRES`)
  before it lapses; RFC 9116 asks for less than a year ahead.

## Placeholders to fill

Set each value in `site.config.json`. Unfilled placeholders stay visible as
`{{NAME}}` and are highlighted in yellow on the pages, and the build lists
them with the pages that use them.

| Placeholder | What it is | Used on |
|---|---|---|
| `COMPANY_NAME` | Seller and licensor: your full name while trading as a sole trader | Footer, all legal pages |
| `COMPANY_ADDRESS` | Registered address of that entity | Legal pages |
| `POSTAL_CODE` | Postal code, used inside `COMPANY_ADDRESS` (values may contain other placeholders) | Legal pages |
| `COPYRIGHT_YEAR` | Footer year (preset to 2026) | Footer |
| `DOMAIN` | Website domain, without `https://` | Canonical links, sitemap, robots.txt, security.txt, privacy policy |
| `CONTACT_EMAIL` | General support address | Footer, support, licence, legal |
| `SECURITY_EMAIL` | Security reports address | Security, download, disclosure policy, security.txt |
| `PRIVACY_EMAIL` | Privacy requests address (can equal `CONTACT_EMAIL`) | Privacy policy |
| `JURISDICTION` | Country or state whose lawyer reviews the drafts and whose courts apply | Legal pages |
| `GOVERNING_LAW` | Governing law of the EULA and terms of sale | EULA, terms of sale |
| `EFFECTIVE_DATE` | Date the legal documents take effect | Legal pages |
| `PRIVACY_EFFECTIVE_DATE` | Date the current privacy policy takes effect | Privacy policy |
| `PRICE` | Pro price, with currency ("US$4.99") | Home, pricing, terms of sale, EULA |
| `LIABILITY_CAP_FREE` | Liability cap for the Free edition, for example "EUR 50" | EULA |
| `MERCHANT_OF_RECORD` | "Paddle" or "Lemon Squeezy" | Pricing, support, licence, legal |
| `MERCHANT_TERMS_URL` | The merchant's buyer terms | Terms of sale |
| `MERCHANT_PRIVACY_URL` | The merchant's privacy policy | Privacy policy |
| `ORDER_LOOKUP_URL` | The merchant's order or receipt lookup page | Licence page |
| `BUY_URL` | Checkout link for Pro; when set, the header gets a "Buy Pro" link | Pricing, home, header |
| `PADDLE_CLIENT_TOKEN` | Paddle client-side token for Paddle.js | Buy Pro |
| `PADDLE_PRICE_ID` | Paddle price of Pro (`pri_...`) | Buy Pro |
| `LICENCE_HOST` | Host of the licence Worker, for example `licenses.{{DOMAIN}}` | Buy Pro, licence page |
| `LICENCE_RETENTION` | How long the licence service keeps issued licences, for example "10 years" | Privacy policy |
| `ORDER_RETENTION` | How long order records are kept, for example "10 years" | Privacy policy |
| `SUPPORT_RETENTION` | How long support emails are kept, for example "2 years" | Privacy policy |
| `LATEST_VERSION` | Current release, for example "0.4.0" | Download |
| `MS_STORE_URL` | Microsoft Store listing | Home, get started, download |
| `MS_STORE_LIVE` | `true` once the Store listing is public; shows the Store buttons instead of "Coming soon" | Home, get started, download |
| `IPHONE_APP_URL` | App Store link of the iPhone app; when set, the App Store button is shown | Home, download, help |
| `INSTALLER_URL` | Direct installer download | Download |
| `INSTALLER_FILENAME` | Installer file name, for the Get-FileHash example | Download |
| `INSTALLER_SHA256` | SHA-256 of that installer | Download |
| `CHROME_STORE_URL` | Chrome Web Store listing (`null` until it exists: "coming soon") | Download, get started |
| `EDGE_ADDONS_URL` | Microsoft Edge Add-ons listing | Download, get started |
| `UPDATE_HOST` | Host of the update feed and revocation list, for example `updates.{{DOMAIN}}` | Privacy policy |
| `SECURITY_TXT_EXPIRES` | RFC 3339 timestamp, under a year ahead, for example `2027-10-01T00:00:00Z` | security.txt, disclosure policy |
| `LEGAL_REVIEW_COMPLETE` | `true` only after a lawyer has approved the drafts; removes the DRAFT banners and owner notes | Legal pages |
| `HIDE_DRAFT_NOTES` | `true` hides the DRAFT banners and owner notes before the review is complete | Legal pages |

The `if:NAME` blocks in the pages (`<!-- if:NAME -->...<!-- else -->...<!-- /if -->`)
show their first branch only when `NAME` is set.

The decisions behind several of these values are listed at the top of each
draft in `docs/legal/`, and the cross-cutting ones in `docs/legal/README.md`.

## Copy that depends on the product

The site follows the item-limit licensing model in `docs/LICENSING.md`. Keep these true or change the copy:

- Free has browser and Windows app fill, passkeys, Windows Hello, a recovery
  phrase, imports and backups, for up to 4 live items; items in the trash do
  not count. Sync, two-factor codes and documents (attachments) are Pro
  (`licensing.Feature`); without Pro, existing codes and documents stay usable
  and only adding or changing them, and syncing, are refused.
- Over the limit nothing is taken away: existing items stay usable, editable
  and fillable; only adding is blocked. Imports take the remaining free places.
- Pro is US$4.99 once, with all future updates (licences carry
  `updates_until = 9999-12-31`). No device limit; one licence per person.
- After checkout the buyer lands on the licence page (`/license/<token>` on
  the licence Worker) with the `LGK1-` key, a file and an "Install in
  LocalGateKeys" button (`localgatekeys://install-licence/` link). It is not
  emailed by us. Lost pages are found again at `/recover` (order id + email).
- The licence is also stored inside the encrypted vault, so a restored backup
  restores Pro.
- The revocation list is fetched together with update checks, carries no
  licence identifier, and Strict offline mode stops it.
- The licence embeds the buyer's name and email (privacy policy 5.3).
- Importers are shipped (1Password, Bitwarden, LastPass, Dashlane, Proton Pass,
  KeePass/KeePassXC, Chrome/Edge/Brave, Firefox, Safari, mapped CSV). The
  iPhone app is on the App Store (`IPHONE_APP_URL`); copy says nothing about
  its price. The Android app is not on Google Play yet (the help page says
  "coming soon"), and `site.config.json` has no Mac download link, so the
  download page offers neither.

## The buy page

The licence Worker expects the checkout page to create a random claim token
in the buyer's browser and pass it to the checkout as custom data
(`cloudflare/license-issuer/README.md`). That needs JavaScript and Paddle.js,
which this site's CSP blocks on purpose, so `/buy` (`src/pages/buy.html` and
`src/static/buy.js`) has its own `_headers` rule allowing only Paddle's
origins, and `BUY_URL` points at it.
