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
  src/layout.html     shared header and footer
  src/pages/          page bodies (Home, Features, Pricing, Security,
                      Download, Support, Find your licence, Legal index, 404)
  src/static/         styles.css, _headers, robots.txt, sitemap.xml,
                      .well-known/security.txt
  public/             build output, committed, deployable as is
docs/legal/*.md       legal drafts, rendered into public/legal/
assets/brand, assets/icons   logo and favicons, copied into public/brand/
```

## Build

```powershell
python website/build.py            # rebuild public/ and list unfilled placeholders
python website/build.py --strict   # same, but exit 1 if any placeholder is unfilled
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

Do this only after the placeholders are filled and the legal drafts have been
reviewed (`LEGAL_REVIEW_COMPLETE: true`).

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
| `PRICE` | Pro price, with currency ("US$4.99") | Home, pricing, terms of sale, EULA |
| `LIABILITY_CAP_FREE` | Liability cap for the Free edition, for example "EUR 50" | EULA |
| `MERCHANT_OF_RECORD` | "Paddle" or "Lemon Squeezy" | Pricing, support, licence, legal |
| `MERCHANT_TERMS_URL` | The merchant's buyer terms | Terms of sale |
| `MERCHANT_PRIVACY_URL` | The merchant's privacy policy | Privacy policy |
| `ORDER_LOOKUP_URL` | The merchant's order or receipt lookup page | Licence page |
| `BUY_URL` | Checkout link for Pro | Pricing |
| `LICENCE_RETENTION` | How long the licence service keeps issued licences, for example "10 years" | Privacy policy |
| `ORDER_RETENTION` | How long order records are kept, for example "10 years" | Privacy policy |
| `SUPPORT_RETENTION` | How long support emails are kept, for example "2 years" | Privacy policy |
| `LATEST_VERSION` | Current release, for example "0.4.0" | Download |
| `MS_STORE_URL` | Microsoft Store listing | Download |
| `INSTALLER_URL` | Direct installer download | Download |
| `INSTALLER_FILENAME` | Installer file name, for the Get-FileHash example | Download |
| `INSTALLER_SHA256` | SHA-256 of that installer | Download |
| `CHROME_STORE_URL` | Chrome Web Store listing | Download |
| `EDGE_ADDONS_URL` | Microsoft Edge Add-ons listing | Download |
| `UPDATE_HOST` | Host of the update feed and revocation list, for example `updates.{{DOMAIN}}` | Privacy policy |
| `SECURITY_TXT_EXPIRES` | RFC 3339 timestamp, under a year ahead, for example `2027-10-01T00:00:00Z` | security.txt, disclosure policy |
| `LEGAL_REVIEW_COMPLETE` | `true` only after a lawyer has approved the drafts; removes the DRAFT banners and owner notes | Legal pages |

The decisions behind several of these values are listed at the top of each
draft in `docs/legal/`, and the cross-cutting ones in `docs/legal/README.md`.

## Copy that depends on the product

The site follows licensing revision 2 (`docs/superpowers/specs/2026-10-15-licensing-design.md`
on the `pro-launch` branch). Keep these true or change the copy:

- Free has every feature, including sync and Windows app fill, for up to 4
  live items; items in the trash do not count.
- Over the limit nothing is taken away: existing items stay usable, editable
  and fillable; only adding is blocked. Imports take the remaining free places.
- Pro is US$4.99 once, with all future updates (licences carry
  `updates_until = 9999-12-31`). No device limit; one licence per person.
- After checkout the buyer lands on the licence page (`/license/<token>` on
  the licence Worker) with the `LGK1-` key and a file. It is not emailed by us.
- The licence is also stored inside the encrypted vault, so a restored backup
  restores Pro.
- The revocation list is fetched together with update checks, carries no
  licence identifier, and Strict offline mode stops it.
- The licence embeds the buyer's name and email (privacy policy 5.3).
- Importers are "in development" in the FAQ; the iPhone app is "coming"
  with its pricing undecided, so copy says nothing about its price.

## The buy button needs its own page

The licence Worker expects the checkout page to create a random claim token
in the buyer's browser and pass it to the checkout as custom data
(`cloudflare/license-issuer/README.md` on `pro-launch`). That needs
JavaScript and the payment provider's checkout script, which this site's CSP
blocks on purpose. Build `/buy` as a separate page with its own `_headers`
rule allowing only that provider's script origin, and point `BUY_URL` at it.
