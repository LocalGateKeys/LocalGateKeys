# Holding page for localgatekeys.app

**Retired.** The full site in `website/` is live on the Cloudflare Pages project
`localgatekeys-site`. Do not deploy this folder to branch `main`: that would
replace the whole website with the holding page. If it is ever needed again
(for example during an outage), deploy it to a preview branch first:

```powershell
cd cloudflare/license-issuer; npm ci   # once: installs the pinned wrangler
npx wrangler pages deploy ../holding-page/public --project-name localgatekeys-site --branch holding-preview
```

Zone settings this relies on (also needed by the full site): Always Use HTTPS
on, minimum TLS 1.2, and **Email Address Obfuscation off**. Cloudflare's
obfuscation replaces `mailto:` links with a script-decoded placeholder that
the Content-Security-Policy blocks.
