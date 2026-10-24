# Holding page for localgatekeys.app

Served by the Cloudflare Pages project `localgatekeys-site` until the full
site in `website/` is ready (placeholders filled, legal drafts reviewed).
The full site deploys to the same project and replaces this page.

```powershell
npx wrangler pages deploy cloudflare/holding-page/public --project-name localgatekeys-site --branch main
```

Zone settings this relies on (also needed by the full site): Always Use HTTPS
on, minimum TLS 1.2, and **Email Address Obfuscation off**. Cloudflare's
obfuscation replaces `mailto:` links with a script-decoded placeholder that
the Content-Security-Policy blocks.
