<!-- summary: The LocalGateKeys apps collect nothing. What this website, update checks, the licence revocation list and Pro purchases involve. -->
<!-- draft-notice -->
> **DRAFT for legal review. Not legal advice. Do not publish as is.** This document was drafted without a lawyer. It must be reviewed and adapted by a lawyer qualified in {{JURISDICTION}} (and, where you sell to them, for the EU/UK GDPR and US state privacy laws) before it is published or relied on.
<!-- /draft-notice -->

# LocalGateKeys Privacy Policy

<!-- owner-decisions -->
## Decisions the owner must make before review

- **Controller identity.** Name, address and, if required, the EU/UK representative of {{COMPANY_NAME}}; a privacy contact ({{PRIVACY_EMAIL}}).
- **Update host.** The domain the app's update checks and revocation list use ({{UPDATE_HOST}}). The current build points at a `workers.dev` subdomain that contains the Cloudflare account name; move the feed to a custom domain such as `updates.{{DOMAIN}}` before launch if that name must not be public, and update this policy.
- **Server logs.** Confirm that Workers logs, Logpush and Cloudflare Web Analytics stay off for the update service and the website, and that Bot Fight Mode or other features that set cookies stay off on the website. If any are turned on, sections 3 and 4 must change.
- **Revocation list behaviour.** Confirm with the implementation how often the list is fetched, that the request contains no licence identifier, and that Strict offline mode stops it.
- **Licence contents.** The licence format (pro-launch branch) embeds the buyer's name and email. Section 5.3 says so. If you drop them from the format, update it.
- **Licence store.** The licence-issuer Worker keeps every issued licence in Cloudflare KV under a retrieval token, with an order index. Decide how long it keeps them ({{LICENCE_RETENTION}}) and whether it deletes them after a refund.
- **What the merchant of record shares.** Confirm with {{MERCHANT_OF_RECORD}} which buyer fields you receive (for example name, email, country, postcode, order ID, VAT ID) and remove the ones you do not.
- **Retention periods** for order records ({{ORDER_RETENTION}}, usually set by tax law) and support emails ({{SUPPORT_RETENTION}}).
- **iPhone crash reports.** Decide whether you will read Apple's opt-in crash reports in App Store Connect. If yes, keep section 7.3; the App Store label can still be "Data Not Collected" only if nothing else is collected.
- **Support tooling.** Which email provider hosts {{CONTACT_EMAIL}} (it processes support emails) and where it stores data.
- **Effective date** ({{EFFECTIVE_DATE}}).
<!-- /owner-decisions -->

Effective date: {{PRIVACY_EFFECTIVE_DATE}}

This policy explains what personal data {{COMPANY_NAME}}, {{COMPANY_ADDRESS}} ("we", "us") processes in connection with the LocalGateKeys software, the website at {{DOMAIN}} and Pro purchases. We are the controller for the processing described here, except where we say another company is.

## 1. Summary

- **The apps collect nothing.** The LocalGateKeys Windows app, browser extension, local browser helper and iPhone app do not send us your vault, usage data, crash reports, analytics or identifiers. There is no account.
- **The website sets no cookies** and uses no analytics, trackers, third-party scripts or third-party fonts.
- **Payments are handled by {{MERCHANT_OF_RECORD}}**, our merchant of record. We never see your card details.
- **Our servers only see ordinary connection data** when the app checks for updates or downloads the licence revocation list, and you can turn both off with Strict offline mode.

## 2. The apps

### 2.1 Your vault

Your vault, attachments, backups and settings are stored on your devices. They are encrypted with keys derived from your master password, which never leaves your device. We do not receive, store or have any way to access them.

### 2.2 No telemetry

The apps contain no telemetry, analytics, advertising identifiers or automatic crash reporting. Error logs are written only to your own device. If you choose to email us a log, we process what you send as described in section 6.

### 2.3 Browser extension

The extension communicates only with the LocalGateKeys app on the same computer, through a local helper program. It does not send page content, browsing history or logins to us or to anyone else. The Chrome Web Store and Microsoft Edge Add-ons may process data about installations under their own privacy policies.

### 2.4 Sync (Pro)

- **Over your home network**, your devices connect to each other directly. The data they exchange is encrypted end to end and does not pass through us.
- **Through your own cloud folder**, the app writes encrypted files to a folder on your device, and your cloud-drive provider (for example Microsoft OneDrive, Dropbox, Google Drive or Proton Drive) uploads them. Your provider can see that the files exist, their size and when they change, but not their contents. Your agreement with that provider governs its processing. We do not receive these files.

### 2.5 Requests to other websites, only if you turn them on

Two optional features make the apps contact services other than ours. Both are off by default, and strict offline mode in the Windows app blocks both.

- **Website icons.** With "Show website icons" turned on, the app downloads each saved website's icon from that website's own address. No username, password or vault data is sent, but each download tells that website, and anyone who can watch your network, that your vault has an account there. The website sees your IP address and the time, under its own privacy policy.
- **Breach checks.** When you start a breach check, the app sends the first five characters of each password's SHA-1 hash to Have I Been Pwned. The service sees your IP address, never the password, the full hash, the username or the website.

We do not receive any of this data.

## 3. Network requests the app makes to us

The app contacts our update service at {{UPDATE_HOST}} in only two cases. Strict offline mode in Settings stops both.

### 3.1 Update checks

When you choose Check for updates (or accept the app's offer to check after a long time offline), the app downloads one small signed file describing the latest version. The request contains:

- your IP address, as for any internet connection;
- the time of the request;
- the address of the file requested;
- the app's user agent, in the form `LocalGateKeys/<version>`, which tells us the version you use.

It contains no account, licence, device or vault identifier, and no cookie. The app does not download or install anything else unless you choose to, in your browser.

### 3.2 Licence revocation list

Together with each update check, the app downloads a signed list of revoked licences and checks your licence against it on your device. The request contains the same connection data as an update check and nothing about your licence. We therefore cannot tell from it which licence, or which customer, made the request.

### 3.3 Who processes this data and for how long

The update service is hosted by Cloudflare, Inc. as our processor. Cloudflare processes connection data to deliver the files and protect the service from abuse, under its data processing addendum. We do not keep our own logs of these requests, and we do not combine them with order data. Cloudflare's own retention of security logs is described in its privacy policy.

Legal basis (where the GDPR applies): our legitimate interest in delivering updates and the revocation list securely (Article 6(1)(f) GDPR), and performing our contract with Pro customers (Article 6(1)(b)).

## 4. This website

The website is a set of static pages hosted on Cloudflare Pages. It sets no cookies and uses no analytics, advertising, tracking pixels, social media plugins, third-party scripts or externally hosted fonts.

The one exception is the checkout page (`/buy`). It loads {{MERCHANT_OF_RECORD}}'s checkout script and payment form from {{MERCHANT_OF_RECORD}}'s servers, so that you can pay. {{MERCHANT_OF_RECORD}} processes what you enter there, and may use cookies or similar technology needed for the payment and to prevent fraud, under its own privacy policy: {{MERCHANT_PRIVACY_URL}}. The page also creates a random code in your browser that links your payment to your licence page (section 5.4). It is kept only in that browser tab and sent only to {{MERCHANT_OF_RECORD}} and our licence service.

When you visit, Cloudflare, Inc. processes your IP address, browser user agent, the pages you request and the time, as our processor, in order to deliver the pages and protect the site against attacks. We do not use this data to identify or profile visitors. Legal basis: legitimate interests (Article 6(1)(f) GDPR).

Links to the Microsoft Store, Chrome Web Store, Edge Add-ons, App Store and {{MERCHANT_OF_RECORD}} take you to other companies' websites, which have their own privacy policies.

## 5. Purchases

### 5.1 The merchant of record

Pro is sold by {{MERCHANT_OF_RECORD}}, which acts as the reseller and merchant of record. {{MERCHANT_OF_RECORD}} collects your payment details, billing information and tax information, processes the payment, calculates and remits tax and issues receipts and invoices. It is the controller of that data under its own privacy policy: {{MERCHANT_PRIVACY_URL}}. We never receive your full card or bank details.

### 5.2 What we receive

To issue and support your licence, {{MERCHANT_OF_RECORD}} gives us:

- your name and email address;
- your country (and postcode, where required for tax);
- your order number, product, price, tax, currency and date;
- your VAT ID, if you entered one;
- refund and chargeback status.

We use this data to generate and send your Licence File, resend it if you lose it, answer your questions, process refunds and revocations, prevent fraud and keep the records required by tax and accounting law.

Legal bases: performance of a contract (Article 6(1)(b) GDPR), legal obligations (Article 6(1)(c)) and legitimate interests in preventing fraud (Article 6(1)(f)).

### 5.3 The Licence File

Your licence contains a random licence ID, the edition, your name, your email address and the date it was issued, signed by us. Your name and email are included so that a licence can be traced to its buyer if it is shared. The licence is stored on your devices (also inside your encrypted vault) and checked there. The app never sends it to us.

### 5.4 Issuing and retrieving your licence

After payment, {{MERCHANT_OF_RECORD}} notifies our licence service, which runs on Cloudflare Workers. The service asks {{MERCHANT_OF_RECORD}} for your name and email address, creates your licence, and stores it in Cloudflare's key-value storage under a random link that only your browser knows, so the page you are sent to after checkout can show it. We keep issued licences there for {{LICENCE_RETENTION}} so we can show or resend them, and an index from your order number to the licence so the same order is never issued twice. A separate record in Cloudflare's D1 database links that random link to your order number and licence ID, so one link can only ever show one order's licence; it holds no name, email or payment details and is kept as long as the licence.

### 5.5 Retention

We keep order records for {{ORDER_RETENTION}}, as required by tax and accounting law, and then delete them. Revoked licence IDs stay on the revocation list for as long as the licence could otherwise be used; the list contains licence IDs only, not names or email addresses.

## 6. Support emails

If you email us, we process your email address, your message and anything you attach, in order to answer you. The email is processed by our email provider as our processor. We keep support emails for {{SUPPORT_RETENTION}} after the conversation ends. Please never send your master password, recovery phrase, vault file or unencrypted backups.

Legal basis: legitimate interests in answering your request (Article 6(1)(f) GDPR), or performance of a contract if you are a customer (Article 6(1)(b)).

## 7. iPhone app

7.1 The LocalGateKeys iPhone app, when released, collects no data. Its App Store privacy label is "Data Not Collected". It syncs only with your own Windows PC, over your own network, or through your own cloud folder.

7.2 Apple processes data about your App Store download and purchases under Apple's privacy policy. We receive only aggregated, non-identifying download and sales reports from Apple.

7.3 If you choose to share analytics with app developers in your iPhone settings, Apple may provide us with crash reports that do not identify you. We use them only to fix bugs.

## 8. Sharing

We do not sell or rent personal data, and we do not share it for advertising. We share it only with:

- {{MERCHANT_OF_RECORD}}, for orders and refunds;
- Cloudflare, Inc., which hosts the website, the update service and the licence service;
- our email provider, for support;
- professional advisers and authorities, where required by law.

## 9. International transfers

Cloudflare, {{MERCHANT_OF_RECORD}} and our email provider may process data outside your country, including in the United States. Where the GDPR applies, these transfers are protected by an adequacy decision (such as the EU-US Data Privacy Framework, where the recipient is certified) or by the European Commission's standard contractual clauses.

## 10. Your rights

Depending on where you live, you may have the right to access, correct, delete, restrict or object to the processing of your personal data, to data portability, and to withdraw consent. To exercise these rights, email {{PRIVACY_EMAIL}}. We may ask you to confirm you control the email address on an order.

Because the apps do not send us your vault or usage data, we hold no such data to give you, correct or delete. Your vault is under your control on your devices.

You have the right to complain to a data protection supervisory authority, in particular in the country where you live or work. Our lead authority is the President of the Personal Data Protection Office in Poland (Prezes Urzędu Ochrony Danych Osobowych, uodo.gov.pl).

## 11. Children

LocalGateKeys is not directed at children under 16, and we do not knowingly sell to them.

## 12. Security

We protect the data we hold (order records and support email) with access control and two-factor authentication on the accounts that store it. Licence files and update manifests are signed with keys that are not stored on the servers that publish them.

## 13. Changes

We will post any changes to this policy on this page and update the effective date. If a change affects what the apps send, we will also describe it in the release notes before that version is released.

## 14. Contact

{{COMPANY_NAME}}, {{COMPANY_ADDRESS}}. Privacy questions: {{PRIVACY_EMAIL}}.
