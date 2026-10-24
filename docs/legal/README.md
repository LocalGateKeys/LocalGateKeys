# Legal drafts

**Every document in this folder is a DRAFT.** None has been reviewed by a
lawyer. Each must be reviewed and adapted by a lawyer qualified in
{{JURISDICTION}} before it is published, linked from the app or a store
listing, or relied on.

| File | Rendered at | Covers |
|---|---|---|
| [eula.md](eula.md) | `/legal/eula` | Free (4 items) and Pro (unlimited) licence, lifetime updates, revocation, no warranty, liability cap |
| [privacy-policy.md](privacy-policy.md) | `/legal/privacy` | Apps collect nothing; website without cookies or analytics; update-check and revocation-list requests; merchant of record; iOS "Data Not Collected" |
| [terms-of-sale.md](terms-of-sale.md) | `/legal/terms-of-sale` | Merchant of record, price and tax, delivery, withdrawal rights |
| [refund-policy.md](refund-policy.md) | `/legal/refunds` | 30-day refund, how to ask, revocation without data loss |
| [vulnerability-disclosure.md](vulnerability-disclosure.md) | `/legal/vulnerability-disclosure` | Reporting, scope, response times, safe harbour |

## How they reach the website

`python website/build.py` renders these Markdown files into
`website/public/legal/`. Two marked blocks in each file control the review
state:

- `<!-- draft-notice -->` ... `<!-- /draft-notice -->`: the DRAFT banner.
- `<!-- owner-decisions -->` ... `<!-- /owner-decisions -->`: the decisions
  the owner must make before review.

While `LEGAL_REVIEW_COMPLETE` is `false` in `website/site.config.json`, both
blocks are shown on the site, highlighted. Set it to `true` only after the
lawyer has signed off; the build then drops both blocks. Placeholders such
as `{{COMPANY_NAME}}` are filled from the same config file.

## Decisions that affect every document

- **Legal entity.** For now the owner trades under their own name as a
  sole trader ({{COMPANY_NAME}}). That means unlimited personal liability
  for anything the EULA cannot exclude; consider insurance now and a limited
  company later. Some countries require a sole trader to show a postal
  address and tax number on the website (for example the German
  *Impressum*); ask the lawyer.
- **Jurisdiction and governing law**: {{JURISDICTION}}; governing law {{GOVERNING_LAW}}.

## Poland: points for the lawyer

The owner is a sole trader in Poland. Points a Polish lawyer should settle:

- **Business registration.** Whether to register a sole proprietorship
  (*jednoosobowa działalność gospodarcza*, CEIDG) or start as unregistered
  activity (*działalność nierejestrowana*) while revenue stays under the
  statutory limit. A registered business must show its NIP (and REGON) with
  the name and address; the Act on providing services by electronic means
  (*ustawa o świadczeniu usług drogą elektroniczną*) requires the provider's
  name, address and email on the site in any case.
- **Polish-language terms.** The Polish Language Act (*ustawa o języku
  polskim*) requires consumer-facing terms in Polish for consumers in Poland.
  Plan Polish versions of the EULA, terms of sale, refund and privacy
  policies, with the Polish text prevailing for Polish consumers.
- **Abusive clauses.** Under Articles 385¹ and 385³ of the Civil Code
  (*klauzule niedozwolone*), clauses that exclude or limit liability to a
  consumer for non-performance are presumed abusive and do not bind the
  consumer. Expect the liability caps in the EULA to be unenforceable
  against Polish (and most EU) consumers; they still help against business
  users and outside the EU.
- **Consumer rights.** The Consumer Rights Act (*ustawa o prawach
  konsumenta*) implements the EU rules on withdrawal and on digital content
  conformity (Directive 2019/770); check sections 6 and 11 against it.
- **Data protection.** Supervisory authority: Prezes UODO. Check the
  retention periods against the Tax Ordinance (*Ordynacja podatkowa*,
  5 years from the end of the tax year) and the accounting rules that apply
  to the chosen business form.
- **Postal code.** Missing from the address ({{POSTAL_CODE}}).
- **Merchant of record**: Paddle or Lemon Squeezy ({{MERCHANT_OF_RECORD}}),
  and alignment with its buyer terms and refund rules.
- **The MIT licence** on the repository conflicts with selling Pro under an
  EULA; see the first decision in [eula.md](eula.md).
- **Update host**: move the update feed from the `workers.dev` subdomain
  (which shows the Cloudflare account name) to a custom domain before launch;
  see [privacy-policy.md](privacy-policy.md).
- **Effective dates** and how changes are announced.
