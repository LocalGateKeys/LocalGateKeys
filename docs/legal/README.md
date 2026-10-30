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

