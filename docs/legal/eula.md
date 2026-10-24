<!-- summary: The licence agreement for LocalGateKeys Free and Pro: what you may do, lifetime updates for Pro, warranty and liability. -->
<!-- draft-notice -->
> **DRAFT for legal review. Not legal advice. Do not publish as is.** This document was drafted without a lawyer. It must be reviewed and adapted by a lawyer qualified in {{JURISDICTION}} before it is published, linked from the app or the store listings, or relied on.
<!-- /draft-notice -->

# LocalGateKeys End User Licence Agreement

<!-- owner-decisions -->
## Decisions the owner must make before review

- **Source licence conflict.** The repository is currently published under the MIT licence (`LICENSE`). MIT lets anyone use, modify and redistribute the code, including a build without the item limit, for free. Decide before launch whether to (a) relicense the code you own (for example to a proprietary or source-available licence) for future releases, (b) keep MIT and accept that Pro is sold on convenience and support, or (c) split Free (MIT) and Pro (proprietary) code. Sections 3, 4 and 7 assume the binaries are distributed under this agreement; they must be rewritten if MIT remains for everything. Code already released under MIT stays MIT for whoever received it.
- **Legal entity.** The owner has chosen, for now, to trade under their own name as a sole trader ({{COMPANY_NAME}}). A sole trader is personally liable without limit for anything this Agreement cannot exclude; the caps in section 12 protect only as far as the law allows them. Revisit a limited company before revenue or user numbers grow, and ask the lawyer whether your country requires a trading address and tax number on the site.
- **Insurance.** Consider professional indemnity or product liability insurance that covers software and data loss; it covers what section 12 cannot exclude.
- **Product liability.** The EU Product Liability Directive (EU) 2024/2853 applies to software placed on the market from 9 December 2026. It makes the producer liable, without fault, for destruction or corruption of data that is not used for professional purposes, and it cannot be excluded by contract (section 12.4). Ask the lawyer how it applies to the Free edition, to updates and to your country's implementing law.
- **Acceptance at install.** Make the installer and the Microsoft Store listing require acceptance of this Agreement (a checkbox in the installer, the EULA field in Partner Center). Terms accepted at install are far easier to enforce than a link on the website.
- **Device use.** This draft lets one person use Pro on all Devices they use, with no number limit (the app does not count devices), and does not allow household sharing. Confirm.
- **Commercial use of Free.** Whether businesses may use the Free edition at no cost (this draft says yes).
- **What "all future updates" means.** Pro is sold once and includes every future update (section 4.2). That promise covers future major versions too, so you cannot later charge existing Pro customers for a "version 2" without breaking it. If you might ever want paid major upgrades, say so now (for example "all updates to LocalGateKeys 1.x"); changing it after selling would be unfair to buyers. The draft also makes clear that you do not promise to keep developing forever (section 10).
- **Revocation.** Confirm the reasons for revocation (refund, chargeback, fraud, licence leak) and that revocation never touches vault data: the 4-item limit returns, existing items stay usable.
- **iPhone app.** If the iPhone app ever enforces the item limit, App Store rule 3.1.1 requires an in-app purchase as well as the outside purchase. This Agreement would then need an App Store section.
- **Transfer and resale.** In the EU, the resale of a perpetual software licence may be permitted by law (CJEU, UsedSoft, C-128/11). Decide whether to allow transfer with notice instead of prohibiting it.
- **Liability caps.** Pro: the amount paid for the licence ({{PRICE}}). Free: {{LIABILITY_CAP_FREE}}. Caps this low may be found unreasonable for consumers in some countries; ask the lawyer whether a higher floor (for example USD 50) makes them more likely to hold.
- **Governing law and courts** ({{GOVERNING_LAW}}, {{JURISDICTION}}), and how consumer protections of the user's country of residence are preserved.
- **Mandatory consumer rights.** EU Directive 2019/770 (digital content) gives consumers conformity and update rights that cannot be excluded. The lawyer must adapt sections 10 and 11 so they do not purport to exclude them.
- **Effective date** ({{EFFECTIVE_DATE}}) and how changes are notified (website notice, in-app notice on update).
<!-- /owner-decisions -->

Effective date: {{EFFECTIVE_DATE}}

This End User Licence Agreement ("Agreement") is between you and {{COMPANY_NAME}}, {{COMPANY_ADDRESS}} ("we", "us"). It applies to the LocalGateKeys software for Windows, its browser extension, its local browser helper and, when available, the LocalGateKeys iPhone app (together, the "Software"). By installing or using the Software you accept this Agreement. If you do not accept it, do not install or use the Software.

## 1. Plain-language summary

This summary is for convenience; the numbered sections below are what apply.

- The Free Edition has no time limit and holds up to 4 items in your vault. Device sync, two-factor codes and attachments are Pro Features.
- Pro removes the item limit. It is a one-time purchase that includes all future updates. There is no subscription and nothing to renew.
- Your vault stays on your devices. We cannot see it, recover it or reset your master password.
- **Keeping your vault safe and backed up is your responsibility.** If you lose your master password, your recovery phrase and your backups, your vault cannot be recovered by anyone, and we are not responsible for that loss.
- **We never receive your vault, so we cannot leak it.** The security of your devices, your browser and the cloud services you choose is outside our control and our responsibility.
- **Breaches of websites and services you use are not our responsibility**, and neither is losing access to an account, unless a defect in the Software that we failed to fix caused it (sections 1A.6 and 1A.7).
- The Software is provided without warranties, to the extent the law allows, and **our liability is limited to the price you paid** (section 12).
- Some consumer rights cannot be excluded by any agreement. Where they apply, this Agreement does not take them away.

## 1A. Important: your data and backups

**Please read this section carefully. It applies to every edition.**

1A.1 **You hold the only keys.** Your vault is encrypted with keys derived from your master password and, if you create one, your recovery phrase. We never receive either, so we cannot open, recover or reset your vault, and we cannot restore it from any copy of ours, because we have none.

1A.2 **Back up.** Turn on scheduled backups, keep at least one backup on a separate device or drive, write down your backup password, and create and store your recovery phrase offline. Check from time to time that you can open a backup.

1A.3 **Losses we are not responsible for.** To the extent permitted by law, we are not responsible for any loss, corruption or unavailability of your vault, attachments, backups or synced copies, or for any loss that follows from it (such as being locked out of accounts), where it is caused by:

- a forgotten or lost master password, recovery phrase or backup password;
- not making, keeping or testing backups;
- failure, loss, theft, repair or reset of your Device or storage;
- malware, another person with access to your Device, or anyone with administrator control of it;
- your browser, operating system or other software, or the conduct of your cloud-drive, email or other service providers;
- deleting, moving or editing vault or backup files outside the Software;
- not installing an update that fixes a problem we have told you about.

1A.4 **Privacy and security incidents.** We do not receive, host or process the contents of your vault. To the extent permitted by law, we are not responsible for the disclosure, misuse or loss of credentials or other information stored in or filled by the Software where it results from the circumstances in section 1A.3, from a website or app you choose to fill credentials into, from phishing, or from a third-party service. The data we do process, such as order and support records, is covered by our [privacy policy](privacy-policy.md).

1A.5 **Not audited.** The Software has not yet been independently security-audited. Do not rely on it as the only copy of credentials you cannot afford to lose.

1A.6 **Breaches of other services.** The websites, apps and online accounts whose credentials you keep in the Software are run by other companies. If one of them is breached, leaks your password, locks your account or loses your data, that is the responsibility of that company, not ours, even if the credentials for it were stored in or filled by the Software.

1A.7 **Lost or locked accounts.** To the extent permitted by law, we are not responsible for losing access to any online account, for an account being taken over, or for anything that follows from it (such as lost money, lost data, lost business or the cost of recovering the account), unless it was caused by a defect in the Software that we failed to fix within a reasonable time after we knew about it. This includes accounts protected by one-time codes (2FA) stored in the Software: keep the account's own backup codes somewhere outside the Software.

1A.8 **Your choice to rely on the Software.** You decide which credentials to store in the Software, where to fill them and whether to keep other copies. A password manager reduces some risks but cannot remove them. You use the Software at your own risk, to the extent the law allows us to say so.

1A.9 **Business users.** If you use the Software for a business, trade or profession (and not as a consumer), sections 11 and 12 apply in full, we are not liable for any loss of data, accounts, profits, revenue or business however caused, except where we caused it intentionally, and you are responsible for your own staff, devices, backups and security policies.

## 2. Definitions

- **"Free Edition"** means the Software without a valid Licence File. It allows no more than 4 live items in a vault (items in the trash do not count) and does not include the Pro Features.
- **"Pro Edition"** means the Software with a valid Licence File, which removes the item limit and includes the Pro Features.
- **"Pro Features"** means device sync (over your network or through a cloud folder), adding or changing two-factor (one-time) codes, and adding or replacing attachments (documents).
- **"Licence File"** means the digitally signed licence we issue to you after you buy Pro, whether as a licence key (beginning `LGK1-`) or as a file.
- **"Purchase Date"** means the date shown in your Licence File.
- **"Device"** means a Windows computer that you own or control.

## 3. Free Edition licence

Subject to this Agreement, we grant you a free, non-exclusive, non-transferable, worldwide licence to install and use the Free Edition on any number of Devices, for personal or business purposes.

The item limit only stops new items from being added. If a vault holds more than 4 items without a valid Licence File (for example after an upgrade from an older version, after a sync, or after a licence is revoked), every existing item remains usable, editable and fillable.

Without a valid Licence File, device sync does not run and you cannot add or change two-factor codes or add or replace attachments. Two-factor codes, attachments and synced data already in a vault stay usable, viewable and exportable, and you can remove them.

## 4. Pro Edition licence

4.1 **Grant.** When you buy Pro and we issue a Licence File, we grant you a non-exclusive, worldwide, perpetual licence to use the Pro Edition of the Software on the Devices that you personally use.

4.2 **All future updates included.** Your one-time payment covers every version of the Software that we release in the future, including new major versions. You will not be asked to pay again to keep Pro in a newer version.

4.3 **Perpetual use.** Your licence does not expire, unless this Agreement is terminated under section 13 or your Licence File is revoked under section 5.3.

4.4 **One person.** A Pro licence is for one individual. A business that buys Pro for its staff needs one licence per person who uses it.

## 5. Licence File and checks

5.1 **No account, no activation server.** The Software checks the Licence File on your Device using a public key built into the Software. It does not contact us to activate. Once entered, a copy of the Licence File is kept inside your encrypted vault, so restoring the vault or a backup of it restores Pro. Enter your Licence File on each PC you use; on the Free Edition, sync does not carry it to another PC.

5.2 **Revocation list.** Together with each update check, the Software downloads a signed list of revoked licences from our update service and compares it with your Licence File on your Device. The request does not include your Licence File or any identifier from it. The [privacy policy](privacy-policy.md) describes what our servers can see.

5.3 **Revocation.** We may revoke a Licence File if the purchase is refunded or charged back, if the payment was fraudulent, or if the Licence File has been shared or published in breach of this Agreement. When a Licence File is revoked, the Free Edition applies again the next time the Software reads the revocation list. Revocation never deletes, locks or alters your vault or its data: every existing item stays usable, and existing two-factor codes and attachments stay viewable and exportable.

5.4 **Keep it safe.** Keep your Licence File private. Do not share it or publish it.

## 6. Restrictions

Except as permitted by law or by the licences of open-source components (section 7), you must not:

- share, sell, rent or publish your Licence File, or let others use it;
- remove, bypass or tamper with the licence check, the revocation check or the update signature check;
- create or distribute Licence Files or tools that remove the item limit without a valid Licence File;
- remove copyright or licence notices from the Software;
- use the Software in breach of applicable law.

## 7. Open-source components

The Software includes open-source components that are licensed to you under their own licences, listed in the Software's licence notices and its software bill of materials. Nothing in this Agreement limits your rights under those licences.

## 8. Your data and your responsibilities

8.1 Your vault, backups and synced copies are stored only on your Devices and in storage you choose, such as your own cloud-drive folder. We do not receive, store or have access to them.

8.2 You are responsible for remembering your master password, keeping your recovery phrase and backup passwords safe and making backups, as described in section 1A.

8.3 You are responsible for the security of your Devices. The Software is not designed to protect against malware or other people who control your Device; see the security model on our website.

## 9. Third-party services

The Software works with products of other companies, such as Microsoft Windows, Google Chrome, Microsoft Edge, Apple iOS and cloud-drive services. Their terms apply to your use of them. If you obtained the Software from the Microsoft Store or Apple App Store, that store's terms also apply, and where they conflict with this Agreement in respect of the store, the store's terms prevail.

## 10. Updates and support

10.1 We make updates available as and when we release them, at no extra charge for Pro customers. We do not promise a particular number or frequency of updates, particular new features, or that we will continue to develop the Software indefinitely. If we stop development, the versions you already have keep working, including Pro.

10.2 We aim to release fixes for security vulnerabilities that we confirm in the latest version. We may stop maintaining older versions.

10.3 The Software never installs updates by itself. You decide when to install them.

10.4 We provide support by email on a reasonable-effort basis. We will never ask for your master password, recovery phrase or vault.

## 11. Warranty disclaimer

**To the extent permitted by law, the Software is provided "as is" and "as available", without warranties of any kind, express or implied, including warranties of merchantability, fitness for a particular purpose, non-infringement, and that the Software will be error-free, secure, uninterrupted or compatible with any particular website, app or device, or that it will prevent any loss of data or unauthorised access.**

The Software has not been independently audited. You should keep backups of your vault and not rely on the Software as the only copy of important credentials.

If you are a consumer, you have legal rights in relation to digital content and services that this section does not affect. Nothing in this Agreement excludes those rights.

## 12. Limitation of liability

12.1 **To the extent permitted by law, we are not liable for any indirect, incidental, special or consequential loss, or for loss or corruption of data, loss of access to accounts, loss of profits, revenue, business or goodwill, arising from or related to the Software, however caused, including the losses described in section 1A.**

12.2 **To the extent permitted by law, our total liability arising from or related to the Software, whether in contract, tort (including negligence) or otherwise, is limited to:**

- **for the Pro Edition, the amount you paid for your Pro licence;**
- **for the Free Edition, {{LIABILITY_CAP_FREE}}.**

12.3 Where liability for loss of data cannot be excluded, we are liable only for the cost of restoring the data from a backup that you could reasonably have been expected to make under section 1A.2.

12.4 Nothing in this Agreement limits or excludes liability for death or personal injury caused by negligence, for fraud or fraudulent misrepresentation, for gross negligence or wilful misconduct, under mandatory product liability law (including laws implementing Directive (EU) 2024/2853), or any other liability that cannot be limited or excluded by law. If you are a consumer, your statutory rights are not affected.

## 13. Termination

13.1 You may stop using the Software at any time and uninstall it. Uninstalling does not delete your vault unless you choose to.

13.2 This Agreement ends automatically if you materially breach it, for example by distributing Licence Files or tools to bypass the licence check. If it ends, you must stop using the Pro Edition. Your vault data remains yours.

13.3 Sections 1A, 7, 8, 11, 12, 14 and 15 survive termination.

## 14. Governing law and disputes

This Agreement is governed by the laws of {{GOVERNING_LAW}}. The courts of {{JURISDICTION}} have jurisdiction, except that if you are a consumer you keep the protection of the mandatory laws of your country of residence and may bring proceedings in the courts there.

## 15. General

15.1 **Changes.** We may update this Agreement for future versions of the Software. The version that applies to a version of the Software is the one shipped with it, and a change never takes away Pro or updates you have already paid for. We will describe material changes in the release notes.

15.2 **Entire agreement.** This Agreement, together with the [terms of sale](terms-of-sale.md) for purchases, is the entire agreement between you and us about the Software.

15.3 **Severability.** If any part of this Agreement is found unenforceable, the rest remains in effect.

15.4 **No waiver.** Not enforcing a right is not a waiver of it.

15.5 **Assignment.** You may not assign this Agreement without our written consent, except where the law gives you that right. We may assign it to a successor of our business, provided your rights under it are not reduced.

## 16. Contact

{{COMPANY_NAME}}, {{COMPANY_ADDRESS}}. Email: {{CONTACT_EMAIL}}.
