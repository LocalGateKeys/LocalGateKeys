# Importing from another password manager

LocalGateKeys reads the export files of the common password managers and
browsers. Import never contacts the internet, and nothing is written until you
have reviewed every row.

## The three steps

1. **Export** from your old manager using the steps for your app below. Save
   the file somewhere private, such as your Desktop, not a synced folder.
2. In LocalGateKeys choose **Import & export > Import passwords & items…**
   (or **Import items** from the command palette) and pick the file.
   LocalGateKeys works out the format from the file's contents, so the file
   name does not matter. Encrypted files ask for their password.
3. **Review** the list. New items are set to *Add*. An item that already
   exists in your vault is set to *Skip*; you can change it to:
   - **Replace**: overwrite the vault copy with the imported one;
   - **Merge**: pick which parts to take (name, password, details);
   - **Keep both**: keep your vault copy unchanged and save the imported copy
     as well. For website logins the copy is saved as a secure note called
     "*name* (imported copy)", because a vault holds only one login per
     website and username.

   Choose **Import**. Everything is written in one step, so if you cancel or
   anything fails, nothing is written. Replaced and merged passwords are kept
   in the login's password history.

**Afterwards, delete the export file** and empty the Recycle Bin. Most
exports hold your passwords in plain text.

## How to export from each app

| App | What to export | File you get |
| --- | --- | --- |
| **1Password 8** | *File > Export >* choose the account, format **1PUX** (or **CSV**) | `.1pux` (or `.csv`) |
| **Bitwarden** | *Tools > Export vault*, format **.json**. To keep the file encrypted, choose **.json (Encrypted)**, export type **Password protected**, and type that password into LocalGateKeys. | `.json` |
| **LastPass** | *Advanced options > Export* (in the browser extension: *Account > Fix a problem yourself > Export vault items*) | `.csv` |
| **Chrome, Edge, Brave** | *Settings > Passwords (Password Manager) > Export passwords* | `.csv` |
| **Firefox** | *Passwords (about:logins) > ⋯ > Export passwords* | `.csv` |
| **Safari** (on a Mac) | *File > Export > Passwords* | `.csv` |
| **KeePass 2** | Open the `.kdbx` directly, or *File > Export* as **KeePass XML (2.x)** or CSV | `.kdbx` / `.xml` / `.csv` |
| **KeePassXC** | Open the `.kdbx` directly (password and/or key file), or *Database > Export > CSV* | `.kdbx` / `.csv` |
| **Proton Pass** | *Settings > Export*, turn **off** "Encrypt with PGP", format **JSON** (zip) or **CSV** | `.zip` / `.csv` |
| **Dashlane** | *Settings > Export data > Export to CSV* | `.zip` (or a single `.csv` from inside it) |

Any other CSV file also works: LocalGateKeys asks you which column holds the
name, website, username, password, notes, one-time code and folder.

## What is imported

| Data | What happens in LocalGateKeys |
| --- | --- |
| Website logins | Logins with every website address, username, password, notes, favourite, tags and custom fields |
| One-time codes (TOTP) | Kept on the login, from a secret or an `otpauth://` link. A code LocalGateKeys cannot read is kept as a hidden custom field. |
| Secure notes | Secure notes, with custom fields |
| Payment cards | Payment cards (cardholder, number, expiry, security code, PIN, notes). Other card details go into an "*name* (extra details)" secure note. |
| Identities / addresses | Identities (name, address, email, phone, company, job title, website). ID numbers (passport, social security, licence) and other extras go into an "*name* (extra details)" secure note. |
| Folders, vaults, groups | Notes, cards and identities go into a collection with the same name (created if needed). Logins get the folder name as a tag. |
| Bank accounts, SSH keys, Wi-Fi, API credentials, software licences, aliases | Secure notes that keep every field. Secret fields stay hidden. |

### Nothing is dropped without telling you

- **Logins with no website** (app-only logins such as `android://…`, or no
  address at all) and **logins with no password** become secure notes that
  keep the address, username, password and one-time code.
- **Plain `http://` sites** are saved for `https://`, because LocalGateKeys
  only fills passwords over HTTPS. The review screen lists the rows this
  affected.
- **Card numbers that fail the checksum** and other card data that does not
  fit a payment card are kept as a secure note with hidden fields.
- **Very long notes** that go over the vault's 20,000-character limit carry on
  in custom fields named "Notes (continued 1)", and so on.
- **The same login twice in one export**: if the copies are identical, the
  second is skipped. If the passwords differ, the second is kept as a secure
  note copy. You can change either choice in the review.

### Not imported

- **Items in the trash** or recycle bin of the old manager.
- **Password history** (older passwords) and **KeePass entry history**.
- **Passkeys.** No password manager exports them in a form another app can
  use. Sign in with the password, then register a new passkey. Affected items
  are listed in the review or marked on the item.
- **File attachments** (1Password documents, KeePass attachments). The item
  itself is imported, and the review or the item says a file was left out.
  Save the file from the old app and add it as a document.

## Restoring a phone backup

Once the Android and iPhone apps support backups, they will write a backup file
ending in `.lgkm`, protected by a backup password you choose on the phone. (No
phone app writes backups yet; the desktop can already restore them.) On the
desktop open **Import &
export** and choose **Restore phone backup…**, pick the file, enter the backup
password and review the preview. Nothing changes until you press restore.

- **What is restored:** logins, secure notes, payment cards, identities and
  your Pro licence. Device keys and the sync setup are not in a backup, so a
  restore never pairs or unpairs anything.
- **Pro licence:** a licence in the backup is restored only when it verifies on
  this version of LocalGateKeys (a valid signature, not revoked, covering this
  version). It then makes this computer Pro straight away. On the free plan,
  items beyond the 4-item limit are still held back in that same restore: the
  result says so, and restoring the file again brings them back.
- **Restore merges.** It uses the same rules as sync: new items are added, and
  an item you already have is never overwritten by an older or equal version.
  Items deleted on the phone move to the trash here when sync would remove
  them (the phone's deletion is newer than your copy); the preview and the
  result say how many ("moved to the trash (deleted on the phone)"). Deletions
  of items this computer never had change nothing.
- **Free plan:** the 4-item limit still applies. New items beyond the limit are
  held back, newest first kept, and the preview says how many. Copies made
  when the same item changed on both sides take slots too.
- **Two-factor keys on the free plan:** two-factor codes need Pro, so the key
  is kept as a hidden field named "Two-factor key (needs Pro)" on the item,
  so it is not lost.
- **Wrong password:** after 5 wrong passwords you must wait 30 seconds. A file
  that is damaged, edited or not a LocalGateKeys backup is refused before
  anything changes.
- **A backup made on this computer is refused**, because there is nothing to
  restore from it.
- **Items this version cannot read** (written by a newer app, or damaged) are
  skipped. The preview already leaves them out and says how many, so they never
  take a free slot, and the result repeats the count. If every item was
  skipped, the result says that nothing was restored.

## Files that cannot be imported

| File | What to do |
| --- | --- |
| Bitwarden **account-restricted** encrypted `.json` | Only Bitwarden can open it. Export again as plain **.json**, or as **.json (Encrypted)** with **Password protected**. |
| Proton Pass export **encrypted with PGP** | Export again with "Encrypt with PGP" turned off. |
| 1Password 7 `.1pif` | Export again as **1PUX** or **CSV**. |
| KeePass 1.x `.kdb` | Open it in KeePass 2 and save it as `.kdbx`. |

### Limits

- A text export (CSV, JSON, XML) can be up to 8 MiB. A zip export (1PUX,
  Proton Pass, Dashlane) can be up to 64 MiB.
- Up to 5,000 items per import. Split bigger vaults by folder, or import in
  several passes. Rows that are already in the vault are recognised as
  duplicates.
- Damaged, truncated or edited files are rejected with a message that says so.
  A partial import never happens.
