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

## Moving from another password manager

An empty vault shows an **Import your passwords** card on Windows, iPhone and
Android. **Import** opens the import page; **Not now** hides the card on that
device. It goes away by itself once the vault has an item.

**1. Export from your old app.** The menu names below are the ones the
importers were checked against; apps rename menus between versions, so if a
step does not match, look for *Export* in the app's settings or main menu.

- **Bitwarden**: *Tools > Export vault*, format **.json** (or **.json
  (Encrypted)** with **Password protected**).
- **1Password 8**: *File > Export*, pick the account, format **1PUX** (or CSV).
- **LastPass**: *Advanced options > Export*, or in the browser extension
  *Account > Fix a problem yourself > Export vault items*. You get a CSV.
- **Dashlane**: *Settings > Export data > Export to CSV*. You get a zip of
  CSV files; import the zip or one CSV from it.
- **KeePass 2 / KeePassXC**: no export needed, open the `.kdbx` file directly
  (KeePass XML or CSV also work).
- **Proton Pass**: *Settings > Export*, turn **off** "Encrypt with PGP",
  format JSON (zip) or CSV.
- **Chrome / Edge / Brave**: *Settings > Passwords (Password Manager) > Export
  passwords*. You get a CSV.
- **Firefox**: *Passwords* (`about:logins`) *> ⋯ > Export passwords*. You get
  a CSV.
- **Apple Passwords**: on iOS 26 or macOS 26, nothing to save: choose
  **Export Data to Another App** in the Passwords app and pick LocalGateKeys.
  On older systems, export a CSV (Safari on a Mac: *File > Export > Passwords*).
- **Anything else**: export a CSV; LocalGateKeys asks which column is which
  when it does not recognise the headings.

**2. Import into LocalGateKeys.**

- **Windows**: the card's **Import**, or **Import & export > Import passwords
  & items…**, then pick the file (see [The three steps](#the-three-steps)).
- **iPhone**: the card's **Import**, or **Settings > Import & Export** (see
  [On the iPhone](#on-the-iphone)).
- **Mac**: the **Import & export** page in the sidebar (see
  [On the Mac](#on-the-mac)).
- **Android**: Settings > **Import from another app** > Import from a file (the card opens it): Chrome,
  Edge, Brave, Apple Passwords, Firefox, Bitwarden (also password-protected), 1Password (.1pux) or any
  CSV. LastPass, KeePass, Proton Pass, Dashlane and 1Password CSV files are imported on the PC or Mac.

If you use LocalGateKeys on more than one device, import on one of them and
let sync bring the items to the others, so nothing is imported twice.

**3. Delete the export file** afterwards; most exports are plain text.

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

## Two-factor codes from a QR code (Windows)

Two-factor (2FA) codes are part of LocalGateKeys Pro. On the free plan,
scanning a 2FA code opens the upgrade screen.

Open **Tools > Scan QR code** in the sidebar, **New item > Scan QR code**, or
type *scan* in the command palette (Ctrl+K). The Scan sheet opens beside the
list and offers three ways in:

- **Paste screenshot**: press Win+Shift+S, select the QR code on screen, then
  press Ctrl+V in the sheet.
- **Choose image…**: pick a PNG, JPEG or BMP picture of the code (a photo or a
  saved screenshot). You can also drag the picture onto the sheet.
- **Use webcam**: hold the code up to the camera.

The picture is read in memory only. It is never saved, uploaded or logged,
and LocalGateKeys checks its type and size again before decoding it.

What happens next depends on the code:

- **One site's 2FA setup code** (`otpauth://`): if a login looks like it
  belongs to the code (same name or website), pick it; otherwise choose
  **New login**. **Open in editor** opens that login with the key already
  filled in, or a new login with the title and username filled in. Nothing is
  saved until you press **Save**.
- **A Google Authenticator export** (*Transfer accounts > Export*): every
  account is listed with a tick box. For each ticked account choose **New
  login** (and type its website) or a matching login to add the key to, then
  press **Add**. Everything is added in one step, like a file import: an
  account whose website and username are already in your vault is skipped
  rather than doubled, and nothing is written if anything fails. A login is
  chosen for you only when its name and username match the account exactly;
  if a chosen login already has a 2FA code, LocalGateKeys asks before
  replacing it. If you already have a login for a site, use **Add to existing
  login**. New logins get a generated password, the tag `needs-password` and a
  note saying so; change the password to your real one afterwards. Password
  health leaves these placeholder passwords out of weak and reuse scoring and
  breach checks. A single scan holds at most 256 accounts. If a picture holds
  several QR codes, only the first is read and the sheet says so. A large
  export is split over several codes: the sheet says *Code 1 of 3 scanned*;
  show the next code and the accounts are added to the same list.

In a login's editor the 2FA section offers the same picture options
(**Choose image…**, drag and drop, Ctrl+V and **Scan with camera**).

## On the iPhone

Open Settings, then Import & Export.

- **From Apple Passwords (iOS 26 or later).** In the Passwords app, open the menu, choose "Export Data to
  Another App", then pick LocalGateKeys. Logins, 2FA codes and passkeys come across (passkeys with P-256
  keys only). On older iOS the app says "Needs iOS 26. Use a CSV file instead."
- **From a file.** Choose "Import from a file" and pick the export in Files: Apple Passwords, Chrome,
  Edge, Firefox, Bitwarden (also password-protected), 1Password (.1pux or CSV), LastPass, Dashlane,
  KeePass (.kdbx, XML or CSV), Proton Pass or any CSV. KeePass and protected Bitwarden files ask for
  their password. You review every row before anything is saved.
- Importing the same file again adds nothing; the result says how many were already saved.
- The free plan holds 4 items. Extra items are not stored, and the result says how many are waiting:
  "upgrade to Pro, then import again".
- **Export is free.** "Export encrypted backup" asks for a password of at least 12 characters, typed
  twice. It is never stored and can't be recovered, so keep it safe. The `.lgkm` file can be restored in
  the desktop app. "Export as CSV" writes an unencrypted file of logins only (passkeys can't go in a
  CSV); the app warns you before it creates the file.

## On the Mac

Open the **Import & export** page in the sidebar. Everything here is free; only the free plan's item
limit applies, and rows beyond it are marked "Needs Pro".

- **From another password manager.** Choose the export file (the formats in the table above, including
  Bitwarden, 1Password 1PUX and KeePass `.kdbx` 3.1 or 4 with a password; Twofish and key files are
  refused with a message). A review sheet shows each row as new, a duplicate or an update before
  anything is saved. A CSV with unknown columns opens a column-mapping sheet.
- **From Apple Passwords (macOS 26 or later).** Choose "Review the passwords from Apple Passwords":
  logins, 2FA codes and passkeys come across through the same review sheet.
- **Restore a phone backup** (`.lgkm` from the iPhone or Android app). It merges into this vault through
  the review sheet and never wipes it. Items the backup deleted move to Recently deleted, where you can
  restore them; Mac sync handles deletes the same way.
- **Export** an encrypted backup or a CSV, as on the iPhone.

### Full backups and the Recovery centre

The **Recovery centre** page holds full backups of this vault, byte-compatible with the Windows app's
`.lgk` backups: a backup made on the Mac restores on Windows and the other way round. Vault formats 1,
2 and 3 open; the Mac writes format 3. Backups include the Pro licence.

- **Create…** writes the backup and a `.sha256.json` checksum beside it, so choose a folder you can
  write to. **Verify…** checks a backup without restoring it.
- **Restore…** asks for the backup's password and your master password, then replaces this vault.
  First a safety copy of the vault as it was is kept on this Mac. The newest 5 safety copies are kept
  (they are never deleted when you unlock), and **Put back…** restores one. Restoring as a new profile
  comes later, with profiles.
- **Recovery phrase.** Set one on this page to open the vault if you forget the master password.
  Recovering with the phrase turns Touch ID off; turn it on again in Settings. Changing the master
  password or the phrase, or recovering, replaces the vault's local key.

### Scheduled backups

In the Recovery centre, set a frequency (daily or weekly), a time, how many backups to keep, a folder
(the Backups folder on this Mac unless you choose one) and, optionally, a mirror folder such as a cloud
folder. Set a backup password first; it is kept on this Mac sealed under the vault's key, not in the
Keychain.

- Backups run only while the vault is unlocked: at unlock, when the Mac wakes and every 15 minutes. A
  time missed while the Mac slept or the app was closed runs at the next check. A backup that has
  started still finishes and is checked if the vault locks meanwhile; only the mirror copy is skipped.
- Each backup is checked before older ones are removed. A failed backup keeps every older file and is
  tried again after 30 minutes.
- If the folder can no longer be reached, the card says "Choose the backup folder again" and the backup
  never goes anywhere else.

## Restoring a phone backup

Both the Android and iPhone apps write encrypted backup files ending in `.lgkm`,
protected by a backup password you choose on the phone (on the iPhone:
Settings › Import & Export › Export encrypted backup). The desktop app restores
them. On the desktop open **Import &
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
