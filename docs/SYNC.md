# Device sync

Device sync keeps the same logins and notes on more than one device: Windows
PCs, a Mac, an iPhone and an Android phone. There is no
LocalGateKeys server and no account. Your devices talk to each other directly
over your home Wi-Fi, or they leave encrypted files in a cloud-drive folder you
choose (OneDrive, Dropbox, Google Drive, iCloud Drive). You can use either, or
both.

Sync is part of LocalGateKeys Pro. Without a Pro licence on a PC, full sync does not run there; what earlier syncs brought stays in its vault, and sync resumes where it left off once Pro is back. A free PC runs a licence-only sync service: it can pair and join, and it takes a valid
licence from a Pro phone or PC, but it never syncs logins or notes and publishes nothing. It
never runs in the background, only when you press Sync now, and its Wi-Fi listener stays open
for about 120 seconds after such a round (and while a pairing code is armed). Once it adopts a
licence the PC turns Pro and full sync starts. You can also enter a licence key on each PC.

This page describes the app as built. It makes no claim of an independent
security audit. How the pieces work is in
[ARCHITECTURE.md](ARCHITECTURE.md#10-device-sync).

Open it from the **Tools** group in the sidebar, then **Sync**. This page names
the buttons of the Windows app; the Mac app uses the same names. The iPhone and
Android apps join a group (by QR code or code text, or with a cloud folder) but
cannot create one or show a code; set the group up on a PC or Mac.

## What syncs

- Website logins and desktop app logins (including desktop bindings).
- Typed items such as notes and bookmarks.
- Your Pro licence, between devices that are already Pro. A PC where you removed
  the licence keeps it removed, and a revoked licence is never passed on.
- Deleting an item on one device moves it to the trash on the others. It is not
  purged, so you can restore it.
- Collections, and which items are in each, on Windows, Mac, iPhone and Android.
  Two devices that change the same item's collections at the same time keep both.
  Two collections with the same name get " (2)" on one of them.

## Share a collection with family

Optional, part of Pro. In this release you share through a shared folder only: a
cloud-drive folder that the people in the share can all open. There is no Wi-Fi
sharing yet.

- **Create.** Choose a collection and share it. LocalGateKeys asks you to confirm
  it's you (the master password on Windows and Mac, Face ID or the passcode on the
  iPhone, the fingerprint, face or screen lock on Android). You pick a folder and a
  share password. Write the share password down and give it to family another way.
- **The share password protects the items in the folder.** Anyone who can open the
  folder and knows the share password can decrypt the shared items. Give it only to
  people you invite.
- **Join.** The other person opens the same folder on their device, enters the
  share password and waits. You approve them by name. Approval is what lets their
  device sync: until then the app on their device takes none of the shared items and
  writes none of its own, and they see "Waiting for the person who shared this
  collection to let you in". Once approved, their device syncs and, in an edit
  share, their edits count.
- **View-only or edit.** You choose when you create the share. Members of a
  view-only share can read the items; members of an edit share can also change them.
  To switch, share the collection again.
- **The owner decides who is in.** Your device signs the member list. Nobody else
  can add or remove people. If your device is lost, the old group cannot be changed:
  on one of your other devices, open the collection's Share section and choose
  **Forget share link** (it asks you to confirm), then share the collection again into
  a new, empty folder. Forgetting the link also lets you delete the collection, and on
  your other devices it ends the read-only rule of a view-only share whose member
  device is gone. A device that still holds the share puts its link back at its next
  sync, so forgetting never takes a live share away. If the collection was shared again
  meanwhile, it is now shared from two of your devices: the Share section on both says so;
  stop sharing or leave it on one. Until then your devices agree on one link (an owner's
  over a member's), so device sync does not go back and forth.
- **Someone damages the share's key file.** The owner's device puts its own copy back
  on its next sync, with or without Pro. If the folder held another share's key file,
  the owner's device replaces it and says so ("This folder held another share's key
  file; it was replaced."); two shares never belong in one folder.
- **Remove someone.** The app asks you to confirm. It does not ask for the master
  password. The share gets a new key, so the removed person gets no later changes.
  Their device shows that it was removed, and the shared items on it go to
  Recently deleted. Their own items stay.
- **Deletes.** Deleting a shared item moves it to Recently deleted on every device
  in the share. You can restore it.
- **Pro.** Creating or joining a share needs Pro. If your Pro ends, you can still
  remove people from a share you own, and your device still repairs the share's key
  file; it no longer syncs the items until Pro is back.
- **Backups.** A backup never contains a share: no share key, key file, owner key or
  member list. Restoring a backup keeps the shares this device has now, with their
  items as they are now (Windows, Mac, iPhone and Android alike); the restore
  confirmation says so. On Windows a backup is restored as a new profile, where the
  shared collections are ordinary collections that sync with nobody. Windows and Mac
  full backups made with earlier versions do contain the share keys of the time, so
  keep them as safe as the vault; restoring one drops them. A restore that replaces a
  vault (only through the API) keeps that vault's shares, and is refused when that vault
  does not open with the restore's master password.
- **Older versions.** A device on an older version of the app does not know shares.
  If you downgrade, the app drops the share records, so the share stops on that device.
- **Privacy.** Nothing leaves your devices except encrypted files in the folder you
  chose. There is no LocalGateKeys server and no account. The folder never shows the
  collection name.

What does not sync in this version:

- Collections with a device that runs an older version. Collections and which
  items are in them sync on Windows, Mac, iPhone and Android, but only between
  devices that all run this version or newer (on Wi-Fi, between the two devices of
  each sync). An older device gets the items without the collection link, and its
  edits keep the collections on the newer devices. Documents and their files sync between devices that all run this
  version or newer (see "Documents and files" below).
- Per-PC trust. The approval for filling an embedded web view, browser approvals
  and sign-in settings stay on each PC. A login that arrives by sync starts with
  auto sign-in set to "never" on the receiving PC; you turn it on there if you
  want it.
- Anything that cannot be read safely. If one of your own items is damaged, sync
  skips it, tells you which one, and keeps syncing the rest.

Limits: 16 devices per group, 20,000 items and 64 MiB per device file.

Sync runs only while the vault is unlocked on that PC: on unlock, every 5
minutes, and about 10 seconds after you change something. A locked PC neither
sends nor receives. A failed sync never changes your local data.

The iPhone and Android apps sync when you unlock, when you come back to the app
while it is still unlocked, and about 2 seconds after you change something.
**Sync automatically** in the phone's Settings (on by default) turns all three
off; the phone then syncs only on **Sync now** or pull-to-refresh.

## Wi-Fi or cloud folder

| | Wi-Fi (this network) | Cloud folder |
| --- | --- | --- |
| Needs | Both devices on the same network, both unlocked | A folder your cloud app already syncs, and a sync password |
| Works while the other device is off | No | Yes, the files wait in the folder |
| Third party involved | None | The cloud provider holds encrypted files |
| Adding a device | A one-use QR code; between PCs you paste its text | Join the folder with the sync password |
| Follows a password change | No, pair again | Yes, on the next sync |

Wi-Fi sync uses a fixed port (47821 by default) on this PC's private address.
There is no Internet fallback. You enter this PC's address once (see step 0 below), for example `192.168.1.20:47821`; only private and
link-local addresses are accepted. The PC serves up to four incoming
connections at a time (two per network address), separately from its own
outgoing ones, and drops a connection that sends nothing within two seconds, so
a stray connection on the network cannot block sync or pairing.

While Wi-Fi sync is listening, the Windows app also announces it on the local
network with mDNS / DNS-SD (Windows 10 1809 or later; on older Windows nothing
is announced), so a paired device can find the PC again after its address
changed. The announcement is the service `_lgksync._tcp` with the instance name
`LocalGateKeys-xxxx` (four random hex digits, new on each app start), the host
name `lgk-xxxx.local` (not the computer name), the listening address and port,
and a TXT record with a version and a tag. The tag is an HMAC of the device id
and the UTC date under a key only group members hold, so it changes every day
and cannot be used by others to follow a PC across days; paired devices accept
only announcements whose tag they can compute. The instance name does reveal
that LocalGateKeys runs on that address. It is sent only on the adapter that
owns the listening address, and only when Windows treats that network as
Private or domain. There is no separate setting to turn it off: it stops when
Wi-Fi sync stops listening, and on a Public network it is not sent.

You can start with either. **Show QR code...** on a vault that is not in a group
yet creates a Wi-Fi-only group; it can add a cloud folder later without pairing
again (see "Add a cloud folder to a Wi-Fi group" below). A cloud folder group
can use Wi-Fi sync too (**Turn on Wi-Fi sync...**).

## What the cloud provider can see

The provider holds ciphertext and coarse metadata. It can see:

- how many files are in `LocalGateKeys Sync` and their sizes and timestamps;
- file names, which are random device ids (`devices/<id>.lgksync`);
- the key file's member list: each device's id, its public key and when it
  joined. Device names (a PC calls itself "Windows PC") are encrypted with a
  key derived from the group key, so the provider sees only their approximate
  length;
- each device file's plain header: group id, device id, key epoch, a write
  counter and a write time.

It cannot read your items. Everything inside a device file is encrypted with a
key derived from the group key. The group key is stored in the key file wrapped
by your sync password (Argon2id, 128 MiB) and wrapped separately to each
member device.

Anyone who can both read your cloud folder and guess your sync password can
open the group key. That is why the password must be strong and used nowhere
else.

## Set up a group (first device)

1. **Create sync group...** on the Cloud folder card.
2. Choose the folder your cloud app syncs. LocalGateKeys makes a
   `LocalGateKeys Sync` folder inside it.
3. Choose a sync password, twice.

## Join with a cloud folder

On another PC, **Join a folder...**, choose the folder that contains
`LocalGateKeys Sync` (wait until your cloud app has downloaded it), and enter
the sync password. The PC then merges what is there and starts writing its own
file.

On the iPhone, the folder picker only lets you choose folders from cloud apps
that allow other apps to open their folders. Some, such as OneDrive, appear
greyed out there even though their folders open normally in the Files app; this
is a limit of those apps on iOS, not of LocalGateKeys. Sync the iPhone
over Wi-Fi, or keep the group's folder in iCloud Drive.

## Add a cloud folder to a Wi-Fi group

A group that so far syncs only over Wi-Fi keeps its devices and pairings when it
gets a cloud folder. The Cloud folder card of such a group offers two actions:

1. On one device, **Add a cloud folder to this group...**: choose the folder your
   cloud app syncs and a new sync password, twice. LocalGateKeys makes a
   `LocalGateKeys Sync` folder inside it with a key file for the group you are
   already in.
2. On each other device of the group, **Use this group's cloud folder...**:
   choose the same folder (wait until your cloud app has downloaded it) and enter
   that sync password. The device keeps its Wi-Fi pairings and starts writing
   its own file in the folder.

If you removed a Wi-Fi device from this group since the sync key last changed,
that device still knows the key. **Add a cloud folder to this group...** then
asks first and gives the folder a NEW key, so the removed device cannot read it.
Wi-Fi cannot hand a new key to your other paired devices, so they stop syncing
with this PC (they show "older sync key") until you pair each of them again
(leave sync there, then scan a new QR code) or use **Join a folder...** there
with the new sync password. The dialog names them.

If the folder already holds this group, **Add a cloud folder to this group...**
uses it instead, with the password you typed. A folder that holds a different
group is refused and left as it is. If someone changed the sync password of the
folder group after this PC was paired, this PC cannot use the folder: leave sync
on this PC, then **Join a folder...** with the current sync password.

## Pair a PC or phone by QR (Wi-Fi)

A phone scans the QR code (**Scan QR code** on the phone's Sync screen) or takes
the pasted code text (**Paste code text**). There is no QR scanner in the PC
app: between two computers you copy the code text from one and paste it into
the other (on a Mac, in the **Join with a code** section). The code is always shown on a PC or
Mac.

0. On the device that will show the code, choose **Turn on Wi-Fi sync...** on the
   Wi-Fi card. Enter this PC's own address on your home network and a port, for
   example `192.168.1.20:47821`. The dialog suggests one from this PC's network
   addresses (find yours with `ipconfig`, the IPv4 address of your Wi-Fi or
   Ethernet adapter). Use the numeric address, not a name. Only private
   addresses work (192.168.x.x, 10.x.x.x, 172.16-31.x.x or link-local); the port
   must be 1024 to 65535. **Show QR code...** appears only after this.
1. Choose **Show QR code...**. A code with a 120 second countdown appears. It
   works once. After five wrong attempts it stops working. Closing the window
   cancels it at once. If this vault is not in a group yet, this starts a
   Wi-Fi-only group.
2. On a phone, choose **Scan QR code** and scan it within the 120 seconds. On a
   new PC, which needs no Wi-Fi setup of its own, choose **Join by QR
   text...**; on the first PC choose **Copy code text** and paste it within the
   120 seconds. The copied text is cleared from the clipboard after 120 seconds
   if it is still there.
3. The new device shows a 6-digit code (for example `123 456`) and waits. It
   shows the code only after the first device has checked its request and sent
   back the secret half of the code, so nobody who saw the QR code can work out
   a matching code in advance. The
   first device asks **Add <name>?** with the new device's name and the same
   code, and **Accept** / **Decline**. Choose **Accept** only if both screens
   show the same code. Nothing is sent and nobody is added before Accept; with
   **Decline**, or no answer within 60 seconds, the new device is told
   "declined" and the code is used up (show a new one to try again).
4. After Accept the new device receives the group key over the connection that
   the code authenticates, and syncing starts. The first device shows **Paired:
   Device ...** with the start of the new device's key fingerprint and still
   offers **Undo**, which removes it like **Remove a device...** (in a
   cloud-folder group this also changes the sync password, because the device
   already received the key).

Both devices must be unlocked and on the same network, and the first one must
be listening (step 0). The code carries the first device's address, so the new
device does not need it. A phone has no listening address: it always connects
to the PC or Mac, so every Wi-Fi sync with a phone is started by the phone.
On Windows, the code window shows whether Windows Firewall lets other devices
reach the port and, if not, offers **Allow through Windows Firewall** (Windows
asks for permission first).

## Sync password

- At least 12 characters and rated Strong.
- Write it down and keep it somewhere safe. It is never stored on any device,
  and nobody can recover it. If every device is lost and you forget it, the
  cloud files cannot be opened.
- The password is used exactly as typed (UTF-8, no Unicode normalisation); key derivation is Argon2id version 1.3.
- Never reuse an earlier sync password. An old password, together with an old
  copy of the key file from your cloud's version history, still opens the old
  group key.

## Change the password, or remove a device

Both are the same operation. The app makes a new group key, wraps it to the
devices that stay and to the new password, and moves everyone to the next epoch.

- **Change sync password...** is the button for a plain change. You must choose a
  **new** password; only reuse of the *current* one is blocked. Not reusing
  earlier ones is advice the app cannot check, so follow it.
- Your other cloud-folder devices pick the change up on their next sync. A
  device you add later joins with the new password.
- **Devices paired by QR cannot follow a password change. Pair them again.**
  The dialog names them.
- A removed device keeps what it already has, but cannot read anything written
  afterwards.
- **Unused members...** (shown when some device has no sync file or none for over
  a year) lets you tick those devices and remove them in one password change.
- The confirmation lists every device that gets the new key. Only those devices
  and this PC get it. A device another device added that you have not confirmed
  yet (**These are my devices**) is not on that list and loses access; so does a
  device that appears in the folder after you opened the confirmation.

## New devices in the member list

Anyone who knows the sync password (or the group key) can add a device to the
key file. Each PC therefore shows a device it did not know before as "added to
this sync group by another device", marked "not confirmed" in the device list,
until you choose **These are my devices**. If you don't recognise it, remove it
(**Remove a device...**). This also catches a device about to be removed that
adds a stand-in for itself: the stand-in never gets the new key unless you
confirmed it.

## A device is lost

1. On a device you still have, **I lost a device...** (or **Remove a device...**),
   pick the lost one, and choose a new sync password. (**Unused members...**
   lists devices with no recent sync file, for example a PC you retired, and
   removes several at once the same way.) **I lost a device...** then shows a
   short checklist of what to do next.
2. Sign the lost device out of your cloud account, so it can no longer reach
   the folder. This matters: a removed device that can still reach the folder
   is the one case the rotation can lose a race against (see limitations).
3. If it was paired only by Wi-Fi, remove it from the paired devices; it stops
   being contacted.

Items are already on the lost device; change passwords that matter. The copy
there is encrypted and only as safe as your master password.

### Erase on removal (Windows, 2026-10-30)

A removal from a cloud-folder group also leaves a removal notice in the folder
(`removed/<device id>.lgkremoved`), signed with the removing device's signing
key. A Windows PC that finds a notice for itself, signed by the key of a
confirmed member that it trusted before the removal, and whose folder key file
no longer lists it,
erases that vault from the PC (vault file, sidecars, attachments, pre-restore
safety copies, the stored backup password and sync state, each overwritten once,
then deleted) and says so on the next screen. Its scheduled backups are kept:
they are moved first to `Kept backups/<vault name> <date>/` in the data folder,
because opening one needs the separate backup password as well as the master
password. The notice says where they are. Settings > Plan & sync > **Erase this device if it is removed from
sync** (on by default) turns this off on that PC. It checks at start, every
5 minutes while the app runs (locked or not) and when a sync run stops.

This is a bonus, not a guarantee: a device kept offline, with its cloud app
stopped or the vault file copied first, is not erased. It never happens on the
"may have been removed" warnings below, which anyone with the sync password or
folder access could cause, nor for a device removed only from Wi-Fi sync (no
notice reaches it), nor for a device that left sync itself before it was
removed. Older Windows builds, the Mac, iPhone and Android ignore the notice
(the Mac follows later). Design: `docs/design/security-2026-10-30/wp-a-design.md`.

## Leave, and reset

- **A device that leaves keeps its id.** Leave sync keeps the device's id and keys in the vault (never in a
  backup, never synced). Pairing again with the same group, or joining its folder again, uses them, so the
  other devices show the device once. Reset sync, erasing the vault, a reinstall and a removal from the group
  drop them. A device on an earlier version refuses the first pairing under the kept id; the app then says to
  show a new code and pairs under a new id. Design: `docs/superpowers/specs/2026-11-17-keep-device-id-on-rejoin-design.md`.
- **Leave sync...** stops syncing on this PC and forgets its paired devices.
  Your items stay. This PC's last file stays in the folder, so your other
  devices still receive the changes it made before leaving. On another device,
  remove this PC (**Remove a device...**): that deletes its file and changes the
  password. The key file keeps listing a leaving PC until someone does that.
- **Reset sync on this PC...** forgets the group, its keys and the sync history
  on this PC, after two confirmations. Your items stay. It is the way out of
  most of the stopped states below. To sync again you join or pair again.

A vault that is copied or restored onto another PC does not keep syncing under
the old PC's identity. It asks you to join again on the new PC, so two PCs never
share one device identity.

## Conflict copies

If two devices edit the same item before they sync, one version keeps the
original place. The other is kept as a separate item with " (sync conflict)"
added to its title or label. Nothing is dropped. The one that keeps the original
place is the one edited more recently by the devices' clocks; if that is equal,
the choice is fixed by a hash, and every device decides the same way.

If one device edits an item while another deletes it, the edited item stays and
the delete does not apply.

To resolve: open both, copy over what you want to keep, then delete the copy (or
the original). Editing or deleting a copy counts as your decision about it.
The Sync screen shows how many copies were made since you unlocked.

## What the Sync screen warnings mean

Messages can name a file or a device. Stopped states are shown as errors and
offer **Reset sync on this PC** where that is the way out.

### Key file and membership (cloud folder)

| Message (shortened) | What it means and what to do |
| --- | --- |
| Older or altered key file. This PC put the trusted copy back | Someone or something wrote an old key file. It was replaced. Sync continues. If it repeats, check who has access to the folder. |
| Folder holds a different sync group | The folder was changed to another group. Nothing was written. Leave or reset, then join the right folder. |
| Two devices changed the sync password at the same time | Join the folder again with the newest sync password. |
| This device may have been removed from sync | Another device removed this one, or two changes collided. Re-join if you did not expect it. |
| Another of your devices removed this PC from sync | A signed removal notice was verified, and Erase on removal is off on this PC. Leave sync, or join the folder again. |
| This PC must join sync again | It missed a password change or was removed. Join the folder with the current sync password. |
| This PC has an older sync key than a paired device | Leave sync on this PC, then pair it again. |
| A device disappeared from the member list without a password change | If you did not remove it, change the sync password. |
| A device was added to this sync group by another device | If it is yours, choose These are my devices. If not, remove it. |
| A Wi-Fi device removed from this PC still knows the current sync key | Change the sync password to cut it off from the cloud folder. |
| Key file was altered / damaged / missing / could not be read | Sync stopped. Check the folder and that your cloud app has downloaded the file. If it persists, reset sync on this PC and join again. |
| Key file was replaced by an older copy and could not be put back | Sync stopped. Check the folder, or reset and join again. |
| A member has an unsafe name and is ignored | Harmless; that member's file is not read. |
| Sync settings are damaged, or the sync identity does not match its pairing | Reset sync on this PC, then join or pair again. |
| This vault was set up for sync on another PC | Join the folder again on this PC. |

### Device files

| Message | Meaning and action |
| --- | --- |
| Device has not synced for over a year and is ignored | Remove the device if it is gone. |
| This PC had not synced for over a year | Items deleted elsewhere more than a year ago may come back. Delete them again if they do. |
| Unknown files were ignored | Cloud apps make copies such as `name (1).lgksync`. They are never merged. You can delete them. |
| File is damaged or could not be verified, was skipped | Nothing was changed. If it persists, the owner device rewrites it on its next sync. |
| File was replaced by an older copy | Cloud file history put an old version back. It was skipped. |
| File was rewritten without a new version number | Somebody with folder access may have altered it. It was skipped. |
| File was written with another sync key | Ignored until that device syncs again. |
| A device's file is signed with the wrong key, or not signed | Skipped. Someone with folder access may have altered it. |
| A device has a different signing key in the member list than before | The key file now names another signing key for that device, and this PC follows it. If you did not set that device up again, remove devices you do not trust. |
| File holds data of a different device, or a device "sent data signed for a different device" | Skipped. Normally a renamed or copied file or a confused peer; it fixes itself when the owner syncs again. |
| File could not be read | Skipped. Usually the cloud app has not finished downloading it. |
| Sync folder not available or could not be read | Check that the cloud app is running and the folder exists. |
| This PC could not write its sync file | Check the folder is available and not read-only. |
| Over the sync limit (20,000 items or 64 MB) | Some changes were not sent. Delete items you no longer need. |
| This vault was restored from an older copy; sync caught up | Informational. |

### Merging

| Message | Meaning and action |
| --- | --- |
| Could not move deleted items to the trash | The trash is full. Empty it. |
| Could not keep item history | History limit reached. Clear old history, then sync again. |
| Data from a device could not be read and was skipped | A peer sent a malformed record. Other items still sync. |
| One item needs a newer LocalGateKeys on this PC | A device wrote that item in a newer format. This PC keeps its own copy of it unchanged and syncs everything else. Update LocalGateKeys on this PC. |
| One item from a device could not be read on this PC and was skipped | Usually a newer app version on the other device. Only that item waits (this PC keeps its own copy of it unchanged); everything else syncs. Update LocalGateKeys on this PC. |
| Items changed while syncing | Sync retries shortly. |
| Changes could not be saved | Sync retries later. |
| Some items on this PC could not be read for sync | Those items stay only on this PC. The screen names them. |
| Unexpected problem | Details are in the error log. |

Each synced item carries a format number. A device that receives an item written in a newer format keeps its own copy of that item and syncs the rest; update LocalGateKeys on that device.

### Wi-Fi

| Message | Meaning and action |
| --- | --- |
| Pairing code was used up or expired | Show a new code. |
| This pairing code belongs to another sync group | Show a new code on the right device. |
| Other device already has the most paired devices | Remove one there first. |
| Wi-Fi sync is not listening / could not start listening | Check the address and port, and that no other app uses the port. |
| A device could not be reached | Same Wi-Fi, and LocalGateKeys unlocked on both. |
| A device that is not paired tried to sync | It was refused. Nothing to do unless you expected it. |
| A device was removed from sync and was not contacted | Expected after a removal. |
| A device did not match its pairing | Not synced. Pair it again. |
| A device belongs to a different group, is not set up, or must join again | Fix on that device. |
| Another device sent data this PC could not understand (bad reply, chunk or message) | Skipped. Update both devices if it repeats. |
| The other device refused to sync | It does not accept this PC (not paired, removed, or not unlocked). Check pairing on that device. |
| The other device refused the pairing | Show a new code and try again. |
| The other device declined, or nobody chose Accept there in time | Show a new code and choose Accept when both screens show the same code. |
| A device runs an older LocalGateKeys and cannot sync over Wi-Fi with this PC | Update LocalGateKeys on that device. Wi-Fi sync never falls back to the older protocol. |
| Another device runs a newer Wi-Fi sync | Update LocalGateKeys on this PC. |
| Not a valid LocalGateKeys pairing code | You pasted something else, or the text was cut off. Copy the code text again. |
| Peer has no network address; it connects to this PC instead | Normal for a phone. |
| A paired device has an older sync key | Pair it again with Show QR code. |

Other short messages on the screen, such as a wrong sync password, a weak
password, "this folder already holds a group" or "this vault is already in a
sync group", describe themselves and say what to do next.

### Restored or rolled-back vaults

Each device remembers how new the vaults of the other devices were (their vault generation) and publishes
what it saw with its own sync file (a small witness file under `LocalGateKeys Sync/witness/`, or a Wi-Fi
`witness` message). A device that is put back to an older copy of its vault is caught at the next sync, even
when its local anchor file was deleted with it.

| Message | Meaning and action |
| --- | --- |
| **This vault is older than one your other devices have seen** | Another device saw a newer copy of this vault. If you restored a backup yourself, choose **This was me — keep this copy** (the app asks you to confirm and for your master password or Windows Hello). If you did not, someone may have replaced the vault file with an old copy: sync brings back the newer items your other devices hold; check recent changes and change your master password. The warning comes back at every sync until you confirm it. |
| Another device in your sync group is now using an older copy of its vault | If nobody restored a backup there, check that device. **Dismiss** accepts its older copy, so the warning stops. |
| You restored an older backup. Your other devices were told this copy is the current one | Shown once after **This was me**. After restoring a backup with **Restore**, choose **This was me** at the next warning: the app never confirms on its own, because a file it could leave behind would be as easy to fake as the old vault copy. |

Confirming raises this vault's generation above every value the other devices have seen, so they accept the
restored copy from then on. Limits: a vault restored from a copy made before it joined sync has no witness;
a device holding the group key can make another device show the warning (a false alarm, no data is lost);
someone who controls the shared folder can hold back files and delay the warning until Wi-Fi sync or a later
folder run. The iPhone, Mac and Android apps keep syncing as before but do not publish or check witnesses yet.

## Known limitations in this version

- **Rare duplicate.** After some concurrent edit and delete histories across
  three or more devices you can see the same content twice, once as a
  "(sync conflict)" item. Delete the one you do not want. The engine prefers a
  visible duplicate to losing an edit.
- **A deleted conflict copy can come back.** If the same two versions conflict
  again later, the copy you deleted may reappear. Delete it again, or resolve the
  original.
- **A device offline for over 365 days** can bring back items that were deleted
  more than 365 days ago, because the deletion markers are gone. You are warned
  on that PC. Files older than that from other devices are ignored.
- **A device that was offline during a removal.** A removed device that still
  has access to the cloud folder and the old group key can race the real rotation
  against a device that was offline when the removal happened, and a lagging
  device accepts the first valid next-epoch key file it sees. Sign a lost device
  out of the cloud account, and re-check the member list after a removal. A
  shared collection (share v2) is not affected: the owner's signature covers the
  new key's wraps, the password wrap and the chain value, so only the owner can
  write a next-epoch key file that a device accepts.
- **Wi-Fi-only peers cannot follow a rotation.** After a password change or
  removal they show as "older sync key" and must pair again. The same applies
  when a cloud folder gets a new key because a Wi-Fi device was removed.
- **Wi-Fi removal is per PC.** Removing a Wi-Fi device on one PC does not remove
  it on the others. If another PC that did not remove it adds the cloud folder,
  the folder uses the key the removed device knows; change the sync password
  afterwards.
- **The Accept code checks the device, not the person.** Anyone who saw the
  QR code or the copied text can try to pair while it is shown; compare the
  6-digit code on both screens before choosing Accept.
- **Older devices.** Wi-Fi sync and QR pairing changed in this version
  (session keys with forward secrecy, the Accept step). A device running an
  older LocalGateKeys cannot sync over Wi-Fi with an updated one and must be
  updated; an older device that tries is reported on the updated one, while the
  older device itself only sees "could not be reached". Since 2026-11-12 the
  Wi-Fi greeting is encrypted (version 3). An updated device still answers the
  previous version's greeting from a paired device until that device has once
  used the encrypted one; from then on it refuses the old greeting from it. An
  updated device cannot start a sync with an older one (it is reported as
  needing an update), and an older device cannot join through an updated
  device's QR code.
- **Saved addresses on other networks.** A PC or phone still tries the saved
  address of each paired device, also on a network that is not yours. The
  greeting it sends is encrypted to that device and reveals no device or group
  id, but the address, port and timing are visible to that network.
- **Signing keys of older members.** Devices that joined the cloud folder with an
  older version have no signing key in the member list. Their files are checked
  against the key seen first, as before, until they leave and join again.
- **A lagging peer can relay a removed device's edits.** A device that has not
  yet seen the removal can still pass on edits the removed device made before it
  was cut off, until it catches up.
- **Auto sign-in starts at "never"** for logins that arrive by sync.
- **Collections sync only between devices of this version or newer** (an older cloud-folder
  member holds them back for the whole folder until it updates). Shared collections need the
  same version on every device in the share. If you go back to an older app version, it drops
  the share records it does not know, so those collections stop being shared on that device. Documents reach a device that has only received
  them as the answering side of a Wi-Fi sync once that device starts a sync
  itself, or through the cloud folder.
- **Someone with write access to your cloud folder can stop sync** by deleting
  or damaging the key file or making it look like a competing password change.
  Your data stays local and readable; you reset sync on this PC and join again.
- **Clock skew.** The winner of a concurrent edit follows the devices' own
  clocks, so a PC with a wrong clock may have its edit kept as the copy instead
  of the original. Both versions are still visible.

## Protocol changes in this version (2026-10-24)

For implementers; the shared test vectors in `tests/vectors/sync/` (README there)
pin every recipe byte for byte.

- **Wi-Fi session protocol version 2.** The session hello has a new field
  `ephemeral_public` (a fresh X25519 key for each connection); the signing label
  is `localgatekeys|sync|session-hello|v2|` and `version` is 2 in hellos and
  sealed frames. Session key = HKDF-SHA256 over X25519(ephemeral, peer
  ephemeral) followed by X25519(static exchange key, pinned peer exchange key),
  salt SHA-256(`localgatekeys|sync|session-salt|v2|` + sorted hellos), info
  `localgatekeys|sync|session-key|v2|` + session id. Each ephemeral private key
  is used once and erased, so a later leak of a device's exchange key does not
  open recorded traffic. A hello of another version is answered with the plain
  frame `{"refused":"version","version":2}`; there is no fallback.
- **Listener limits (audit R-1).** At most 4 inbound connections, 2 from one
  address; before a verified hello at most 1 per address and 3 per /24 (IPv4)
  or /64 (IPv6), and one slot is kept for addresses that completed a verified
  hello in the last 15 minutes. Connecting waits up to 3 seconds.
- **QR enrollment version 2.** The request body has `version` 2 and a `name`
  (1..64 UTF-8 bytes), which is also `invitee_name` in the enrollment
  transcript. Both screens show the verification code: the first 4 bytes of
  SHA-256(`localgatekeys|sync|enroll-verify|v2|` + transcript), big-endian, mod
  10^6, 6 digits. The inviting device answers only after Accept (up to 60
  seconds); the new device waits up to 75 seconds. New refusal reasons:
  `declined` and `update-needed` (a version-1 request).
- **Key file format 2 (audit R-4).** Each member entry also lists
  `signing_public` (its Ed25519 view-signing key) and `signing_proof` (that key's
  signature over `localgatekeys|sync|keyring-member|v2|` + group id + `|` +
  device id + `|` + exchange key + `|` + signing key, base64 text), both null for
  a member carried over from format 1. The key file MAC covers them. Format 1 is
  still read; every write is format 2. A device's file signature must carry the
  key from the member list first, else its Wi-Fi pairing key, else the key seen
  first; a changed key in the member list replaces the old one and is reported.
- **Share metadata (sub-plan 07).** The key file of a shared collection's group also has
  `"metadata":{"kind":"share","collection_id","name_ct","shared_mode","owner","owner_key"}` and
  `"owner_sig":{"members","sig"}`. The collection name is encrypted under the group key like device
  names, so the folder never shows it. `owner_sig` is the owner's Ed25519 signature over the group id,
  epoch, metadata and the approved members (share v2 also: the content block, `kdf`, `password_wrap`,
  the approved members' device wraps and `prev_mac`, so a removed member who kept the old key cannot
  reuse the signature for a next-epoch key file with a key of its own); only the owner can rotate, remove members or approve
  new ones, and a member who joins with the password stays pending until the owner signs again.
  Every device pins the owner, owner key, collection id and mode at create or join and refuses a key
  file that changes them or drops the owner. Removal notices of a share group count only when the
  pinned owner signed them, and the owner's device never acts on one. Within one epoch a share key
  file may only grow (a password join appends a member, an owner approval approves more): a key
  file that drops or changes a member, a device wrap or the password wrap, or approves fewer
  members, is refused, so removing anyone needs the owner's signed rotation. Losing the owner's
  device freezes the group: nobody can rotate, remove or approve until owner recovery exists
  (planned); the owner can share the collection again from another device after **Forget share
  link** there (below), into a new, empty folder. Device-sync key files never
  have these fields and read as before; device sync refuses to join a folder whose key file has them
  (`share-group`). Format details: `src/localvault/sync/keyring.py`; code: `share_group.py`.
- **Personal collections (sub-plan 07 Task 4).** Collections, item membership and share links travel
  in device sync as states of namespace `collection`: `col:<id>` (name, description, times), `cm:<item
  id>` (the item's collection ids) and `csl:<collection id>` (`mode` and `role` of a share held by one
  of your devices). Item records keep their earlier shape, so older devices read every view as before.
  They are sent only when every reader understands them: in a cloud folder each other member must have
  written its signed `attachments/<device>.lgkcol` file, on Wi-Fi the peer must have answered a
  `features` message. Two devices that change one item's collections at the same time keep both (no
  conflict copy); two collections of one name get " (2)" on the one with the larger id. A share's group
  id, keys, key file, members, folder and owner key never leave the device in device sync: your other
  devices learn only that the collection is shared, with which mode and role. They are not in the share;
  if it is read-only for you they refuse edits too, and the device in the share refuses edits, deletes
  and collection moves of its items that arrive by device sync (its own copy wins). A received
  `csl:` link goes away only through a tombstone: **Forget share link** (`share_group.forget_share_link`,
  `ShareGroups.forgetLink` on Kotlin and Swift) drops it on a device that does not hold the share,
  and that device's next run publishes the tombstone; a device that still holds the share republishes
  its link above it. Code: `src/localvault/sync/vault_bridge.py` ("Personal collections").

## Documents and files (2026-10-29)

Documents sync together with their files. The byte formats are in the code in `src/localvault/sync/attachment_sync.py`
and `attachment_flow.py`, and the vectors in `tests/vectors/sync/attachments/vectors.json`.

- Each file becomes one immutable encrypted blob, padded to 64 KiB and named after the SHA-256 of
  its ciphertext. In the cloud folder it is `attachments/<blob id>.lgkblob`. Over Wi-Fi it moves as
  `blob-get` / `blob` messages. The name, type, size and key travel only inside the sealed, signed view.
- A device imports and checks the file before it applies the document. A damaged or swapped file is
  refused and nothing is stored. A document whose file has not arrived yet is set aside
  (`attachment-missing`) and tried again on the next sync.
- A file that is already there is never sent again. Deleting a document moves it to the trash
  everywhere, like any item. Blobs nobody references are removed from the folder after 7 days.
- Older versions never receive documents. In the cloud folder, documents are published only when
  every other member wrote a signed capability file (`attachments/<device id>.lgkcap` plus `.lgksig`).
  Over Wi-Fi, they are sent only to peers in `attachment_peers`, which are learned from a `blob-get`
  probe. Older builds ignore the `attachments/` folder and answer the new messages with `bad-message`.
- Limits: 25 MiB per file, 500 per view, and the 1 GiB local attachment quota.

## Wi-Fi protocol version 3 (2026-11-12)

For implementers; byte rules in `docs/formats/LAN_SYNC_V3.md`, vectors in `tests/vectors/sync/lan/v3/`.

- **Sealed hello.** The first frame of a Wi-Fi connection is
  `{"box","eph","signature":"","version":3}`: the version-3 hello (the version-2 hello with `v3` labels),
  padded to 1024 bytes and sealed with AES-256-GCM under a key from X25519(fresh ephemeral key, the
  responder's pinned exchange key). The responder answers with its own hello sealed the same way, or
  closes without a word if the frame does not open or the hello inside does not verify. No device id,
  group id or public key is sent in clear text, and two connections share no bytes beyond the fixed
  JSON. The session key and the encrypted frames are as in version 2, with `v3` in the two key labels.
- **Pin.** A device that has completed one sealed session with a peer, or paired with it through a
  version-2 QR code, stores `"hello":3` in that peer's entry and from then on answers a clear-text hello
  from it only with `{"refused":"version","version":3}`. Before that, a clear-text version-2 hello from a
  paired device is answered as before. A device never sends a clear-text hello itself; a version-2 peer
  answers the sealed frame with its refusal and is reported as needing an update.
- **QR offer version 2.** The QR code carries `commit` = SHA-256(`localgatekeys|sync|enroll-commit|v3|`
  + 32 random bytes). The request body and transcript have version 3; once a request verified, the
  inviting device sends `LGKENROLLRV1\n` + `{"reveal"}` once, before its reply, and the code is
  SHA-256(`localgatekeys|sync|enroll-verify|v3|` + transcript + reveal), first 4 bytes big-endian, mod
  10^6. The new device shows the code only after the reveal matched, and refuses a reply without it. A
  version-2 body for such a QR code gets `update-needed`; a new device that scans a version-1 QR code
  uses the version-2 body and code.
