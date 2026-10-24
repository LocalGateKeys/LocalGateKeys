# Disaster-recovery runbook

This runbook is for an offline-first LocalGateKeys vault. It assumes that the
computer may be destroyed, unavailable, or suspected compromised. It does not
turn the application into a cloud backup service and it does not replace an
independent security review.

## Recovery kit and password separation

For each important profile, maintain a recovery kit containing:

1. a verified encrypted, attachment-aware full backup;
2. the generated SHA-256 manifest and backup creation date;
3. the matching signed installer or portable package, when signing is
   available; otherwise a package explicitly labelled unsigned development
   software;
4. the matching browser-extension package and native-bridge instructions; and
5. this runbook, including the version and recorded verification results.

The recovery kit must not contain either password. Store the vault master
password and the independent backup-container password in separate sealed
records, preferably in separate physical locations or under separate custodial
controls. They must not be the same password and must not be written into the
backup filename, manifest, recovery-kit JSON, email, chat, or an unencrypted
note alongside the media. The application can produce the non-secret kit
metadata; password separation is a human/physical control.

## Recovery phrase

A vault can carry an optional 24-word recovery phrase (Backup & restore >
Advanced tools > Recovery phrase). The phrase can open the vault when the master
password is lost, after which a new master password must be set immediately;
Windows Hello and camera unlock then need to be re-enrolled. Treat the phrase
exactly like the master password:

1. Create it only on a trusted, unlocked machine. The card shows the words once
   and asks you to retype three of them; write all 24 words down in order on
   paper or another offline medium before confirming. The application never
   stores the phrase and cannot show it again.
2. Seal the written phrase and keep it separate from the backup media, the
   backup-password record, and the master-password record. Anyone holding the
   phrase can open the vault and every backup that was made while the phrase
   was active, because the phrase stays valid in restored copies of that vault.
3. Regenerate the phrase if it may have been seen, after using it, and after a
   data-key rotation that did not supply it (that rotation invalidates it and
   the application reports it). Regenerating invalidates the earlier phrase
   immediately. Destroy the old written copy.
4. Record in the kit inventory only that a phrase exists (the backup inventory
   carries `recovery_phrase_enrolled`). Never copy the words into the kit, the
   manifest, a filename, email, chat, or a note stored with the media.
5. If the phrase is used to recover: set the new master password, verify the
   records, create a fresh encrypted backup, then regenerate the phrase.

Phrase attempts share the master-password throttle, so a mistyped phrase delays
the next attempt; compare the written copy word by word instead of retrying
blindly.

## Two disconnected physical copies

Maintain at least two encrypted physical backup copies on separate removable
media. When not being written or verified, both copies must be disconnected
from computers and networks. Keep one copy in a separate physical location
from the computer and the other; a fireproof or otherwise protected location
is preferred. A stronger operating target is three encrypted copies across two
media types/devices, with at least one off-site.

Do not count a LAN peer, a sync cache, cloud storage, email, chat attachment,
or an online drive as one of the two disconnected recovery copies. Keep several
historical generations so a deletion, compromise, or bad sync cannot replace
the only usable version.

## Create and verify a kit

1. Lock the profile and close all LocalGateKeys processes, including the tray
   and native bridge.
2. Export an encrypted full backup with a new, independent backup password.
   Include attachments and preserve the profile name/version in the operator
   record, not in a secret-bearing filename.
3. Verify the backup using the backup password, vault master password, and the
   generated SHA-256 value. Verification must complete before copying it.
4. Create the non-secret recovery kit with the backup, installer/package,
   extension package, bridge instructions, and hashes. Inspect the kit as text
   and confirm that neither password appears in it.
5. Copy the verified backup, manifest, and kit to physical copy A. Eject the
   media and disconnect it.
6. Copy the same verified generation to physical copy B on different media.
   Recompute and compare hashes after the copy, then eject and disconnect it.
7. Record media labels, generation, version, hashes, verification date, and the
   separate locations of the password records. Never record the passwords in
   this inventory.

Perform a restore drill at least quarterly on a disposable Windows VM or spare
computer. Keep the original kit untouched, restore to a new profile, verify
expected non-secret metadata and attachments, then securely remove the drill
copy according to the organization’s media policy.

## Restore after a destroyed computer

1. Obtain a clean, supported Windows machine, apply operating-system updates,
   and keep it disconnected from the network unless a required OS operation
   explicitly needs access.
2. Retrieve one disconnected recovery copy and its separately stored password
   records. Do not modify the second copy.
3. Verify the installer/package and backup SHA-256 hashes against the manifest
   using a trusted local tool. If a hash differs, stop and use the other copy;
   preserve the suspect media for investigation.
4. Install the matching package. If it is unsigned development software, keep
   that warning visible and do not use it with real credentials until the
   release has been independently reviewed.
5. Start with a new destination profile and run restore in preview/dry-run
   mode. Confirm the version, manifest, attachment count, and destination
   paths before committing.
6. Commit the restore only after the preview is understood. The restored
   profile must start strict-offline, with automatic fill/sign-in and machine
   trust disabled. Re-enroll Windows Hello, face binding, or browser approval
   only after the restored vault has been inspected and the machine is trusted.
   If the application reports that the backup is older than the vault already
   on that machine, stop: restoring would roll the vault back. Confirm the
   rollback only when the newer vault is known to be unwanted or compromised;
   otherwise restore as a new profile instead.
7. Unlock with the vault master password, verify several known records and
   attachment hashes, and immediately create a fresh encrypted backup. Keep
   both old copies until that backup has been verified.
8. Reinstall the matching browser extension and native bridge only from the
   recovered package. Recheck the extension ID, native-host path, and hashes;
   do not pair a restored vault with an unverified extension.
9. Change passwords or revoke sessions if the original computer may have been
   accessed. Treat the original machine and any connected backup as suspect.

## Failure handling

- Wrong backup password, wrong master password, checksum failure, archive
  corruption, traversal, duplicate members, or quota failure must stop before
  any destination profile is mutated.
- Never overwrite a working profile during the first restore. Use a new
  destination, compare it, and retain the original backup generation.
- If restore publication or transfer commit fails, preserve the destination
  and source evidence, record the error, and retry only after confirming the
  rollback result. Do not manually copy encrypted sidecars into place.
- If a password is exposed, replace the affected backup generation and rotate
  the independent backup password. If the vault master password is exposed,
  rekey the vault after recovery and invalidate machine/browser trust.
- If the master password is lost but a recovery phrase exists, restore as a new
  profile, open it with the phrase, set a new master password, then regenerate
  the phrase. The backup password is still required to open the backup; the
  phrase does not replace it.
- If both password records are lost and there is no recovery phrase, the
  encrypted backup is not recoverable by this runbook. Do not weaken the KDF,
  guess at scale, or send the backup to a third party.

## Explicit limitations

Strict-offline mode prevents automatic/background external checks, but a user
can still explicitly open a bookmark, enable an external breach check, start
opt-in LAN sync, or run a build-time download for optional camera models. Those
actions are outside the disconnected-copy guarantee. LAN sync is an
availability/convenience mechanism, never the only recovery copy.

The release harness uses synthetic data and bounded local tests. It does not
prove signed artifacts, live browser/native messaging, screen-reader behavior,
high-DPI or multi-monitor behavior, router/firewall behavior, or a clean-machine
restore. The source scan is heuristic and cannot establish the absence of every
future telemetry or exfiltration bug. Complete the release verification and an
independent security review before using the product with real credentials.
