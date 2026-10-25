// Page payloads recorded from the real Python view builders (2026-10-22) for the demo vault in
// demoData.js: settings sections (shell/settings_sections.py through app/settings._Recorder), the
// Security center (shell/security_model.py), the health report (password_tools.vault_health) and the
// Sync screen (app/sync.SyncWebService.view). Replayed verbatim by mockApi.js so the screens show
// exactly what the app shows. Dev-only: nothing in the production build imports this file.

export const settingsPage = {
  "sections": [
    {
      "key": "locking",
      "title": "Locking",
      "column": 0,
      "subtitle": "",
      "keywords": [
        "lock",
        "timeout",
        "idle",
        "auto-lock",
        "sleep"
      ],
      "rows": [
        {
          "type": "choice",
          "key": "auto_lock_seconds",
          "title": "Lock after inactivity",
          "description": "When you have not used your computer or the vault",
          "value": 300,
          "options": [
            {
              "label": "Never",
              "value": 0
            },
            {
              "label": "1 minute",
              "value": 60
            },
            {
              "label": "5 minutes",
              "value": 300
            },
            {
              "label": "15 minutes",
              "value": 900
            },
            {
              "label": "30 minutes",
              "value": 1800
            },
            {
              "label": "1 hour",
              "value": 3600
            },
            {
              "label": "2 hours",
              "value": 7200
            },
            {
              "label": "4 hours",
              "value": 14400
            },
            {
              "label": "8 hours",
              "value": 28800
            },
            {
              "label": "12 hours",
              "value": 43200
            },
            {
              "label": "24 hours",
              "value": 86400
            }
          ]
        },
        {
          "type": "switch",
          "key": "lock_on_session_lock",
          "title": "Lock when Windows locks",
          "description": "Win+L, switching user or signing out",
          "value": true
        },
        {
          "type": "switch",
          "key": "lock_on_sleep",
          "title": "Lock on sleep",
          "description": "Laptop lid closed, sleep or hibernation",
          "value": true
        },
        {
          "type": "choice",
          "key": "max_session_seconds",
          "title": "Never stay unlocked longer than",
          "description": "Even while you are using it",
          "value": 28800,
          "options": [
            {
              "label": "Never",
              "value": 0
            },
            {
              "label": "1 minute",
              "value": 60
            },
            {
              "label": "5 minutes",
              "value": 300
            },
            {
              "label": "15 minutes",
              "value": 900
            },
            {
              "label": "30 minutes",
              "value": 1800
            },
            {
              "label": "1 hour",
              "value": 3600
            },
            {
              "label": "2 hours",
              "value": 7200
            },
            {
              "label": "4 hours",
              "value": 14400
            },
            {
              "label": "8 hours",
              "value": 28800
            },
            {
              "label": "12 hours",
              "value": 43200
            },
            {
              "label": "24 hours",
              "value": 86400
            }
          ]
        },
        {
          "type": "choice",
          "key": "idle_source",
          "title": "Count activity from",
          "description": "Computer: keyboard or mouse anywhere. Vault: using or saving items.",
          "value": "computer",
          "options": [
            {
              "label": "Computer activity",
              "value": "computer"
            },
            {
              "label": "Vault activity",
              "value": "vault"
            }
          ]
        },
        {
          "type": "switch",
          "key": "totp_confirm",
          "title": "Ask before releasing 2FA codes",
          "description": "Confirm on this PC each time the browser extension asks for a one-time code",
          "value": false
        }
      ]
    },
    {
      "key": "unlocking",
      "title": "Unlocking",
      "column": 0,
      "subtitle": "",
      "keywords": [
        "hello",
        "face",
        "camera",
        "biometric",
        "master",
        "recovery",
        "phrase"
      ],
      "rows": [
        {
          "type": "button",
          "title": "Windows Hello",
          "description": "On · fingerprint, face or PIN",
          "label": "Manage",
          "route": "hello",
          "params": {},
          "primary": false
        },
        {
          "type": "switch",
          "key": "hello_auto_start",
          "title": "Start Windows Hello automatically",
          "description": "When the unlock screen opens",
          "value": true
        },
        {
          "type": "button",
          "title": "Camera check",
          "description": "Not set up · less secure than Windows Hello",
          "label": "Set up",
          "route": "face",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Master password",
          "description": "Re-encrypts this vault. Backups keep the password they were made with.",
          "label": "Change…",
          "route": "master",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Recovery phrase",
          "description": "Set · unlocks if you forget the master password",
          "label": "Manage",
          "route": "recovery",
          "params": {},
          "primary": false
        }
      ]
    },
    {
      "key": "privacy",
      "title": "Privacy",
      "column": 0,
      "subtitle": "",
      "keywords": [
        "clipboard",
        "breach",
        "offline",
        "trash",
        "documents",
        "network"
      ],
      "rows": [
        {
          "type": "choice",
          "key": "clipboard_clear_seconds",
          "title": "Clear clipboard after",
          "description": "Only what LocalGateKeys copied is cleared",
          "value": 30,
          "options": [
            {
              "label": "Never",
              "value": 0
            },
            {
              "label": "5 seconds",
              "value": 5
            },
            {
              "label": "15 seconds",
              "value": 15
            },
            {
              "label": "30 seconds",
              "value": 30
            },
            {
              "label": "1 minute",
              "value": 60
            },
            {
              "label": "2 minutes",
              "value": 120
            },
            {
              "label": "5 minutes",
              "value": 300
            }
          ]
        },
        {
          "type": "switch",
          "key": "breach_check_enabled",
          "title": "Breach checks",
          "description": "You start each check. It sends 5 characters of a hash, never the password.",
          "value": false
        },
        {
          "type": "switch",
          "key": "strict_offline_mode",
          "title": "Strict offline mode",
          "description": "Blocks background internet requests, website icons and breach checks",
          "value": true
        },
        {
          "type": "switch",
          "key": "website_icons",
          "title": "Show website icons",
          "description": "Shows each site's logo. Downloading it tells that site you have an account there (nothing else is sent). Works in strict offline mode.",
          "value": true
        },
        {
          "type": "switch",
          "key": "trash_auto_purge",
          "title": "Empty trash automatically",
          "description": "When off, deleted items stay in the trash until you delete them",
          "value": true
        },
        {
          "type": "choice",
          "key": "trash_retention_days",
          "title": "Keep deleted items for",
          "description": "Used while automatic emptying is on",
          "value": 30,
          "options": [
            {
              "label": "7 days",
              "value": 7
            },
            {
              "label": "14 days",
              "value": 14
            },
            {
              "label": "30 days",
              "value": 30
            },
            {
              "label": "90 days",
              "value": 90
            }
          ]
        },
        {
          "type": "switch",
          "key": "document_open_enabled",
          "title": "Open documents in other apps",
          "description": "Puts a decrypted copy on this PC while you use it; deleted when you close it",
          "value": true
        }
      ]
    },
    {
      "key": "autofill",
      "title": "Autofill",
      "column": 1,
      "subtitle": "",
      "keywords": [
        "fill",
        "browser",
        "extension",
        "desktop",
        "shortcut",
        "hotkey"
      ],
      "rows": [
        {
          "type": "switch",
          "key": "browser_enabled",
          "title": "Browser autofill",
          "description": "Through the LocalGateKeys browser extension",
          "value": true
        },
        {
          "type": "switch",
          "key": "passkeys_enabled",
          "title": "Offer LocalGateKeys for passkeys",
          "description": "Create and use passkeys from this vault when a website asks. Off: the browser handles passkeys itself",
          "value": true
        },
        {
          "type": "switch",
          "key": "desktop_overlay_enabled",
          "title": "Desktop app autofill",
          "description": "Show a fill button beside supported desktop password fields",
          "value": true
        },
        {
          "type": "switch",
          "key": "fill_and_sign_in",
          "title": "Sign in after filling",
          "description": "Submit one supported sign-in form after you start a fill. CAPTCHA and MFA stay manual.",
          "value": false
        },
        {
          "type": "text",
          "key": "quick_access_hotkey",
          "title": "Quick access",
          "description": "Search and copy from anywhere · Ctrl, Alt, Shift or Win + a key",
          "value": "Ctrl+Alt+K"
        },
        {
          "type": "shortcut",
          "title": "Fill the focused app",
          "description": "Desktop fill",
          "keys": "Ctrl+Shift+Space"
        },
        {
          "type": "shortcut",
          "title": "Emergency lock",
          "description": "Lock and cancel pending fills",
          "keys": "Ctrl+Alt+L"
        }
      ]
    },
    {
      "key": "appearance",
      "title": "Appearance & app",
      "column": 1,
      "subtitle": "",
      "keywords": [
        "theme",
        "dark",
        "light",
        "startup",
        "tray",
        "updates",
        "version"
      ],
      "rows": [
        {
          "type": "segmented",
          "key": "appearance",
          "title": "Theme",
          "description": "Match Windows or choose one",
          "value": "light",
          "options": [
            {
              "label": "System",
              "value": "system"
            },
            {
              "label": "Light",
              "value": "light"
            },
            {
              "label": "Dark",
              "value": "dark"
            }
          ]
        },
        {
          "type": "switch",
          "key": "start_with_windows",
          "title": "Start with Windows",
          "description": "Starts locked in the background for this Windows account",
          "value": false
        },
        {
          "type": "switch",
          "key": "minimize_to_tray",
          "title": "Keep running in the tray",
          "description": "Closing the window keeps autofill working; it does not lock the vault",
          "value": true
        },
        {
          "type": "button",
          "title": "Updates",
          "description": "Version 0.4.8",
          "label": "Check now",
          "route": "updates",
          "params": {},
          "primary": false
        }
      ]
    },
    {
      "key": "backups",
      "title": "Backups",
      "column": 1,
      "subtitle": "",
      "keywords": [
        "backup",
        "schedule",
        "folder",
        "cloud",
        "mirror"
      ],
      "rows": [
        {
          "type": "choice",
          "key": "automatic_backup_count",
          "title": "Automatic backups to keep",
          "description": "Copies made as you save. Older ones may still hold deleted items.",
          "value": 5,
          "options": [
            {
              "label": "Off",
              "value": 0
            },
            {
              "label": "3 backups",
              "value": 3
            },
            {
              "label": "5 backups",
              "value": 5
            },
            {
              "label": "10 backups",
              "value": 10
            },
            {
              "label": "20 backups",
              "value": 20
            }
          ]
        },
        {
          "type": "folder",
          "key": "backup_mirror_dir",
          "title": "Cloud copy",
          "value": "D:\\Dropbox\\LocalGateKeys Backups"
        },
        {
          "type": "choice",
          "key": "scheduled_backup_frequency",
          "title": "Scheduled backups",
          "description": "Runs while unlocked. A run missed while the app was closed happens at the next unlock.",
          "value": "off",
          "options": [
            {
              "label": "Off",
              "value": "off"
            },
            {
              "label": "Daily",
              "value": "daily"
            },
            {
              "label": "Weekly",
              "value": "weekly"
            }
          ]
        },
        {
          "type": "text",
          "key": "scheduled_backup_time",
          "title": "Time of day",
          "description": "24-hour local time, for example 08:30",
          "value": "12:00"
        },
        {
          "type": "choice",
          "key": "scheduled_backup_weekday",
          "title": "Day of the week",
          "description": "For weekly backups",
          "value": 0,
          "options": [
            {
              "label": "Monday",
              "value": 0
            },
            {
              "label": "Tuesday",
              "value": 1
            },
            {
              "label": "Wednesday",
              "value": 2
            },
            {
              "label": "Thursday",
              "value": 3
            },
            {
              "label": "Friday",
              "value": 4
            },
            {
              "label": "Saturday",
              "value": 5
            },
            {
              "label": "Sunday",
              "value": 6
            }
          ]
        },
        {
          "type": "choice",
          "key": "scheduled_backup_keep",
          "title": "Old scheduled backups",
          "description": "A new backup is written and checked before the oldest is deleted",
          "value": 2,
          "options": [
            {
              "label": "Keep only the latest",
              "value": 1
            },
            {
              "label": "Keep latest + previous",
              "value": 2
            }
          ]
        },
        {
          "type": "button",
          "title": "Backup password",
          "description": "Set · kept only inside your encrypted vault",
          "label": "Change…",
          "route": "backup_password",
          "params": {
            "clear": false
          },
          "primary": false
        },
        {
          "type": "button",
          "title": "Clear backup password",
          "description": "Scheduled backups stop until you set one again",
          "label": "Clear",
          "route": "backup_password",
          "params": {
            "clear": true
          },
          "primary": false
        },
        {
          "type": "note",
          "text": "Last scheduled backup: 2026-10-21 08:30"
        }
      ]
    },
    {
      "key": "plan",
      "title": "Plan & sync",
      "column": 1,
      "subtitle": "",
      "keywords": [
        "licence",
        "license",
        "pro",
        "upgrade",
        "sync",
        "devices"
      ],
      "rows": [
        {
          "type": "button",
          "title": "Licence",
          "description": "LocalGateKeys Pro",
          "label": "Open",
          "route": "licence",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Device sync",
          "description": "Wi-Fi and cloud-folder sync between your devices",
          "label": "Open",
          "route": "sync",
          "params": {},
          "primary": false
        }
      ]
    },
    {
      "key": "help",
      "title": "Help & diagnostics",
      "column": 1,
      "subtitle": "",
      "keywords": [
        "shortcuts",
        "guide",
        "diagnostics",
        "log",
        "support"
      ],
      "rows": [
        {
          "type": "button",
          "title": "Keyboard shortcuts",
          "description": "Also with F1",
          "label": "View",
          "route": "shortcuts",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Setup guide",
          "description": "Walk through the basics again",
          "label": "Open",
          "route": "onboarding",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Devices & connections",
          "description": "Browser extension status and diagnostics",
          "label": "Open",
          "route": "connections",
          "params": {},
          "primary": false
        },
        {
          "type": "button",
          "title": "Error log",
          "description": "Technical log files; they contain no secrets",
          "label": "Open",
          "route": "errorlog",
          "params": {},
          "primary": false
        }
      ]
    }
  ],
  "saved_text": "Changes save as you make them"
};

export const securityCenter = {
  "score": 77,
  "label": "Fair",
  "headline": "Fair overall. Fixing the flagged logins below would bring you to 100.",
  "issues": [
    {
      "key": "weak",
      "count": 1,
      "title": "Weak passwords",
      "description": "Reddit",
      "tone": "warning",
      "action": {
        "label": "Review 1",
        "route": "health",
        "params": {
          "filter": "weak"
        }
      }
    },
    {
      "key": "reused",
      "count": 2,
      "title": "Reused passwords",
      "description": "Discord, Spotify share a password with another login",
      "tone": "warning",
      "action": {
        "label": "Review 2",
        "route": "health",
        "params": {
          "filter": "reused"
        }
      }
    },
    {
      "key": "no_2fa",
      "count": 6,
      "title": "Two-factor not set up",
      "description": "Add a one-time code to these logins where the site offers it",
      "tone": "accent",
      "action": {
        "label": "Set up 2FA",
        "route": "health",
        "params": {
          "filter": "no_2fa"
        }
      }
    },
    {
      "key": "old",
      "count": 1,
      "title": "Not changed in over a year",
      "description": "Low risk; change when convenient",
      "tone": "neutral",
      "action": {
        "label": "Review 1",
        "route": "health",
        "params": {
          "filter": "old"
        }
      }
    }
  ],
  "panels": [
    {
      "title": "How you unlock",
      "rows": [
        {
          "label": "Master password",
          "meta": "Always works, even when other methods are off",
          "meta_tone": "neutral",
          "action": {
            "label": "Change…",
            "route": "master",
            "params": {}
          }
        },
        {
          "label": "Windows Hello",
          "meta": "On · fingerprint, face or PIN",
          "meta_tone": "neutral",
          "action": {
            "label": "Manage",
            "route": "hello",
            "params": {}
          }
        },
        {
          "label": "Camera check",
          "meta": "Not set up",
          "meta_tone": "neutral",
          "action": {
            "label": "Set up",
            "route": "face",
            "params": {}
          }
        },
        {
          "label": "Recovery phrase",
          "meta": "Set · unlocks if you forget the master password",
          "meta_tone": "neutral",
          "action": {
            "label": "Manage",
            "route": "recovery",
            "params": {
              "initial": "create"
            }
          }
        },
        {
          "label": "Auto-lock",
          "meta": "After 5 minutes idle · when Windows locks · on sleep",
          "meta_tone": "neutral",
          "action": {
            "label": "Edit",
            "route": "settings",
            "params": {
              "section": "locking"
            }
          }
        }
      ]
    },
    {
      "title": "Backups",
      "rows": [
        {
          "label": "Last backup",
          "meta": "3 hours ago · 14 copies kept",
          "meta_tone": "neutral",
          "action": {
            "label": "Back up now",
            "route": "recovery",
            "params": {
              "initial": "create"
            }
          }
        },
        {
          "label": "Check a backup",
          "meta": "Open it and confirm every item is there",
          "meta_tone": "neutral",
          "action": {
            "label": "Verify",
            "route": "recovery",
            "params": {
              "initial": "verify"
            }
          }
        },
        {
          "label": "Restore from a backup",
          "meta": "Bring items back from a backup file",
          "meta_tone": "neutral",
          "action": {
            "label": "Restore…",
            "route": "recovery",
            "params": {
              "initial": "restore"
            }
          }
        },
        {
          "label": "Recovery kit",
          "meta": "Printable sheet for when you forget everything",
          "meta_tone": "neutral",
          "action": {
            "label": "Write kit",
            "route": "recovery",
            "params": {
              "initial": "kit"
            }
          }
        }
      ]
    },
    {
      "title": "Moving data",
      "rows": [
        {
          "label": "Export vault",
          "meta": "Creates an unencrypted file; delete it when you are done",
          "meta_tone": "neutral",
          "action": {
            "label": "Export…",
            "route": "export",
            "params": {}
          }
        },
        {
          "label": "Encrypted transfer",
          "meta": "Move items to another LocalGateKeys profile or PC",
          "meta_tone": "neutral",
          "action": {
            "label": "Open",
            "route": "transfer",
            "params": {}
          }
        },
        {
          "label": "Import",
          "meta": "From another password manager or a file",
          "meta_tone": "neutral",
          "action": {
            "label": "Import…",
            "route": "import",
            "params": {}
          }
        }
      ]
    },
    {
      "title": "Privacy",
      "rows": [
        {
          "label": "Clipboard",
          "meta": "Cleared 30 seconds after copying",
          "meta_tone": "neutral",
          "action": {
            "label": "Edit",
            "route": "settings",
            "params": {
              "section": "privacy"
            }
          }
        },
        {
          "label": "Breach checks",
          "meta": "Off",
          "meta_tone": "neutral",
          "action": {
            "label": "Turn on",
            "route": "set",
            "params": {
              "key": "breach_check_enabled",
              "value": true
            }
          }
        },
        {
          "label": "Strict offline mode",
          "meta": "On · no background network access",
          "meta_tone": "neutral",
          "action": {
            "label": "Turn off",
            "route": "set",
            "params": {
              "key": "strict_offline_mode",
              "value": false
            }
          }
        }
      ]
    }
  ],
  "footnote": "Breach checks send only the first 5 characters of a password hash, and only when you start one. Strict offline mode blocks them."
};

export const healthReport = {
  "summary": "13 logins · 1 weak · 2 reused · 6 without 2FA · 1 older than a year",
  "rows": [
    {
      "id": "github",
      "label": "GitHub",
      "username": "alex-morgan-dev",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "google",
      "label": "Google",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "netflix",
      "label": "Netflix",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [
        "no_2fa"
      ],
      "findings": "No 2FA",
      "breach": "Not checked"
    },
    {
      "id": "dropbox",
      "label": "Dropbox",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "paypal",
      "label": "PayPal",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "spotify",
      "label": "Spotify",
      "username": "alexmorgan.music",
      "score": 4,
      "categories": [
        "reused",
        "no_2fa"
      ],
      "findings": "Reused, No 2FA",
      "breach": "Not checked"
    },
    {
      "id": "steam",
      "label": "Steam",
      "username": "quiet_otter_42",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "discord",
      "label": "Discord",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [
        "reused",
        "no_2fa"
      ],
      "findings": "Reused, No 2FA",
      "breach": "Not checked"
    },
    {
      "id": "reddit",
      "label": "Reddit",
      "username": "quiet_otter_42",
      "score": 1,
      "categories": [
        "weak",
        "no_2fa"
      ],
      "findings": "Weak, No 2FA",
      "breach": "Not checked"
    },
    {
      "id": "notion",
      "label": "Notion",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    },
    {
      "id": "figma",
      "label": "Figma",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [
        "no_2fa"
      ],
      "findings": "No 2FA",
      "breach": "Not checked"
    },
    {
      "id": "airbnb",
      "label": "Airbnb",
      "username": "alex.morgan@example.com",
      "score": 4,
      "categories": [
        "no_2fa",
        "old"
      ],
      "findings": "No 2FA, Old (>1 year)",
      "breach": "Not checked"
    },
    {
      "id": "proton",
      "label": "Proton Mail",
      "username": "alex.morgan@proton.example",
      "score": 4,
      "categories": [],
      "findings": "No local flag",
      "breach": "Not checked"
    }
  ],
  "subtitle": "Local pattern checks are guidance, not a guarantee. Password age alone is not a reason to change it. Focus on reuse, guessability and known exposure.",
  "footer": "No check is performed automatically. Passwords, hashes and results are not logged.",
  "filters": [
    {
      "label": "All",
      "key": null
    },
    {
      "label": "Weak",
      "key": "weak"
    },
    {
      "label": "Reused",
      "key": "reused"
    },
    {
      "label": "No 2FA",
      "key": "no_2fa"
    },
    {
      "label": "Old (>1 year)",
      "key": "old"
    },
    {
      "label": "Exposed (HIBP)",
      "key": "exposed"
    }
  ],
  "running": false
};

export const syncView = {
  "intro": "Keep this vault in step on your phone and other PCs. Everything is encrypted before it leaves this PC.",
  "status_line": "",
  "banner": null,
  "cards": [
    {
      "key": "wifi",
      "title": "Wi-Fi (this network)",
      "state": "on",
      "state_text": "On. This PC listens on 192.168.1.24:47821.",
      "last_sync_text": "Last synced 15 min ago",
      "banner": null,
      "hint": "",
      "members_heading": "Paired devices",
      "members": [
        {
          "id": "dev-phone",
          "name": "Alex's iPhone",
          "detail": "Connects to this PC",
          "is_self": false,
          "removable": true
        }
      ],
      "issues": [],
      "actions": [
        {
          "id": "sync-now",
          "label": "Sync now",
          "primary": true
        },
        {
          "id": "show-qr",
          "label": "Show QR code…",
          "primary": true
        },
        {
          "id": "remove-device",
          "label": "Remove a device…",
          "primary": false
        },
        {
          "id": "wifi-disable",
          "label": "Turn off Wi-Fi sync",
          "primary": false
        }
      ]
    },
    {
      "key": "folder",
      "title": "Cloud folder",
      "state": "on",
      "state_text": "On. Folder: D:\\Dropbox\\LocalGateKeys Sync",
      "last_sync_text": "Last synced 4 min ago",
      "banner": null,
      "hint": "",
      "members_heading": "Devices",
      "members": [
        {
          "id": "dev-desktop",
          "name": "Alex's desktop",
          "detail": "This PC",
          "is_self": true,
          "removable": false
        },
        {
          "id": "dev-phone",
          "name": "Alex's iPhone",
          "detail": "",
          "is_self": false,
          "removable": true
        },
        {
          "id": "dev-laptop",
          "name": "Travel laptop",
          "detail": "",
          "is_self": false,
          "removable": true
        }
      ],
      "issues": [],
      "actions": [
        {
          "id": "sync-now",
          "label": "Sync now",
          "primary": true
        },
        {
          "id": "change-password",
          "label": "Change sync password…",
          "primary": false
        },
        {
          "id": "remove-device",
          "label": "Remove a device…",
          "primary": false
        },
        {
          "id": "leave",
          "label": "Leave sync…",
          "primary": false
        }
      ]
    }
  ],
  "skipped": [],
  "available": true,
  "busy": false,
  "advice": "Write this password down. Never reuse an earlier sync password.",
  "pro": true,
  "pro_text": "Device sync is part of LocalGateKeys Pro. Everything already on this PC stays here and keeps working; with Pro, sync resumes where it left off."
};

export const overviewHealth = {
  "score": 77,
  "label": "Fair",
  "weak": 1,
  "reused": 2,
  "no_2fa": 6
};

export const reminders = [
  {
    "date": "OCT 26",
    "label": "Netflix plan renews",
    "meta": "4 days",
    "overdue": false
  },
  {
    "date": "NOV 10",
    "label": "Visa card expires soon",
    "meta": "19 days",
    "overdue": false
  },
  {
    "date": "DEC 2",
    "label": "Rotate GitHub token",
    "meta": "41 days",
    "overdue": false
  }
];

export const flags = {
  "weak": [
    "reddit"
  ],
  "reused": [
    "discord",
    "spotify"
  ],
  "no_2fa": [
    "airbnb",
    "discord",
    "figma",
    "netflix",
    "reddit",
    "spotify"
  ],
  "attention": [
    "discord",
    "reddit",
    "spotify"
  ]
};
