# AI agents and LocalGateKeys (`lgk mcp`)

LocalGateKeys Pro can let an AI agent (Claude Code, a browser agent, any MCP client) ask to sign in to a website for
you. No tool reply contains the password, but the sign-in itself writes the password into the web page, so the page,
and any agent that automates that browser (Playwright, DevTools, a browser extension with script access), can read
it. Approve a sign-in only for an agent you would trust with that password.

An agent can also ask to run one command with secrets from your vault (an API key, an SSH key, a note) in its
environment. The command itself receives the secrets and can do anything with them, including sending them anywhere;
LocalGateKeys only hides them from the output it hands back to the agent. Approve a run only for a command you would
run yourself with that secret. Everything runs on your PC: there is no LocalGateKeys server.

## Turn it on

1. LocalGateKeys Pro, Windows app, unlocked.
2. Settings › Developer › **Allow AI agents to use LocalGateKeys**. Optional: **Require Windows Hello for each
   approval**.
3. Add the server to your MCP client. Claude Code:

   ```
   claude mcp add localgatekeys -- lgk mcp
   ```

   Other clients: run `lgk mcp` as a stdio server (command `lgk`, argument `mcp`). Where `lgk` is not on PATH, use
   the full path of `lgk.exe`.

> Availability: the Microsoft Store package (now the only Windows build) does not contain `lgk.exe`: its one app
> execution alias is the browser bridge's. The bridge exe runs the same server instead:
> `claude mcp add localgatekeys -- LocalGateKeysNativeHost.exe mcp` (and `LocalGateKeysNativeHost.exe lgk ...` for
> the rest of the CLI). Started that way (not by a browser), the app gives it the CLI service only, never the
> browser broker (`pipe_transport.HOST_SCOPE`). The Developer page shows the command.

### On the Mac

The Mac app has the same server with the same three tools and rules (in the source; not yet in a released Mac
build).

1. LocalGateKeys Pro, Mac app, running and unlocked.
2. Settings › Developer › **Allow AI agents to use LocalGateKeys** (off by default, stays on this Mac). Optional:
   **Require Touch ID for each approval** (the master password where Touch ID is not available).
3. Copy the command from that page. It names `lgk` inside the app bundle:

   ```
   claude mcp add localgatekeys -- "/Applications/LocalGateKeys.app/Contents/MacOS/lgk" mcp
   ```

4. Turn on the LocalGateKeys extension in Safari. Sign-ins are filled only there.

`lgk` reads no vault file and opens no network port: it passes each tool call to the running app over a private
socket in the app's group container (owner-only). The approval opens as a floating panel that names the agent, the
program that started `lgk`, the site and the agent's purpose in quotes; *Approve once* is the only yes and is never
the default button. On a sign-in, click the LocalGateKeys icon in the site's sign-in field in Safari, then pick the
login in the list: that second click releases it. On the Mac the icon appears in Safari only while the setting is
on, and it fills nothing but an approved agent sign-in. A passkey grant fills nothing: the agent is told to choose
the site's passkey sign-in, which goes through the system passkey dialog as usual. Closing the app's window ends any
waiting grant; while the app is locked, tools answer `locked`.

The per-login switch *AI agents may use this login* is set in the Windows app for now; it syncs to the Mac.

## Choose the logins an agent may use

Agents see no login until you allow it: open the login, then *Autofill rules* › **AI agents may use this login**
(off by default). A login without it does not exist for an agent: `list_sites` leaves it out and `request_login`
answers `not_found`, exactly as for a site where you have no login. Logins you import, receive in a share or restore
from an export arrive with the switch off.

If the login has a passkey saved for the site, an agent's sign-in uses the passkey and never fills the password. The
approval says which will happen: *Sign in with the passkey* or *Fill the password (the agent can read it)*. For a
passkey sign-in the agent is told to choose the site's passkey sign-in; LocalGateKeys then shows its usual passkey
dialog and asks for Windows Hello or the master password as for any passkey sign-in. The site receives a one-time
signature, not a reusable secret. The approval allows one passkey sign-in on the approved hosts within its 5
minutes. With the Windows system passkey provider turned on, the browser asks Windows instead of the extension, so
an agent's passkey grant is not used there.

## Choose the secrets an agent may use in a command

API keys, SSH keys and secure notes have their own switch: open the item and turn on **AI agents may use this item**
(off by default). The switch is a setting of this device, not part of the item: it does not sync, and items you
import, receive in a share or restore from a backup arrive with it off. An item without it does not exist for an
agent: `list_secrets` leaves it out and a reference to it answers `not_found`, exactly as for an item you do not have,
without asking you. Logins never take part in a run.

The fields an agent can name are, for an API key, `key`, `secret` and `service`; for an SSH key, `private_key`,
`passphrase` and `public_key`; for a note, `body` and its custom fields. Only fields with a value are listed.

## What the agent can do

| Tool | What it returns |
|---|---|
| `list_sites(query)` | After **you** approve it once for that agent session: titles and registrable domains of your logins. No usernames, no passwords. |
| `request_login(site, purpose)` | After **you** click *Approve once* in the LocalGateKeys palette: a grant id, valid 5 minutes, one use, for the exact sign-in hosts shown in the approval (the host the agent named, or the hosts the matching logins are saved for), only for those logins, and for that agent session only. `method` says `passkey` or `password`; a passkey grant also carries a `note` on what to do. |
| `fill_login(grant, tab_hint)` | Arms the grant for 60 seconds. When **you** click the LocalGateKeys icon in the sign-in field on an approved host, the picker offers the approved login(s) and you pick one; it is then filled into the page. The reply says only whether the page took the grant, but the page (and anything automating the browser) can read the filled password. Focus alone, or a page script, never releases it. |
| `list_secrets(query)` | After the same once-per-session approval as `list_sites`: id, title, type and field names of the API keys, SSH keys and notes you allowed. Never a value. |
| `run_with_secrets(command, env, purpose, timeout_seconds)` | After **you** click *Approve once*: runs `command` (a list of arguments, never a shell string) once, in the agent's working folder, with each variable in `env` set to the value of an `lgk://<item id or title>/<field>` reference. The reply is only `exit_code`, `stdout`, `stderr`, `truncated` and `timed_out`, with the secrets masked in the output. |

### How a run works

1. The agent calls `run_with_secrets`. `lgk mcp` checks the request, finds the program on PATH and turns it into a
   full path, so the approval shows the exact program that will run.
2. LocalGateKeys shows the approval: the agent, its program, the exact command line, the working folder, each
   variable with its item and field, the time limit and the purpose as quoted text. *Approve once* is the only yes;
   with **Require Windows Hello for each approval** on, Windows Hello (or the master password) follows.
3. The values go back over the local pipe to that `lgk mcp` process only, once, within 60 seconds. One approval is one
   run; it cannot be used by another agent session or a second time.
4. `lgk mcp` starts the program directly (no shell, no window) with the values in its environment, waits at most
   `timeout_seconds` (default 120, at most 600), then stops it and everything it started (a Windows job object).
5. The output is cut to 64 KiB per stream and every secret in it is replaced by `<concealed by LocalGateKeys>`: the value as is, as
   UTF-16 and in the Windows code page, in base64 (standard and URL-safe), hex, URL encoding and JSON escaping. Then
   `lgk mcp` forgets the values and replies.

Limits: a run refuses values shorter than 4 characters (`too_short`, too short to mask safely), the variables
`PATH`, `PATHEXT`, `COMSPEC`, `SYSTEMROOT` and `WINDIR`, names that differ only in case, and a `.bat` or `.cmd`
program with `& | < > ^ % ! " ( )` or a backtick in its arguments (cmd.exe would read them as commands). While a
command runs, the server answers no other tool call.

## What the agent can never do

- Get a password, a one-time code, a private key or any other secret in a tool reply. No tool reveals or copies a
  value. This does not stop an agent that also drives your browser from reading a password after it is filled into
  the page: the filled form is ordinary page content. Nor does it stop a command you approved in
  `run_with_secrets`: that command has the secrets and can write them to a file, send them over the network or
  print them in a form the masking does not know (reversed, split, compressed, encrypted). Masking keeps the secret
  out of the reply, not out of the command's hands.
- Trigger the fill itself. The browser extension releases an agent grant only on your own click on its icon and in
  its picker, never on page focus or a script's event.
- Approve its own request. The `purpose` text is shown to you quoted, as data; nothing in it can approve. There is
  no "always allow" in this version.
- Use a login you did not switch to *AI agents may use this login*, one that asks for the master password every time
  (strict), or one set to never fill.
- Get the password of a login that has a passkey for the site: the passkey signs in instead. The remaining limit:
  the password of an allowed login **without** a passkey is filled into the page, where an agent driving the
  browser can read it.
- Use a grant on another site or host. The page's host must be one of the exact hosts in the approval, on https
  (an approval for `login.example.com` does not work on `files.example.com` or `examp1e.com`), and only the
  approved logins are offered.
- Use another agent's grant. Grants are bound to the `lgk mcp` process session that asked.
- Use an API key, SSH key or note you did not switch to *AI agents may use this item*, or any login, in a run.
- Change the command after you approved it, run it twice, or run it through a shell. The program path, arguments
  and folder you saw are the ones used.

## Threat model in short

- **Prompt injection.** A web page or document may tell the agent to ask for logins or to run a command that sends a
  secret somewhere. Every request still needs your click in the palette window, which names the agent, its program,
  the site or the exact command, and the stated purpose. Read the command line before you approve a run: a script
  you do not know can do anything with the secret.
- **A rogue local program.** The `lgk` pipe scope is pinned to the installed `lgk.exe`; the agent's program name in
  the dialog comes from Windows, not from the request. On the Mac the socket is owner-only, so any program of your
  user account can connect, as it could start `lgk`; the program name comes from macOS (the process that started
  `lgk`), and only the signed LocalGateKeys Safari extension may ask for a fill.
- **Flooding.** One approval at a time, at most 3 requests per agent session and 10 in total per minute. An
  approval left unanswered for 2 minutes counts as a no.
- **Locked vault.** Tools answer `locked` within 30 seconds and the app shows its unlock prompt; nothing hangs.
- **Audit.** Every tool call is written to the activity log as a content-free event (`agent.search`,
  `agent.request`, `agent.fill`). The log is hash-chained: the Security check shows *Access log
  verified* or *Access log altered*; the bridge can export it as JSON lines with each event's hash. A run adds
  `agent.read` when the values are handed over and `agent.complete` when the command ends, each with the item id.
  The command line, folder, purpose, variable and field names and the outcome of each run go to a separate log,
  encrypted for your Windows account (`agent-runs.json` in the profile folder, last 200 entries), shown under
  Settings › Developer › *Recent AI agent runs*. No log holds a secret value.
