# Deployment Topology

FireAlive supports **two deployment modes**. This document describes each one,
which processes run, what each writes where, and what an installer replaces on an
update. There is no container mode: the platform seals its Tier-1 key to the host
TPM 2.0 / Secure Enclave and fails closed without a hardware root of trust, so a
portable container image (which has no persistent hardware identity) is not a
supported substrate.

Both modes require a hardware root of trust on every host (see
`SETUP.md` → Prerequisites and `docs/tier1-kek-hardware-sealing.md`).

## The processes

FireAlive is five components across two servers:

- **Management Console (MC)** — an Electron desktop app that **embeds the
  Regional Server** as a child process. The Regional Server is the per-region
  backend the Analyst Clients talk to. Default Regional Server port: **3000**.
- **Analyst Client (AC)** — an Electron desktop app the analysts run; it connects
  over the network to a Regional Server. It runs no server of its own.
- **Global Dashboard (GD)** — an Electron desktop app that **embeds the GD
  Server** as a child process. The GD Server aggregates across regions. Default
  GD Server port: **4001**.

The MC's `main.js` and the GD app's `main.js` each spawn their embedded server as
a Node runtime (`ELECTRON_RUN_AS_NODE`) with `NODE_ENV=production`; the servers
are not launched separately by the operator in this mode.

## Mode 1 — packaged Electron installers (the supported production path)

Team Leads install the **Management Console** (which brings the Regional Server
with it) and provision **Analyst Clients**; CISOs install the **Global
Dashboard**. Installers are published on GitHub Releases per OS.

**Program files (what the installer writes, and replaces on update):**

| OS | Installed application location |
| --- | --- |
| macOS | `/Applications/<AppName>.app` (or `~/Applications/…`) |
| Windows | `%LOCALAPPDATA%\Programs\<AppName>\` (NSIS per-user default) |
| Linux | wherever the AppImage is placed by the user; extracted read-only squashfs at run time |

Inside the app bundle, `resources/server/` (MC) and
`resources/global-dashboard-server/` (GD app) hold the embedded server's code,
its `node_modules`, and its **code-integrity manifest** (`integrity-manifest.json`),
which the server verifies against its own files at boot and **refuses to start in
production if the code was modified or the manifest is absent**.

**Persistent data (what the installer NEVER touches):**

All runtime state lives under a per-user data root outside the bundle:
`~/.firealive/` on macOS/Linux, `%USERPROFILE%\.firealive\` on Windows. It holds
the SQLite database, the audit log, backups, the model directory, and the KEK
keystore, created at `0700` and permission-checked on every boot. An update
replaces only the program files; a rollback is a restore from a backup taken on
the previous version (see `SETUP.md` → Data Location, Updates, and Rollback). To
erase FireAlive's data, delete the data root by hand after uninstalling.

## Mode 2 — running from source (development and evaluation)

Clone the repository and run each server directly with Node; run the desktop apps
in dev mode. This is the path in `SETUP.md` → Building from Source.

- The Regional Server runs as `node server/index.js` (port 3000); the GD Server
  as `node index.js` from `packages/global-dashboard-server/` (port 4001).
- Code lives in the working tree; there is no `resources/` bundle. Generate the
  code-integrity manifests locally with
  `node server/services/integrity.js --generate` and
  `node packages/global-dashboard-server/services/gd-integrity.js --generate`.
  Outside production the integrity gate warns rather than halts, so a dev tree
  with no manifest or local edits still runs.
- Secrets come from a root `.env` (never committed). The Tier-1 KEK is still
  hardware-sealed — run `node scripts/provision-tier1-kek.js` first — because the
  server fails closed without it in every mode.
- Persistent data still lives under `~/.firealive/`; running from source does not
  change the data-root convention.

## Which mode writes where — summary

| | Program code | Persistent data | Integrity manifest |
| --- | --- | --- | --- |
| **Installers** | inside the app bundle (`resources/…`), replaced on update | `~/.firealive/` (survives update + uninstall) | shipped in the bundle, generated in CI |
| **From source** | the working tree | `~/.firealive/` | generated locally with `--generate` |

In both modes the boundary is the same: **code is replaceable and integrity-
checked; data lives in `~/.firealive/` and is owned by the operator.** An
installer or a `git pull` changes the former and never the latter.
