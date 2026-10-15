# pager-payloads

A real-time, **MFA-aware credential relay framework** for the WiFi Pineapple (Pager / Mark VII, OpenWrt 24.10.1), backed by a from-scratch captive-portal platform — built for authorized wireless security assessments.

The relay engine intercepts credentials from a captive portal, replays them against the **live** target in a controlled browser, and — the hard part — **automatically completes the one-time-password step** by waiting for the OTP to arrive out of band and entering it, then reports the outcome back. The entire framework retargets to a new login portal by editing a single config file.

> ⚠️ **Authorized testing only.** This performs adversary-in-the-middle credential capture and live MFA relay. Use it exclusively against systems you own or have explicit written permission to assess. See the [disclaimer](#disclaimer).

---

## How the relay works

```
Victim device
    │  submits credentials to the captive portal
    ▼
WiFi Pineapple — Evil Portal
    │  forwards to the relay over an SSH tunnel (:9999)
    ▼
Android device — Termux (Kotlin app + Python relay)
    │  HTTP server receives the credentials
    │  Selenium + Firefox submits them to the REAL target
    │  detects outcome:  success  /  MFA required  /  failed
    │  if MFA: waits for the OTP (separate endpoint), enters it, validates
    ▲  returns the result to the Pineapple (:9998)
```

The victim sees a believable login (and MFA prompt); the framework is authenticating as them against the real service in real time.

---

## The relay engine (the core)

A modular Python framework (controlled by a Kotlin Android app running under Termux) that automates a login — including MFA — against a live target.

### Real-time MFA handling
This is the differentiator. The one-time password arrives **out of band**, on a separate HTTP endpoint, *after* the login attempt is already in flight. The engine:

- blocks a worker thread on a `threading.Event` until the OTP is delivered (300s timeout),
- fills and validates it in the live browser session,
- retries with bounded attempts (`MAX_MFA_RETRIES`) and reports `mfa_success` / `mfa_failed` back through the chain,
- runs the whole MFA flow on a daemon thread so the HTTP server stays responsive to the incoming OTP.

Relaying a live OTP this way defeats OTP-based MFA for the duration of the session — which is the capability the framework exists to demonstrate.

### Config-driven retargeting (phishlet pattern)
`phishlet.py` is the single source of truth for everything target-specific — login path, field names, submit button, success/failure indicators, and the full MFA interaction profile (input IDs, OTP length, validate button, success/failure markers). **Every other module imports from it; no other file changes to target a new portal.** Misconfiguration surfaces as named, actionable errors (e.g. *"Could not find username field 'X' — check USERNAME_FIELD in phishlet"*).

### Structured result objects
Functions return a consistent `{"success": bool, "error": str | None, ...}` shape rather than throwing or returning bare values, so outcomes propagate with context across the whole chain (`main → server → login_handler → mfa_handler → result_notifier`) and nothing fails silently.

### Defensive browser automation
Selenium interactions assume the page will fight back: credential fill verifies the field value took and falls back to JavaScript injection; the MFA validate button has a DOM-click path with a jQuery fallback; outcome detection *polls* URL, page source, and input count rather than trusting one signal. A pre-flight reachability check distinguishes "server responded 403/404" (proceed) from "DNS/connection failure" (fatal).

### Android orchestration
The Kotlin app (`AuthRelayApp`) handles the full device bring-up: device-type selection, Termux verification, Pineapple connectivity check, SSH key generation and transfer, Python module deployment, Evil WPA configuration, and relay monitoring. Modules are redeployed from bundled resources on every run, so the device always executes the current version. Full detail in [`auth-relay-framework/README.md`](auth-relay-framework/README.md).

---

## The captive-portal platform

Not a wrapper around existing tooling — a from-scratch Evil Portal reimplementation for the Pager (OpenWrt), provisioned by `evil_portal/install_evil_portal/payload.sh` and managed by a set of modular payloads.

### What the installer builds (idempotently)
- **A LEMP-style stack**, installed per-package with `opkg list-installed` checks that skip what's present and verify what's critical before continuing.
- **A PHP captive-portal API** generated inline — an abstract `Portal` base class with route → authorize → redirect logic, a client-authorization file, and a SQLite-backed SSID lookup.
- **A tuned nginx config** whose URL rewrites (`/capture`, `/mfa_result`, `/mfa_status`, `/login_result`) are the server-side hooks the **relay engine posts back to** — this is where the two halves of the repo meet.
- **A hand-written OpenWrt init script** (`/etc/init.d/evilportal`) with a full service lifecycle (`start`/`stop`/`restart`/`enable`/`disable`/`switch`) that deliberately separates **ephemeral in-memory nftables rules** from **persistent UCI firewall redirects**.
- **A polling whitelist daemon** that watches the authorized-clients file and inserts `nft` accept rules, using the live nftables ruleset as the source of truth.
- **Transparent interception**: :80/:443/:53 redirected to the portal, DNS spoofed via a dnsmasq instance on :5353, and OS-specific probe pages for Android (`generate_204`) and iOS/macOS (`hotspot-detect`).
- **A verification phase**: curls the portal, confirms NAT rules in `nft list ruleset`, checks symlinks, and reports per-service status.

### UCI-safe interface control
`interface_manager` and `set_evil_portal_interface` manage the three radios (`wlan0wpa` / `wlan0open` / `wlan0mgmt`) with care for real OpenWrt pitfalls:
- Before toggling an interface, it harvests **pending uncommitted** SSID/key edits from the `uci changes` buffer, reverts them for a clean commit, then re-stages them — so a user's half-made config isn't clobbered.
- A safety state machine reasons about enabled-vs-UP counts and warns before all three interfaces are up at once (which severs management connectivity on this hardware).

### WordPress portal front end
`wordpress_web_root/` is the served portal: a convincing WordPress login, an MFA/OTP page, success/failure states, and the PHP that captures credentials and signals results back to the relay. `setup_wordpress_portal` bundles the WordPress CSS/JS/fonts locally (no external fetches at portal-serve time).

---

## Repository structure

```
pager-payloads/
├── auth-relay-framework/     # THE RELAY ENGINE
│   ├── AuthRelayApp/         #   Kotlin Android app + bundled Python relay modules
│   │   └── …/res/raw/        #   phishlet, server, login_handler, mfa_handler, …
│   └── Setup/                #   Pineapple / Termux / Mark VII setup guides
├── evil_portal/              # Captive-portal platform (install, lifecycle, interface mgmt)
└── wordpress_web_root/       # WordPress-login portal front end (PHP/HTML)
```

---

## Setup (high level)

1. **Pineapple** — configure PineAP / client mode / Evil WPA, then run the `evil_portal` payloads in order: `install_evil_portal` → `set_evil_portal_interface` → `interface_manager` → `setup_wordpress_portal` → `switch_evil_portal` (select `wordpress`).
2. **Relay** — follow `auth-relay-framework/Setup/` (Pineapple → Termux). The Android app handles SSH keys, module deployment, and service startup.
3. **Retarget** (optional) — edit `phishlet.py` to point the relay at a different login portal.

```bash
git clone https://github.com/PentestPlaybook/pager-payloads.git
scp -r pager-payloads/evil_portal root@172.16.52.1:/root/payloads/user/
```

---

## Requirements

- WiFi Pineapple Pager or Mark VII (OpenWrt 24.10.1), root SSH access
- Android device (rooted) with Termux + Termux:X11, Firefox + geckodriver
- SSH key pair between Termux and the Pineapple
- Internet connection for initial package installation

---

## If I rebuilt this

Honest notes for anyone reading the source:

- **Decompose the Android app.** `MainActivity.kt` has grown large; the setup/deploy/monitor phases belong in separate classes or a small state machine. (The Python relay is already cleanly modular — the Kotlin side is the next pass.)
- **Add a test suite.** The Python modules are structured for it (pure helpers returning result objects); unit tests around phishlet parsing, outcome detection, and the MFA state machine would be high value.

---

## Disclaimer

For authorized security testing and education only. Using these tools against systems without explicit written permission from the owner is illegal and unethical. The authors assume no liability for misuse or damage. Always obtain proper authorization before any assessment.
