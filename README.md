# pager-payloads

Tooling and payloads for the WiFi Pineapple (Pager / Mark VII, OpenWrt 24.10.1), built for authorized wireless security assessments.

At its center is the **Auth Relay Framework**: a real-time, MFA-aware credential relay engine that intercepts credentials from a captive portal, replays them against the live target in a controlled browser, handles the one-time-password step automatically, and reports the outcome back — all driven by a single target-config file.

> ⚠️ **Authorized testing only.** These tools perform adversary-in-the-middle credential capture. Use them exclusively against systems you own or have explicit written permission to assess. See the [disclaimer](#disclaimer).

---

## System overview

The project spans four tiers and three languages, integrated end to end:

```
Victim device
    │  submits credentials to captive portal
    ▼
WiFi Pineapple — Evil Portal (shell payloads / PHP front end)
    │  forwards to relay over SSH tunnel (:9999)
    ▼
Android device — Termux (Kotlin app + Python relay)
    │  HTTP server receives credentials
    │  Selenium + Firefox submits to the real target
    │  detects outcome: success / MFA required / failed
    ▲  returns result to the Pineapple (:9998)
```

| Tier | Tech | Responsibility |
|------|------|----------------|
| Captive portal | Shell (OpenWrt/nftables) + PHP | Evil Portal lifecycle, credential capture, MFA prompt UI |
| Orchestration | Kotlin (Android) | Device setup, SSH keygen/transfer, module deployment, service monitoring |
| Relay engine | Python (Selenium) | HTTP server, browser automation, login + MFA handling, result signaling |
| Config | Single phishlet file | Retargets the entire framework to a new portal |

---

## Repository structure

```
pager-payloads/
├── evil_portal/              # Modular Pineapple payloads (install, interface, portal switch, lifecycle)
├── wordpress_web_root/       # Captive-portal front end (WordPress login + MFA flow, PHP)
└── auth-relay-framework/
    ├── AuthRelayApp/         # Android app (Kotlin) + bundled Python relay modules
    └── Setup/                # Pineapple, Termux, and Mark VII setup guides
```

---

## Design

A few deliberate choices in the relay engine that are worth calling out:

### Config-driven retargeting (phishlet pattern)
`phishlet.py` is the single source of truth for everything target-specific — login path, field names, submit button, success/failure indicators, and the full MFA interaction profile. Every other module imports from it; **no other file changes when you point the framework at a new portal.** Misconfiguration surfaces as named, actionable errors (e.g. *"Could not find username field 'X' — check USERNAME_FIELD in phishlet"*) rather than raw stack traces.

### Structured result objects everywhere
Functions return a consistent `{"success": bool, "error": str | None, ...}` shape instead of throwing or returning bare values. Outcomes propagate with context across the whole call chain (`main → server → login_handler → mfa_handler → result_notifier`), so failures are explicit and never silent.

### Thread-synchronized MFA handling
The MFA step is the hard part: the OTP arrives *out of band*, on a separate HTTP endpoint, after the login attempt is already in flight. The framework blocks a worker thread on a `threading.Event` until the OTP is delivered (300s timeout), then fills and validates it — with bounded retries (`MAX_MFA_RETRIES`) and a daemon-thread dispatcher so the HTTP server stays responsive.

### Defensive browser automation
Selenium interactions assume the page will fight back: form-fill verifies the field value actually took and falls back to JavaScript injection; the validate button has a DOM-click path with a jQuery fallback; outcome detection *polls* URL, page source, and input count rather than trusting a single signal. A pre-flight reachability check distinguishes "server responded with 403/404" (proceed) from "DNS/connection failure" (fatal).

### Closure-bound request handler
The HTTP server builds its `BaseHTTPRequestHandler` subclass dynamically, binding the driver, domain, and port through a closure instead of mutable class-level state — keeping request handling free of shared global mutation.

---

## Components

### Evil Portal payloads (`evil_portal/`)
Modular payloads that install and manage a captive portal on the Pineapple, so configuration that would otherwise be manual becomes a repeatable sequence.

| Payload | Role |
|---------|------|
| `install_evil_portal` | Installs the Evil Portal service and dependencies |
| `set_evil_portal_interface` | Binds Evil Portal to a chosen interface |
| `interface_manager` | Shows interface status and toggles activation |
| `setup_wordpress_portal` | Deploys the WordPress-login captive portal |
| `switch_evil_portal` | Switches the active portal at runtime |
| `enable` / `disable` / `start` / `stop` / `restart` | Service lifecycle control |
| `default_portal` | Restores the default portal theme |

**Initial setup order:** `install_evil_portal` → `set_evil_portal_interface` → `interface_manager` → `setup_wordpress_portal` → `switch_evil_portal` (select `wordpress`).

### WordPress captive portal (`wordpress_web_root/`)
The front end Evil Portal serves: a convincing WordPress login, an MFA/OTP page, success/failure states, and the PHP glue that captures credentials and signals results back to the relay.

### Auth Relay Framework (`auth-relay-framework/`)
The Kotlin app plus the Python relay engine described in [Design](#design). The app handles the full device bring-up — device-type selection, Termux verification, Pineapple connectivity check, SSH key generation and transfer, Python module deployment, Evil WPA configuration, and relay monitoring. Modules are redeployed from bundled resources on every run, so the device always executes the current version. Full detail in [`auth-relay-framework/README.md`](auth-relay-framework/README.md).

---

## Installation

```bash
# Clone
git clone https://github.com/PentestPlaybook/pager-payloads.git

# Deploy Evil Portal payloads to the Pager
scp -r pager-payloads/evil_portal root@172.16.52.1:/root/payloads/user/
```

For the Auth Relay Framework, follow the guides in `auth-relay-framework/Setup/` (Pineapple → Termux, in order).

---

## Quick reference

```bash
# Simulate captive-portal authorization for a client
cat /tmp/dhcp.leases                              # find the client's private IP
echo "x.x.x.x" >> /tmp/EVILPORTAL_CLIENTS.txt     # add to the allow list
nft list chain inet fw4 dstnat | grep saddr       # verify
/etc/init.d/evilportal restart                    # reset the allow list

# View captured credentials
cat /root/logs/credentials.json
```

---

## Requirements

- WiFi Pineapple Pager or Mark VII (OpenWrt 24.10.1), root SSH access
- Android device (rooted) with Termux + Termux:X11
- Firefox + geckodriver in Termux; SSH key pair between Termux and the Pineapple
- Active internet connection for package installs

---

## If I rebuilt this

Honest notes on what I'd change, for anyone reading the source critically:

- **Decompose the Android app.** `MainActivity.kt` has grown into a single large file; the setup/deploy/monitor phases should be separate classes or a small state machine. (The Python side is already cleanly modular — the Kotlin side is the next pass.)
- **Add a test suite.** The Python modules are structured for it — pure helpers with result objects — so unit tests around phishlet parsing, outcome detection, and the MFA state machine would be high value.
- **Externalize magic values.** A few timeouts and poll counts live as module constants; a small shared settings module would centralize tuning.

---

## Disclaimer

For authorized security testing and education only. Using these tools against systems without explicit written permission from the owner is illegal and unethical. The authors assume no liability for misuse or damage. Always obtain proper authorization before any assessment.
