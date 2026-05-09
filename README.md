# pager-payloads

A collection of tools and payloads for the WiFi Pineapple Pager (OpenWrt 24.10.1) built for authorized wireless security assessments and penetration testing.

---

## Repository Structure

```
pager-payloads/
├── evil_portal/              # Payloads for managing Evil Portal on the Pager
├── wordpress_web_root/       # Captive portal web files (WordPress login theme)
└── auth-relay-framework/     # Android app + Python relay framework
    ├── AuthRelayApp/         # Android Studio project
    └── Setup/                # Setup instructions
```

---

## Components

### Evil Portal Payloads

A set of modular payloads for deploying and managing a captive portal on the Pager. These payloads automate complex configurations that would otherwise require extensive manual setup.

| Payload | Description |
|---------|-------------|
| `install_evil_portal` | Installs Evil Portal service and dependencies |
| `set_evil_portal_interface` | Sets the network interface Evil Portal applies to |
| `interface_manager` | Displays interface status and manages interface activation |
| `enable_evil_portal` | Enables Evil Portal to start on boot |
| `disable_evil_portal` | Disables Evil Portal from starting on boot |
| `start_evil_portal` | Starts the Evil Portal service |
| `stop_evil_portal` | Stops the Evil Portal service |
| `restart_evil_portal` | Restarts the Evil Portal service |
| `switch_evil_portal` | Switches active captive portal at runtime |
| `default_portal` | Activates the default captive portal theme |
| `setup_wordpress_portal` | Deploys the WordPress login captive portal theme |

**Run payloads in this order for initial setup:**

1. `install_evil_portal`
2. `set_evil_portal_interface`
3. `interface_manager`
4. `setup_wordpress_portal`
5. `switch_evil_portal` — select `wordpress`

---

### WordPress Web Root

The captive portal web files that Evil Portal serves to connected clients. Presents a convincing WordPress login page and handles credential capture, MFA flow, and result signaling back to the relay framework.

---

### Auth Relay Framework

An Android application and Python automation framework that integrates with the captive portal to perform real-time credential relay attacks. See [`auth-relay-framework/README.md`](auth-relay-framework/README.md) for full documentation.

**How it works:**

```
Victim device
    --> submits credentials to captive portal
WiFi Pineapple (Evil Portal)
    --> forwards to relay via SSH tunnel (port 9999)
Android device (Termux)
    --> HTTP server receives credentials
    --> Selenium + Firefox submits to real target
    --> detects outcome (success / MFA required / failed)
    <-- sends result back to Pineapple (port 9998)
```

The Android app handles the full setup flow: configuring Evil WPA, establishing SSH tunnels, deploying Python modules, and monitoring the relay service. A phishlet-based configuration system allows the framework to be retargeted against any login portal by editing a single file.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/PentestPlaybook/pager-payloads.git

# Transfer evil_portal payloads to the Pager
scp -r pager-payloads/evil_portal root@172.16.52.1:/root/payloads/user/
```

For the Auth Relay Framework, follow the setup instructions in `auth-relay-framework/Setup/`.

---

## Quick Reference

### Simulate Captive Portal Authorization
```bash
# Get your client's private IP
cat /tmp/dhcp.leases

# Simulate captive portal authentication for your client's private IP
echo "x.x.x.x" >> /tmp/EVILPORTAL_CLIENTS.txt

# Verify client was added to the firewall allow list
nft list chain inet fw4 dstnat | grep saddr

# Restart evilportal to clear the allow list
/etc/init.d/evilportal restart
```

### View Captured Credentials
```bash
cat /root/logs/credentials.json
```

---

## Troubleshooting

**No internet after connecting to access point — Pager cannot ping a domain:**
- Ensure all 3 access points are not enabled simultaneously
- Verify WiFi Client Mode configuration is correct

**No internet after connecting to access point — Pager can ping a domain:**
- Verify PineAP filters are set to **DENY**
- If filters are set to **ALLOW**, ensure the connecting device is on the allow list

**Cannot connect to an access point:**
- Verify the AP is currently enabled on the Pager
- Use the `interface_manager` payload to confirm which interfaces are up

---

## Requirements

- WiFi Pineapple Pager (OpenWrt 24.10.1)
- Active internet connection (for package downloads)
- Root SSH access to the Pager
- Android device with root access (for Auth Relay Framework)
- Termux + Termux:X11 (for Auth Relay Framework)

---

## Contributing

Contributions are welcome. To add a payload:

1. Fork the repository
2. Create a directory: `<category>/<payload_name>/`
3. Include `payload.sh` and `README.md`
4. Test on a Pager
5. Submit a pull request

**Guidelines:**
- Use clear, descriptive variable names
- Include error handling and verification steps
- Use `LOG` for status messages
- Document all prerequisites
- Follow the directory structure: `<category>/<payload_name>/payload.sh`

---

## Resources

- [WiFi Pineapple Docs](https://docs.hak5.org/)
- [OpenWrt Documentation](https://openwrt.org/docs/start)
- [Hak5 Forums](https://forums.hak5.org/)
- [nftables Wiki](https://wiki.nftables.org/)

---

## Disclaimer

This repository is intended for authorized security testing and educational purposes only. Use of these tools against systems without explicit written permission from the system owner is illegal and unethical. The authors assume no liability for misuse or damage caused by this software. Always obtain proper authorization before conducting any security assessments.
