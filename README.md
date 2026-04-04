# WiFi Pineapple Pager Payloads
A collection of automated DuckyScript payloads for the WiFi Pineapple Pager (OpenWrt 24.10.1).

## 📋 Overview
This repository contains ready-to-use payloads designed specifically for the WiFi Pineapple Pager. Each payload automates complex configurations and installations that would otherwise require extensive manual setup.

## ⚙️ Requirements
- WiFi Pineapple Pager (OpenWrt 24.10.1)
- Active internet connection (for package downloads)
- Root access via SSH

---

## 📥 Installation

### Method 1: Clone and Transfer (Recommended)
```bash
# Clone the Repository
git clone https://github.com/PentestPlaybook/pager-payloads.git

# Transfer the Repository to the Pager
scp -r pager-payloads/evil_portal pager-payloads/pine_ap root@172.16.52.1:/root/payloads/user/
```

### Method 2: Manual Installation
```bash
# Replace <category> and <payload_name> with actual values
ssh root@172.16.52.1
mkdir -p /root/payloads/user/<category>/<payload_name>
vim /root/payloads/user/<category>/<payload_name>/payload.sh
```

---

## 🚀 Getting Started with Evil Portal

### Installation Order
The Evil Portal payloads must be run in a specific order:

1. **Install Evil Portal** - Run first to install the Evil Portal service
2. **Set Evil Portal Interface** - Configure which interface Evil Portal applies to
3. **Interface Manager** - Confirm interface status and resolve any connectivity issues
4. **WordPress Portal** - Deploy the WordPress captive portal
5. **Switch Evil Portal** - Select `wordpress` to activate it

### Available Payloads

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

---

## 🎯 Quick Reference

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
> **Note:** After successful authentication, reconnect to the access point to restore internet access.

### View Captured Credentials
```bash
cat /root/logs/credentials.json
```

---


## 🌐 Evil Portal Troubleshooting

### No internet connectivity after connecting to access point and pager cannot ping a domain.
SSH into the Pager using a physical connection. If the Pager cannot ping a domain, check the following:
- Ensure that all 3 access points are not enabled simultaneously
- Verify your WiFi Client Mode configuration is correct

### No internet connectivity after connecting to access point and pager can ping a domain.
SSH into the Pager using a physical connection. If the Pager can ping a domain, check the following:
- Verify your PineAP filters are set to **DENY**
- If filters are set to **ALLOW**, ensure connecting device has been added to the allow list

### Not able to connect to an access point
- Verify the AP you are trying to connect to is currently enabled on the Pager and not just a saved network on your device
- Use the Interface Manager payload to confirm which interfaces are currently up

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

These payloads are provided for security research, penetration testing, and educational purposes. Users are solely responsible for ensuring compliance with all applicable laws and regulations. Unauthorized access to computer systems is illegal.

**By using these payloads, you agree to:**
- Only use on networks/systems you own or have explicit permission to test
- Comply with all local, state, and federal laws
- Take full responsibility for your actions

The authors and contributors are not responsible for misuse or damage caused by these tools.

---

## 🤝 Contributing

Contributions are welcome! Help grow this collection of Pager payloads.

### How to Contribute a Payload

1. **Fork the repository**
2. **Create a new directory** for your payload following the structure:
```
   <category>/<payload_name>/
```
3. **Include required files:**
   - `payload.sh` - Your executable script
   - `README.md` - Payload documentation (see template below)
4. **Test thoroughly** on a Pager
5. **Submit a pull request**

### Payload README Template
```markdown
# [Payload Name]

## Description
Brief description of what the payload does.

## Features
- Feature 1
- Feature 2

## Requirements
- List any specific requirements

## Installation
Location: `/root/payloads/user/<category>/<payload_name>/`

## Usage
```bash
bash /root/payloads/user/<category>/<payload_name>/payload.sh
```

## Post-Installation
What to do after installation

## Management Commands
- Start: `command here`
- Stop: `command here`
- Status: `command here`

## Troubleshooting
Common issues and solutions
```

### Payload Guidelines
- ✅ Use clear, descriptive variable names
- ✅ Include comprehensive error handling
- ✅ Add verification/testing steps
- ✅ Use `LOG` for status messages
- ✅ Document all prerequisites
- ✅ Test on fresh Pager installation
- ✅ Include cleanup/uninstall steps if applicable
- ✅ Follow the directory structure: `<category>/<payload_name>/payload.sh`

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🎄 Credits

**Repository Maintainer:** PentestPlaybook

**Payload Contributors:**
- Evil Portal: Adapted from WiFi Pineapple Mark VII module

---

## 📚 Resources

- [WiFi Pineapple Docs](https://docs.hak5.org/)
- [OpenWrt Documentation](https://openwrt.org/docs/start)
- [Hak5 Forums](https://forums.hak5.org/)
- [nftables Wiki](https://wiki.nftables.org/)

---

## 🔗 Related Projects

- [WiFi Pineapple Mark VII Modules](https://github.com/hak5/mk7-modules)
- [Hak5 Cloud C2](https://shop.hak5.org/products/c2)

---

**Made with ❤️ for the Pineapple community**

*Last Updated: April 4, 2026*
