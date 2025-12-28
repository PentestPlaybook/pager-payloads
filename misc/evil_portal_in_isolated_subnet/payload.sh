#!/bin/bash
# Name: Install Evil Portal on Pager
# Description: Complete Evil Portal installation for WiFi Pineapple Pager (OpenWrt 24.10.1)
# Author: PentestPlaybook
# Version: 1.3
# Category: Evil Portal

LOG "Starting Evil Portal installation for WiFi Pineapple Pager..."

# ====================================================================
# STEP 1: Install Required Packages
# ====================================================================
LOG "Step 1: Installing required packages..."
LOG "Updating package lists..."
opkg update

LOG "Installing PHP 8 and modules..."
opkg install php8 php8-fpm php8-mod-curl php8-mod-sqlite3

LOG "Installing nginx and dependencies..."
opkg install nginx-full nginx-ssl-util zoneinfo-core

LOG "Verifying package installation..."
if ! opkg list-installed | grep -q "php8-fpm"; then
    LOG "ERROR: PHP8-FPM installation failed"
    exit 1
fi

if ! opkg list-installed | grep -q "nginx-full"; then
    LOG "ERROR: nginx-full installation failed"
    exit 1
fi

LOG "SUCCESS: All packages installed"

# ====================================================================
# STEP 2: Create Evil Portal API Files
# ====================================================================
LOG "Step 2: Creating Evil Portal API backend..."
mkdir -p /pineapple/ui/modules/evilportal/assets/api

LOG "Creating index.php..."
cat > /pineapple/ui/modules/evilportal/assets/api/index.php << 'EOF'
<?php namespace evilportal;

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header('Content-Type: application/json');

require_once("API.php");
$api = new API();
echo $api->go();
EOF

LOG "Creating API.php..."
cat > /pineapple/ui/modules/evilportal/assets/api/API.php << 'EOF'
<?php namespace evilportal;

class API
{
    private $request;
    private $error;

    public function __construct()
    {
        $this->request = (object)$_POST;
    }

    public function route()
    {
        $portalPath = "/www/MyPortal.php";
        $portalClass = "evilportal\\MyPortal";

        if (!file_exists($portalPath)) {
            $this->error = "MyPortal.php does not exist in {$portalPath}";
            return;
        }

        require_once("Portal.php");
        require_once($portalPath);

        if (!class_exists($portalClass)) {
            $this->error = "The class {$portalClass} does not exist in {$portalPath}";
            return;
        }

        $portal = new $portalClass($this->request);
        $portal->handleAuthorization();
        $this->response = $portal->getResponse();
    }

    public function finalize()
    {
        if ($this->error) {
            return json_encode(array("error" => $this->error));
        } elseif ($this->response) {
            return json_encode($this->response);
        }
    }

    public function go()
    {
        $this->route();
        return $this->finalize();
    }
}
EOF

LOG "Creating Portal.php..."
cat > /pineapple/ui/modules/evilportal/assets/api/Portal.php << 'EOF'
<?php namespace evilportal;

abstract class Portal
{
    protected $request;
    protected $response;
    protected $error;

    protected $AUTHORIZED_CLIENTS_FILE = "/tmp/EVILPORTAL_CLIENTS.txt";

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function getResponse()
    {
        if (empty($this->error) && !empty($this->response)) {
            return $this->response;
        } elseif (empty($this->error) && empty($this->response)) {
            return array('error' => 'API returned empty response');
        } else {
            return array('error' => $this->error);
        }
    }

    protected final function execBackground($command)
    {
        exec("echo \"{$command}\" | at now");
    }

    protected final function notify($message)
    {
        $this->execBackground("PYTHONPATH=/usr/lib/pineapple; export PYTHONPATH; /usr/bin/python3 /usr/bin/notify info '{$message}' evilportal");
    }

    protected final function writeLog($message)
    {
        try {
            $reflector = new \ReflectionClass(get_class($this));
            $logPath = dirname($reflector->getFileName());
            file_put_contents("{$logPath}/.logs", "{$message}\n", FILE_APPEND);
        } catch (\ReflectionException $e) {
            // do nothing.
        }
    }

    protected function authorizeClient($clientIP)
    {
        if (!$this->isClientAuthorized($clientIP)) {
            // Just write to file - daemon will add nft rule
            file_put_contents($this->AUTHORIZED_CLIENTS_FILE, "{$clientIP}\n", FILE_APPEND);
        }
        return true;
    }

    protected function handleAuthorization()
    {
        if ($this->isClientAuthorized($_SERVER['REMOTE_ADDR']) and isset($this->request->target)) {
            $this->redirect();
         } elseif (isset($this->request->target)) {
             $this->authorizeClient($_SERVER['REMOTE_ADDR']);
             $this->onSuccess();
             $this->redirect();
         } else {
             $this->showError();
         }
    }

    protected function redirect()
    {
        header("Location: {$this->request->target}", true, 302);
    }

    protected function onSuccess()
    {
        $this->notify("New client authorized through EvilPortal!");
    }

    protected function showError()
    {
        echo "You have not been authorized.";
    }

    protected function isClientAuthorized($clientIP)
    {
        $authorizeClients = file_get_contents($this->AUTHORIZED_CLIENTS_FILE);
        return strpos($authorizeClients, $clientIP);
    }
}
EOF

LOG "SUCCESS: API files created"

# ====================================================================
# STEP 3: Create Portal Files
# ====================================================================
LOG "Step 3: Creating portal interface files..."
mkdir -p /root/portals/Wordpress

LOG "Creating index.php..."
cat > /root/portals/Wordpress/index.php << 'EOF'
<?php

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

$destination = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
require_once('helper.php');

?>

<HTML>
    <HEAD>
        <title>Evil Portal</title>
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
        <meta http-equiv="Pragma" content="no-cache" />
        <meta http-equiv="Expires" content="0" />
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </HEAD>

    <BODY>
        <div style="text-align: center;">
            <h1>Evil Portal</h1>
            <p>This is the default Evil Portal page.</p>
            <p>The SSID you are connected to is <?=getClientSSID($_SERVER['REMOTE_ADDR']);?></p>
            <p>Your host name is <?=getClientHostName($_SERVER['REMOTE_ADDR']);?></p>
            <p>Your MAC Address is <?=getClientMac($_SERVER['REMOTE_ADDR']);?></p>
            <p>Your internal IP address is <?=$_SERVER['REMOTE_ADDR'];?></p>

            <form method="POST" action="/captiveportal/index.php">
                <input type="hidden" name="target" value="<?=$destination?>">
                <button type="submit">Authorize</button>
            </form>

        </div>

    </BODY>

</HTML>
EOF

LOG "Creating MyPortal.php..."
cat > /root/portals/Wordpress/MyPortal.php << 'EOF'
<?php namespace evilportal;

class MyPortal extends Portal
{

    public function handleAuthorization()
    {
        // handle form input or other extra things there

        // Call parent to handle basic authorization first
        parent::handleAuthorization();
    }

    public function onSuccess()
    {
        // Calls default success message
        parent::onSuccess();
    }

    public function showError()
    {
        // Calls default error message
        parent::showError();
    }
}
EOF

LOG "Creating helper.php..."
cat > /root/portals/Wordpress/helper.php << 'EOF'
<?php

function getClientMac($clientIP)
{
    return trim(exec("grep " . escapeshellarg($clientIP) . " /tmp/dhcp.leases | awk '{print $2}'"));
}

function getClientSSID($clientIP)
{
    if (file_exists("/tmp/log.db"))
    {
        $mac = strtoupper(getClientMac($clientIP));
        $db = new SQLite3("/tmp/log.db");
        $results = $db->query("select ssid from log WHERE mac = '{$mac}' AND log_type = 0 ORDER BY updated_at DESC LIMIT 1;");
        $ssid = '';
        while($row = $results->fetchArray())
        {
            $ssid = $row['ssid'];
            break;
        }
        $db->close();
        return $ssid;
    }
    return '';
}

function getClientHostName($clientIP)
{
    return trim(exec("grep " . escapeshellarg($clientIP) . " /tmp/dhcp.leases | awk '{print $4}'"));
}
EOF

LOG "Creating Wordpress.ep..."
cat > /root/portals/Wordpress/Wordpress.ep << 'EOF'
{
  "name": "Wordpress",
  "type": "basic"
}
EOF

LOG "SUCCESS: Portal files created"

# ====================================================================
# STEP 4: Configure nginx
# ====================================================================
LOG "Step 4: Configuring nginx web server..."
cat > /etc/nginx/nginx.conf << 'EOF'
user root root;
worker_processes  1;
events {
    worker_connections  1024;
}
http {
        include mime.types;
        index index.php;
        default_type text/html;
        sendfile on;
        keepalive_timeout 65;
        gzip on;
        gzip_min_length  1k;
        gzip_buffers     4 16k;
        gzip_http_version 1.0;
        gzip_comp_level 2;
        gzip_types       text/plain application/x-javascript text/css application/xml;
        gzip_vary on;
        server {
                listen       80;
                server_name  www;
                error_page 404 =200 /index.php;
                error_log /root/elog;
                access_log /dev/null;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                fastcgi_buffer_size 32k;
                fastcgi_buffers 4 32k;
                fastcgi_busy_buffers_size 32k;
                fastcgi_temp_file_write_size 32k;
                client_body_timeout 10;
                client_header_timeout 10;
                send_timeout 60;
                output_buffers 1 32k;
                postpone_output 1460;
                root   /www;
                location ~ \.php$ {
                        fastcgi_split_path_info ^(.+\.php)(/.+)$;
                        fastcgi_pass unix:/var/run/php8-fpm.sock;
                        fastcgi_index index.php;
                        include fastcgi_params;
                        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                        if (-f $request_filename) {
                                fastcgi_pass    unix:/var/run/php8-fpm.sock;
                        }
                }
                error_page 404 =200 /index.php;
        }
}
EOF

LOG "Testing nginx configuration..."
nginx -t
if [ $? -ne 0 ]; then
    LOG "ERROR: nginx configuration test failed"
    exit 1
fi

LOG "SUCCESS: nginx configured"

# ====================================================================
# STEP 5: Disable UCI nginx and Fix Permissions
# ====================================================================
LOG "Step 5: Disabling UCI nginx and setting permissions..."
uci set nginx.global.uci_enable=false
uci commit nginx

chmod 755 /root
chmod -R 755 /root/portals/

LOG "SUCCESS: Permissions configured"

# ====================================================================
# STEP 6: Create Init Script and Whitelist Daemon
# ====================================================================
LOG "Step 6: Creating Evil Portal init script..."
cat > /etc/init.d/evilportal << 'INITEOF'
#!/bin/sh /etc/rc.common

START=99

# Helper function to add temporary nft rules directly to dstnat chain
# (dstnat always exists, dstnat_lan only exists when UCI rules are present)
add_nft_rules() {
    # Add TEMPORARY nftables rules to the main dstnat chain with interface match
    # These disappear on reboot since they're not in UCI config
    nft insert rule inet fw4 dstnat iifname "br-evil" meta nfproto ipv4 tcp dport 443 counter dnat ip to 172.16.52.1:80
    nft insert rule inet fw4 dstnat iifname "br-evil" meta nfproto ipv4 tcp dport 80 counter dnat ip to 172.16.52.1:80
    nft insert rule inet fw4 dstnat iifname "br-evil" meta nfproto ipv4 tcp dport 53 counter dnat ip to 172.16.52.1:5353
    nft insert rule inet fw4 dstnat iifname "br-evil" meta nfproto ipv4 udp dport 53 counter dnat ip to 172.16.52.1:5353
}

# Helper function to remove nft rules from memory
remove_nft_rules() {
    # Remove temporary rules from dstnat chain (the ones we added with iifname match)
    nft -a list chain inet fw4 dstnat 2>/dev/null | grep "dnat ip to 172.16.52.1" | awk '{print $NF}' | while read handle; do
        nft delete rule inet fw4 dstnat handle "$handle" 2>/dev/null
    done
    
    # Also remove from dstnat_lan if it exists (for UCI-created rules)
    nft -a list chain inet fw4 dstnat_lan 2>/dev/null | grep "dnat ip to 172.16.52.1" | awk '{print $NF}' | while read handle; do
        nft delete rule inet fw4 dstnat_lan handle "$handle" 2>/dev/null
    done
}

# Helper function to remove whitelist rules
remove_whitelist_rules() {
    # Remove from dstnat chain
    nft -a list chain inet fw4 dstnat 2>/dev/null | grep "ip saddr.*accept" | awk '{print $NF}' | while read handle; do
        nft delete rule inet fw4 dstnat handle "$handle" 2>/dev/null
    done
    
    # Also remove from dstnat_lan if it exists
    nft -a list chain inet fw4 dstnat_lan 2>/dev/null | grep "ip saddr.*accept" | awk '{print $NF}' | while read handle; do
        nft delete rule inet fw4 dstnat_lan handle "$handle" 2>/dev/null
    done
}

# Helper function to start services
start_services() {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    rm -f /tmp/EVILPORTAL_CLIENTS.txt /tmp/EVILPORTAL_PROCESSED.txt
    touch /tmp/EVILPORTAL_CLIENTS.txt
    chmod 666 /tmp/EVILPORTAL_CLIENTS.txt
    /etc/init.d/php8-fpm start
    /etc/init.d/nginx start
    kill $(netstat -plant 2>/dev/null | grep ':5353' | awk '{print $NF}' | sed 's/\/dnsmasq//g') 2>/dev/null
    dnsmasq --no-hosts --no-resolv --address=/#/172.16.52.1 -p 5353 &
    rm -f /www/captiveportal
    ln -s /pineapple/ui/modules/evilportal/assets/api /www/captiveportal
    ln -sf /root/portals/Wordpress/index.php /www/index.php
    ln -sf /root/portals/Wordpress/MyPortal.php /www/MyPortal.php
    ln -sf /root/portals/Wordpress/helper.php /www/helper.php
    ln -sf /root/portals/Wordpress/index.php /www/generate_204
    
    # Start whitelist daemon
    /usr/bin/evilportal-whitelist-daemon &
}

# Helper function to stop services
stop_services() {
    /etc/init.d/php8-fpm stop
    /etc/init.d/nginx stop
    kill $(netstat -plant 2>/dev/null | grep ':5353' | awk '{print $NF}' | sed 's/\/dnsmasq//g') 2>/dev/null
    killall evilportal-whitelist-daemon 2>/dev/null
    rm -f /www/captiveportal /www/index.php /www/MyPortal.php /www/helper.php /www/generate_204
    
    # Remove whitelist rules
    remove_whitelist_rules
}

start() {
    # Add TEMPORARY nft rules (disappear on reboot)
    add_nft_rules
    
    # Start services
    start_services
    
    logger -t evilportal "Evil Portal started (temporary - will not persist after reboot)"
}

stop() {
    # Stop services
    stop_services
    
    # Remove nft rules from memory
    remove_nft_rules
    
    logger -t evilportal "Evil Portal stopped"
}

restart() {
    stop
    sleep 2
    start
}

enable() {
    # Add PERSISTENT firewall NAT rules via UCI
    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal HTTPS'
    uci set firewall.@redirect[-1].src='lan'
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='443'
    uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
    uci set firewall.@redirect[-1].dest_port='80'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal HTTP'
    uci set firewall.@redirect[-1].src='lan'
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='80'
    uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
    uci set firewall.@redirect[-1].dest_port='80'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal DNS TCP'
    uci set firewall.@redirect[-1].src='lan'
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='53'
    uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
    uci set firewall.@redirect[-1].dest_port='5353'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal DNS UDP'
    uci set firewall.@redirect[-1].src='lan'
    uci set firewall.@redirect[-1].proto='udp'
    uci set firewall.@redirect[-1].src_dport='53'
    uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
    uci set firewall.@redirect[-1].dest_port='5353'
    uci set firewall.@redirect[-1].target='DNAT'

    uci commit firewall
    /etc/init.d/firewall restart
    
    # Create boot symlink
    ln -sf /etc/init.d/evilportal /etc/rc.d/S99evilportal
    
    # Start services
    start_services
    
    logger -t evilportal "Evil Portal enabled and started (persistent - will survive reboot)"
}

disable() {
    # Stop services first
    stop_services
    
    # Remove nft rules from memory
    remove_nft_rules
    
    # Remove boot symlink
    rm -f /etc/rc.d/*evilportal
    
    # Remove PERSISTENT firewall NAT rules from UCI - delete from highest index to lowest
    while uci show firewall | grep -q "Evil Portal"; do
        # Get the last (highest index) redirect rule containing "Evil Portal"
        LAST_INDEX=$(uci show firewall | grep "redirect\[" | grep "Evil Portal" | tail -n1 | sed 's/.*redirect\[\([0-9]*\)\].*/\1/')
        if [ -n "$LAST_INDEX" ]; then
            uci delete firewall.@redirect[$LAST_INDEX]
        else
            break
        fi
    done
    
    uci commit firewall
    /etc/init.d/firewall restart
    
    logger -t evilportal "Evil Portal disabled and cleaned up (removed from boot)"
}
INITEOF

chmod +x /etc/init.d/evilportal

LOG "Creating whitelist daemon..."
cat > /usr/bin/evilportal-whitelist-daemon << 'EOF'
#!/bin/sh

CLIENTS_FILE="/tmp/EVILPORTAL_CLIENTS.txt"
PROCESSED_FILE="/tmp/EVILPORTAL_PROCESSED.txt"

# Create processed file if it doesn't exist
touch "$PROCESSED_FILE"

while true; do
    if [ -f "$CLIENTS_FILE" ]; then
        # Read each IP from clients file
        while read -r ip; do
            # Skip if already processed
            if ! grep -q "^${ip}$" "$PROCESSED_FILE" 2>/dev/null; then
                # Add nft rule - use dstnat chain directly (always exists)
                nft insert rule inet fw4 dstnat ip saddr "$ip" accept
                # Mark as processed
                echo "$ip" >> "$PROCESSED_FILE"
                logger -t evilportal "Whitelisted client: $ip"
            fi
        done < "$CLIENTS_FILE"
    fi
    sleep 2
done
EOF

chmod +x /usr/bin/evilportal-whitelist-daemon

LOG "SUCCESS: Init script and daemon created"

# ====================================================================
# STEP 7: Configure Firewall NAT Rules
# ====================================================================
LOG "Step 7: Configuring firewall NAT rules..."

uci add firewall redirect
uci set firewall.@redirect[-1].name='Evil Portal HTTPS'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='443'
uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
uci set firewall.@redirect[-1].dest_port='80'
uci set firewall.@redirect[-1].target='DNAT'

uci add firewall redirect
uci set firewall.@redirect[-1].name='Evil Portal HTTP'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='80'
uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
uci set firewall.@redirect[-1].dest_port='80'
uci set firewall.@redirect[-1].target='DNAT'

uci add firewall redirect
uci set firewall.@redirect[-1].name='Evil Portal DNS TCP'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
uci set firewall.@redirect[-1].dest_port='5353'
uci set firewall.@redirect[-1].target='DNAT'

uci add firewall redirect
uci set firewall.@redirect[-1].name='Evil Portal DNS UDP'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='udp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_ip='172.16.52.1'
uci set firewall.@redirect[-1].dest_port='5353'
uci set firewall.@redirect[-1].target='DNAT'

uci commit firewall

LOG "Restarting firewall..."
/etc/init.d/firewall restart

LOG "SUCCESS: Firewall rules configured"

# ====================================================================
# STEP 8: Start Services
# ====================================================================
LOG "Step 8: Starting Evil Portal services..."

/etc/init.d/php8-fpm restart
/etc/init.d/nginx restart

LOG "Waiting for services to start..."
sleep 3

# Verify services are running
if ! pgrep php8-fpm > /dev/null; then
    LOG "ERROR: PHP8-FPM failed to start"
    exit 1
fi

if ! pgrep nginx > /dev/null; then
    LOG "ERROR: nginx failed to start"
    exit 1
fi

LOG "Starting Evil Portal..."
/etc/init.d/evilportal start

LOG "Waiting for Evil Portal to start..."
sleep 3

# Verify Evil Portal components
if ! pgrep -f "evilportal-whitelist-daemon" > /dev/null; then
    LOG "WARNING: Whitelist daemon not running"
fi

if ! pgrep -f "dnsmasq.*5353" > /dev/null; then
    LOG "WARNING: DNS spoof daemon not running"
fi

# ====================================================================
# STEP 9: Enable at Boot
# ====================================================================
LOG "Step 9: Enabling Evil Portal at boot..."
ln -sf /etc/init.d/evilportal /etc/rc.d/S99evilportal

if [ -L "/etc/rc.d/S99evilportal" ]; then
    LOG "SUCCESS: Evil Portal enabled at boot"
else
    LOG "WARNING: Failed to create boot symlink"
fi

# ====================================================================
# STEP 10: Verification
# ====================================================================
LOG "Step 10: Running verification tests..."

# Test portal HTTP response
LOG "Testing portal HTTP response..."
if curl -s http://172.16.52.1/ | grep -q "Evil Portal"; then
    LOG "SUCCESS: Portal HTTP responding"
else
    LOG "WARNING: Portal HTTP not responding correctly"
fi

# Verify NAT rules exist
LOG "Verifying NAT rules..."
if nft list chain inet fw4 dstnat 2>/dev/null | grep -q "172.16.52.1"; then
    LOG "SUCCESS: NAT rules configured"
else
    LOG "ERROR: NAT rules not found"
    exit 1
fi

# Verify symlinks
LOG "Verifying symlinks..."
if [ -L "/www/index.php" ] && [ -L "/www/captiveportal" ]; then
    LOG "SUCCESS: Symlinks created"
else
    LOG "WARNING: Some symlinks may be missing"
fi

# ====================================================================
# Installation Complete
# ====================================================================
LOG "=================================================="
LOG "Evil Portal Installation Complete!"
LOG "=================================================="
LOG "Portal URL: http://172.16.52.1/"
LOG "Services Status:"
LOG "  - PHP-FPM: $(pgrep php8-fpm > /dev/null && echo 'Running' || echo 'Stopped')"
LOG "  - nginx: $(pgrep nginx > /dev/null && echo 'Running' || echo 'Stopped')"
LOG "  - dnsmasq (5353): $(pgrep -f 'dnsmasq.*5353' > /dev/null && echo 'Running' || echo 'Stopped')"
LOG "  - Whitelist Daemon: $(pgrep -f evilportal-whitelist-daemon > /dev/null && echo 'Running' || echo 'Stopped')"
LOG ""
LOG "Portal files: /root/portals/Wordpress/"
LOG "API files: /pineapple/ui/modules/evilportal/assets/api/"
LOG "Init script: /etc/init.d/evilportal"
LOG ""
LOG "Management commands:"
LOG "  Enable:  /etc/init.d/evilportal enable   (turn ON + persist after reboot)"
LOG "  Disable: /etc/init.d/evilportal disable  (turn OFF + remove from boot)"
LOG "  Start:   /etc/init.d/evilportal start    (turn ON temporarily - gone after reboot)"
LOG "  Stop:    /etc/init.d/evilportal stop     (turn OFF temporarily)"
LOG "  Restart: /etc/init.d/evilportal restart  (restart portal)"
LOG ""
LOG "Behavior:"
LOG "  - enable + reboot  = Portal ON (persistent)"
LOG "  - disable + reboot = Portal OFF"
LOG "  - start + reboot   = Portal OFF (temporary, not persistent)"
LOG "  - stop + reboot    = depends on enable/disable state"
LOG "=================================================="

exit 0
