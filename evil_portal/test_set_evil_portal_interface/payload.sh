#!/bin/bash
# Name: Test Set Evil Portal Interface (Automated)
# Description: Runs all 9 rounds (54 transitions) without user input, continues on failure, reports at end
# Author: PentestPlaybook
# Version: 1.6
# Category: Evil Portal

PORTAL_IP_EVIL="10.0.0.1"
PORTAL_IP_LAN="172.16.52.1"
BRIDGE_IF_EVIL="br-evil"
BRIDGE_IF_LAN="br-lan"
LOG_FILE="/tmp/evil_portal_transition_test.log"
PASS=0
FAIL=0
FAIL_LIST=""

# Staged change values
WPA_SSID="NetA"
WPA_KEY="Password123!"
OPEN_SSID="OpenA"

log() {
    LOG "$1"
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"
}

state_name() {
    case "$1" in
        1) echo "Evil WPA (wlan0wpa)" ;;
        2) echo "Open AP (wlan0open)" ;;
        3) echo "All Interfaces (br-lan)" ;;
    esac
}

iface_ready() {
    local iface="$1"
    ip link show "$iface" 2>/dev/null | grep -q "BROADCAST,MULTICAST,UP,LOWER_UP" && \
    ip link show "$iface" 2>/dev/null | grep -q "state UP"
}

wait_for_internet() {
    log "Waiting for internet connectivity..."
    ELAPSED=0
    while ! ping -c1 8.8.8.8 &>/dev/null; do
        log "Waiting for internet connectivity... (${ELAPSED}s)"
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
    log "SUCCESS: Internet connectivity confirmed"
}

# Clear all staged SSID/key changes from the UCI buffer and reload wifi
clear_staged_changes() {
    log "Clearing all staged SSID/key changes..."
    uci revert wireless.wlan0wpa.ssid  2>/dev/null
    uci revert wireless.wlan0wpa.key   2>/dev/null
    uci revert wireless.wlan0open.ssid 2>/dev/null
    uci revert wireless.wlan0open.key  2>/dev/null
    uci revert wireless.wlan0mgmt.ssid 2>/dev/null
    uci revert wireless.wlan0mgmt.key  2>/dev/null
    log "SUCCESS: Staged changes cleared"
}

# Stage the changes for a given round group and reload wifi
# Group 1 (rounds 1-3): WPA only
# Group 2 (rounds 4-6): Open only
# Group 3 (rounds 7-9): Both
stage_changes_for_group() {
    local group="$1"

    # Always clear first to prevent stacking
    clear_staged_changes

    case "$group" in
        1)
            log "Staging round group 1: WPA SSID/key only"
            uci set wireless.wlan0wpa.ssid="$WPA_SSID"
            uci set wireless.wlan0wpa.key="$WPA_KEY"
            ;;
        2)
            log "Staging round group 2: Open SSID only"
            uci set wireless.wlan0open.ssid="$OPEN_SSID"
            ;;
        3)
            log "Staging round group 3: WPA SSID/key + Open SSID"
            uci set wireless.wlan0wpa.ssid="$WPA_SSID"
            uci set wireless.wlan0wpa.key="$WPA_KEY"
            uci set wireless.wlan0open.ssid="$OPEN_SSID"
            ;;
    esac

    log "Reloading wifi to apply staged changes..."
    wifi reload
    sleep 5
    log "SUCCESS: Staged changes applied"
}

run_transition() {
    local to="$1"
    local from_name="$2"
    local to_name="$(state_name $to)"
    local label="${from_name} -> ${to_name}"

    log "=================================================="
    log "TRANSITION: ${label}"
    log "=================================================="

    case "$to" in
        1)
            TARGET_IFACE="wlan0wpa"
            OTHER_IFACE="wlan0open"
            TARGET_MODE="isolated"
            PORTAL_IP="${PORTAL_IP_EVIL}"
            FIREWALL_SRC="evil"
            ;;
        2)
            TARGET_IFACE="wlan0open"
            OTHER_IFACE="wlan0wpa"
            TARGET_MODE="isolated"
            PORTAL_IP="${PORTAL_IP_EVIL}"
            FIREWALL_SRC="evil"
            ;;
        3)
            TARGET_IFACE=""
            OTHER_IFACE=""
            TARGET_MODE="lan"
            PORTAL_IP="${PORTAL_IP_LAN}"
            FIREWALL_SRC="lan"
            ;;
    esac

    log "Selected mode: ${TARGET_MODE}"
    [ -n "$TARGET_IFACE" ] && log "Selected interface: ${TARGET_IFACE}"

    # ====================================================================
    # Detect current state
    # ====================================================================
    log "Detecting current state..."
    CURRENT_BRIDGE=$(grep -o 'iifname "[^"]*"' /etc/init.d/evilportal 2>/dev/null | head -1 | grep -o '"[^"]*"' | tr -d '"')
    CURRENT_IFACE=""

    if [ "$CURRENT_BRIDGE" = "br-evil" ]; then
        if uci show wireless.wlan0wpa.network 2>/dev/null | grep -q "evil"; then
            CURRENT_IFACE="wlan0wpa"
        elif uci show wireless.wlan0open.network 2>/dev/null | grep -q "evil"; then
            CURRENT_IFACE="wlan0open"
        fi
    fi

    log "Current bridge: ${CURRENT_BRIDGE}"
    log "Current interface: ${CURRENT_IFACE:-none}"

    # ====================================================================
    # Check if already in desired state
    # ====================================================================
    if [ "$TARGET_MODE" = "isolated" ]; then
        if [ "$CURRENT_BRIDGE" = "br-evil" ] && [ "$CURRENT_IFACE" = "$TARGET_IFACE" ]; then
            log "Already configured for ${TARGET_IFACE}. Skipping."
            return 0
        fi
    elif [ "$TARGET_MODE" = "lan" ]; then
        if [ "$CURRENT_BRIDGE" = "br-lan" ]; then
            log "Already configured for all interfaces. Skipping."
            return 0
        fi
    fi

    # ====================================================================
    # Verify internet connectivity
    # ====================================================================
    wait_for_internet

    # ====================================================================
    # Stop Evil Portal
    # ====================================================================
    log "Stopping Evil Portal..."
    /etc/init.d/evilportal stop
    sleep 3

    if pgrep nginx > /dev/null; then
        log "ERROR: Failed to stop nginx"
        return 1
    fi
    log "SUCCESS: Evil Portal stopped"

    # ====================================================================
    # Remove existing Evil Portal NAT rules
    # ====================================================================
    log "Removing existing Evil Portal NAT rules..."
    while uci show firewall | grep -q "Evil Portal"; do
        LAST_INDEX=$(uci show firewall | grep "redirect\[" | grep "Evil Portal" | tail -n1 | sed 's/.*redirect\[\([0-9]*\)\].*/\1/')
        if [ -n "$LAST_INDEX" ]; then
            uci delete firewall.@redirect[$LAST_INDEX]
        else
            break
        fi
    done
    uci commit firewall
    log "SUCCESS: Existing NAT rules removed"

    # ====================================================================
    # Update network configuration
    # ====================================================================
    log "Updating network configuration..."

    PENDING_SSID_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.key=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_SSID_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.key=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_SSID_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.key=" | cut -d= -f2- | tr -d "'" | tail -1)

    log "Pending SSID WPA: ${PENDING_SSID_WPA:-none}"
    log "Pending KEY WPA: ${PENDING_KEY_WPA:+set}"
    log "Pending SSID OPEN: ${PENDING_SSID_OPEN:-none}"
    log "Pending KEY OPEN: ${PENDING_KEY_OPEN:+set}"
    log "Pending SSID MGMT: ${PENDING_SSID_MGMT:-none}"
    log "Pending KEY MGMT: ${PENDING_KEY_MGMT:+set}"

    [ -n "$PENDING_SSID_WPA" ] && uci revert wireless.wlan0wpa.ssid
    [ -n "$PENDING_KEY_WPA" ] && uci revert wireless.wlan0wpa.key
    [ -n "$PENDING_SSID_OPEN" ] && uci revert wireless.wlan0open.ssid
    [ -n "$PENDING_KEY_OPEN" ] && uci revert wireless.wlan0open.key
    [ -n "$PENDING_SSID_MGMT" ] && uci revert wireless.wlan0mgmt.ssid
    [ -n "$PENDING_KEY_MGMT" ] && uci revert wireless.wlan0mgmt.key

    if [ "$TARGET_MODE" = "lan" ]; then
        log "Converting back to br-lan (all interfaces)..."

        if [ -n "$CURRENT_IFACE" ]; then
            uci set wireless.${CURRENT_IFACE}.network='lan'
            uci commit wireless
            uci del_list network.br_evil.ports="${CURRENT_IFACE}"
            uci add_list network.brlan.ports="${CURRENT_IFACE}"
            uci commit network
        fi

        log "Removing br-evil and evil network..."
        uci delete network.evil 2>/dev/null
        uci delete network.br_evil 2>/dev/null
        uci commit network

        sed -i "/config device/{N;/name 'br-evil'/,/^$/d}" /etc/config/network
        sed -i "/config interface 'evil'/,/^$/d" /etc/config/network

        log "Removing evil DHCP config..."
        uci delete dhcp.evil 2>/dev/null
        uci commit dhcp
        sed -i "/config dhcp 'evil'/,/^$/d" /etc/config/dhcp

        log "Removing evil firewall zone..."
        while uci show firewall | grep -q "name='evil'"; do
            LAST_ZONE=$(uci show firewall | grep "name='evil'" | sed 's/firewall\.\@zone\[\([0-9]*\)\].*/\1/')
            if [ -n "$LAST_ZONE" ]; then
                uci delete firewall.@zone[$LAST_ZONE]
            else
                break
            fi
        done

        log "Removing evil forwarding rule..."
        while uci show firewall | grep -q "src='evil'"; do
            LAST_FWD=$(uci show firewall | grep "src='evil'" | sed 's/firewall\.\@forwarding\[\([0-9]*\)\].*/\1/')
            if [ -n "$LAST_FWD" ]; then
                uci delete firewall.@forwarding[$LAST_FWD]
            else
                break
            fi
        done
        uci commit firewall

        log "Updating init script..."
        sed -i 's|iifname "br-evil"|iifname "br-lan"|g' /etc/init.d/evilportal
        sed -i 's|dnat ip to 10.0.0.1:|dnat ip to 172.16.52.1:|g' /etc/init.d/evilportal
        sed -i 's|dnat ip to 10.0.0.1|dnat ip to 172.16.52.1|g' /etc/init.d/evilportal
        sed -i "s|firewall.@redirect\[-1\].src='evil'|firewall.@redirect[-1].src='lan'|g" /etc/init.d/evilportal
        sed -i "s|firewall.@redirect\[-1\].dest_ip='10.0.0.1'|firewall.@redirect[-1].dest_ip='172.16.52.1'|g" /etc/init.d/evilportal

    elif [ "$CURRENT_BRIDGE" = "br-evil" ] && [ -n "$CURRENT_IFACE" ]; then
        log "Swapping ${CURRENT_IFACE} for ${TARGET_IFACE} on br-evil..."

        uci del wireless.${CURRENT_IFACE}.network
        uci set wireless.${CURRENT_IFACE}.network='lan'
        uci set wireless.${TARGET_IFACE}.network='evil'
        uci commit wireless

        uci del_list network.br_evil.ports="${CURRENT_IFACE}"
        uci add_list network.br_evil.ports="${TARGET_IFACE}"
        uci commit network

    else
        log "Converting from br-lan to br-evil with ${TARGET_IFACE}..."

        echo -e "\nconfig device\n        option name 'br-evil'\n        option type 'bridge'\n\nconfig interface 'evil'\n        option device 'br-evil'\n        option proto 'static'\n        option ipaddr '10.0.0.1'\n        option netmask '255.255.255.0'" >> /etc/config/network

        echo -e "\nconfig dhcp 'evil'\n        option interface 'evil'\n        option start '100'\n        option limit '150'\n        option leasetime '1h'" >> /etc/config/dhcp

        uci del_list network.brlan.ports="${TARGET_IFACE}"
        uci commit network

        uci set wireless.${TARGET_IFACE}.network='evil'
        uci set wireless.${OTHER_IFACE}.network='lan'
        uci commit wireless

        uci add firewall zone
        uci set firewall.@zone[-1].name='evil'
        uci set firewall.@zone[-1].network='evil'
        uci set firewall.@zone[-1].input='ACCEPT'
        uci set firewall.@zone[-1].output='ACCEPT'
        uci set firewall.@zone[-1].forward='REJECT'
        uci add firewall forwarding
        uci set firewall.@forwarding[-1].src='evil'
        uci set firewall.@forwarding[-1].dest='wan'
        uci commit firewall

        sed -i 's|iifname "br-lan"|iifname "br-evil"|g' /etc/init.d/evilportal
        sed -i 's|dnat ip to 172.16.52.1:|dnat ip to 10.0.0.1:|g' /etc/init.d/evilportal
        sed -i 's|dnat ip to 172.16.52.1|dnat ip to 10.0.0.1|g' /etc/init.d/evilportal
        sed -i "s|firewall.@redirect\[-1\].src='lan'|firewall.@redirect[-1].src='evil'|g" /etc/init.d/evilportal
        sed -i "s|firewall.@redirect\[-1\].dest_ip='172.16.52.1'|firewall.@redirect[-1].dest_ip='10.0.0.1'|g" /etc/init.d/evilportal
    fi

    log "SUCCESS: Network configuration updated"

    # ====================================================================
    # Add new Evil Portal NAT rules
    # ====================================================================
    log "Adding new Evil Portal NAT rules..."
    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal HTTPS'
    uci set firewall.@redirect[-1].src="${FIREWALL_SRC}"
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='443'
    uci set firewall.@redirect[-1].dest_ip="${PORTAL_IP}"
    uci set firewall.@redirect[-1].dest_port='80'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal HTTP'
    uci set firewall.@redirect[-1].src="${FIREWALL_SRC}"
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='80'
    uci set firewall.@redirect[-1].dest_ip="${PORTAL_IP}"
    uci set firewall.@redirect[-1].dest_port='80'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal DNS TCP'
    uci set firewall.@redirect[-1].src="${FIREWALL_SRC}"
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='53'
    uci set firewall.@redirect[-1].dest_ip="${PORTAL_IP}"
    uci set firewall.@redirect[-1].dest_port='5353'
    uci set firewall.@redirect[-1].target='DNAT'

    uci add firewall redirect
    uci set firewall.@redirect[-1].name='Evil Portal DNS UDP'
    uci set firewall.@redirect[-1].src="${FIREWALL_SRC}"
    uci set firewall.@redirect[-1].proto='udp'
    uci set firewall.@redirect[-1].src_dport='53'
    uci set firewall.@redirect[-1].dest_ip="${PORTAL_IP}"
    uci set firewall.@redirect[-1].dest_port='5353'
    uci set firewall.@redirect[-1].target='DNAT'

    uci commit firewall
    log "SUCCESS: New NAT rules added"

    # ====================================================================
    # Apply network changes
    # ====================================================================
    log "Applying network changes..."
    /etc/init.d/network restart
    sleep 10
    wifi
    wait_for_internet

    # ====================================================================
    # Restart firewall
    # ====================================================================
    log "Restarting firewall..."
    /etc/init.d/firewall restart
    log "SUCCESS: Firewall restarted"

    # ====================================================================
    # Start Evil Portal
    # ====================================================================
    log "Starting Evil Portal..."
    /etc/init.d/evilportal start
    sleep 5

    if ! pgrep nginx > /dev/null; then
        log "ERROR: Failed to start nginx"
        return 1
    fi

    if ! pgrep -f "evilportal-whitelist-daemon" > /dev/null; then
        log "WARNING: Whitelist daemon not running"
    fi

    if ! pgrep -f "dnsmasq.*5353" > /dev/null; then
        log "WARNING: DNS spoof daemon not running"
    fi

    log "SUCCESS: Evil Portal started"

    # ====================================================================
    # Bring up target interface (isolated mode only)
    # ====================================================================
    if [ "$TARGET_MODE" = "isolated" ]; then
        log "Bringing up ${TARGET_IFACE}..."
        uci set wireless.${TARGET_IFACE}.disabled='0'
        uci commit wireless
        wifi reload
        log "Waiting for ${TARGET_IFACE} to come up..."
        WAIT_COUNT=0
        until ip link show ${TARGET_IFACE} 2>/dev/null | grep -q "UP"; do
            sleep 2
            WAIT_COUNT=$((WAIT_COUNT + 1))
            if [ $WAIT_COUNT -ge 15 ]; then
                log "ERROR: ${TARGET_IFACE} failed to come up after 30 seconds"
                return 1
            fi
        done
        sleep 5
        log "Bringing up evil interface..."
        ifup evil
        sleep 5
        wait_for_internet
    fi

    # Re-stage all pending SSID/key changes without committing
    [ -n "$PENDING_SSID_WPA" ] && uci set wireless.wlan0wpa.ssid="$PENDING_SSID_WPA"
    [ -n "$PENDING_KEY_WPA" ] && uci set wireless.wlan0wpa.key="$PENDING_KEY_WPA"
    [ -n "$PENDING_SSID_OPEN" ] && uci set wireless.wlan0open.ssid="$PENDING_SSID_OPEN"
    [ -n "$PENDING_KEY_OPEN" ] && uci set wireless.wlan0open.key="$PENDING_KEY_OPEN"
    [ -n "$PENDING_SSID_MGMT" ] && uci set wireless.wlan0mgmt.ssid="$PENDING_SSID_MGMT"
    [ -n "$PENDING_KEY_MGMT" ] && uci set wireless.wlan0mgmt.key="$PENDING_KEY_MGMT"

    if [ -n "$PENDING_SSID_WPA" ] || [ -n "$PENDING_KEY_WPA" ] || \
       [ -n "$PENDING_SSID_OPEN" ] || [ -n "$PENDING_KEY_OPEN" ] || \
       [ -n "$PENDING_SSID_MGMT" ] || [ -n "$PENDING_KEY_MGMT" ]; then
        wifi reload
        if [ "$TARGET_MODE" = "isolated" ]; then
            sleep 5
            ifup evil
            wait_for_internet
        fi
    fi

    # ====================================================================
    # Verify
    # ====================================================================
    log "Verifying configuration..."

    log "Verifying NAT rules..."
    if nft list ruleset 2>/dev/null | grep -q "dnat ip to ${PORTAL_IP}"; then
        log "SUCCESS: NAT rules configured"
    else
        log "ERROR: NAT rules not found"
        return 1
    fi

    if [ "$TARGET_MODE" = "isolated" ]; then
        log "Verifying interface network assignment..."
        if uci show wireless.${TARGET_IFACE}.network 2>/dev/null | grep -q "evil"; then
            log "SUCCESS: ${TARGET_IFACE} assigned to evil network"
        else
            log "ERROR: ${TARGET_IFACE} not assigned to evil network"
            return 1
        fi

        log "Verifying OTHER_IFACE network assignment..."
        if uci show wireless.${OTHER_IFACE}.network 2>/dev/null | grep -q "lan"; then
            log "SUCCESS: ${OTHER_IFACE} assigned to lan network"
        else
            log "ERROR: ${OTHER_IFACE} not assigned to lan network"
            return 1
        fi

        log "Verifying br-evil exists..."
        if uci show network | grep -q "name='br-evil'"; then
            log "SUCCESS: br-evil bridge exists"
        else
            log "ERROR: br-evil bridge not found"
            return 1
        fi

    elif [ "$TARGET_MODE" = "lan" ]; then
        log "Verifying br-evil is removed..."
        if uci show network | grep -q "name='br-evil'"; then
            log "ERROR: br-evil still exists"
            return 1
        else
            log "SUCCESS: br-evil removed"
        fi

        log "Verifying init script..."
        if grep -q "br-lan" /etc/init.d/evilportal && grep -q "172.16.52.1" /etc/init.d/evilportal; then
            log "SUCCESS: Init script updated correctly"
        else
            log "ERROR: Init script not updated correctly"
            return 1
        fi
    fi

    # ====================================================================
    # Wait for interfaces to be fully up (isolated mode only)
    # ====================================================================
    if [ "$TARGET_MODE" = "isolated" ]; then
        log "Waiting for interfaces to be fully up..."
        log "Waiting 15 seconds before checking..."
        sleep 15

        ELAPSED=0
        MAX_WAIT=30
        while [ $ELAPSED -lt $MAX_WAIT ]; do
            TARGET_OK=0
            OTHER_OK=0
            iface_ready "$TARGET_IFACE" && TARGET_OK=1
            iface_ready "$OTHER_IFACE" && OTHER_OK=1

            if [ $TARGET_OK -eq 1 ] && [ $OTHER_OK -eq 1 ]; then
                log "SUCCESS: Both interfaces fully up"
                log "  ${TARGET_IFACE}: BROADCAST,MULTICAST,UP,LOWER_UP state UP"
                log "  ${OTHER_IFACE}: BROADCAST,MULTICAST,UP,LOWER_UP state UP"

                MASTER_ELAPSED=0
                MASTER_MAX=30
                while [ $MASTER_ELAPSED -lt $MASTER_MAX ]; do
                    MASTER=$(ip link show "$TARGET_IFACE" 2>/dev/null | grep -o 'master [^ ]*' | cut -d' ' -f2)
                    if [ "$MASTER" = "br-evil" ]; then
                        log "SUCCESS: ${TARGET_IFACE} mastered to br-evil"
                        break
                    fi
                    log "Waiting for ${TARGET_IFACE} to be mastered to br-evil... (${MASTER_ELAPSED}s / ${MASTER_MAX}s)"
                    sleep 5
                    MASTER_ELAPSED=$((MASTER_ELAPSED + 5))
                    if [ $MASTER_ELAPSED -ge $MASTER_MAX ]; then
                        log "ERROR: ${TARGET_IFACE} mastered to '${MASTER}' instead of br-evil after ${MASTER_MAX}s"
                        return 1
                    fi
                done

                if [ -n "$PENDING_SSID_WPA" ]; then
                    BROADCASTING_WPA=$(iwinfo wlan0wpa info 2>/dev/null | grep 'ESSID' | cut -d'"' -f2)
                    if [ "$BROADCASTING_WPA" = "$PENDING_SSID_WPA" ]; then
                        log "SUCCESS: wlan0wpa broadcasting staged SSID: ${PENDING_SSID_WPA}"
                    else
                        log "ERROR: wlan0wpa broadcasting '${BROADCASTING_WPA}' but expected staged SSID '${PENDING_SSID_WPA}'"
                        return 1
                    fi
                fi

                if [ -n "$PENDING_SSID_OPEN" ]; then
                    BROADCASTING_OPEN=$(iwinfo wlan0open info 2>/dev/null | grep 'ESSID' | cut -d'"' -f2)
                    if [ "$BROADCASTING_OPEN" = "$PENDING_SSID_OPEN" ]; then
                        log "SUCCESS: wlan0open broadcasting staged SSID: ${PENDING_SSID_OPEN}"
                    else
                        log "ERROR: wlan0open broadcasting '${BROADCASTING_OPEN}' but expected staged SSID '${PENDING_SSID_OPEN}'"
                        return 1
                    fi
                fi

                break
            fi

            [ $TARGET_OK -eq 0 ] && log "Waiting for ${TARGET_IFACE}... (${ELAPSED}s / ${MAX_WAIT}s)"
            [ $OTHER_OK -eq 0 ] && log "Waiting for ${OTHER_IFACE}... (${ELAPSED}s / ${MAX_WAIT}s)"

            sleep 5
            ELAPSED=$((ELAPSED + 5))

            if [ $ELAPSED -ge $MAX_WAIT ]; then
                [ $TARGET_OK -eq 0 ] && log "WARNING: ${TARGET_IFACE} did not reach BROADCAST,MULTICAST,UP,LOWER_UP state UP"
                [ $OTHER_OK -eq 0 ] && log "WARNING: ${OTHER_IFACE} did not reach BROADCAST,MULTICAST,UP,LOWER_UP state UP"
            fi
        done

        wait_for_internet
    fi

    return 0
}

# ====================================================================
# Main - 9 rounds replicating original log runs exactly:
#
#   Rounds 1-3 (group 1): start br-lan,    seq 3->1->2->3->2->1->3  WPA staged only
#   Rounds 4-6 (group 2): start wlan0wpa,  seq 1->2->3->1->3->2->1  Open staged only
#   Rounds 7-9 (group 3): start wlan0open, seq 2->3->1->2->1->3->2  Both staged
# ====================================================================
> "$LOG_FILE"

log "=================================================="
log "Evil Portal Interface Transition Test (Automated)"
log "9 rounds, 54 transitions, no user input"
log "=================================================="

# Each entry: "ROUND_NUM GROUP START T1 T2 T3 T4 T5 T6"
ROUNDS=(
    "1 1 3 1 2 3 2 1 3"
    "2 1 3 1 2 3 2 1 3"
    "3 1 3 1 2 3 2 1 3"
    "4 2 1 2 3 1 3 2 1"
    "5 2 1 2 3 1 3 2 1"
    "6 2 1 2 3 1 3 2 1"
    "7 3 2 3 1 2 1 3 2"
    "8 3 2 3 1 2 1 3 2"
    "9 3 2 3 1 2 1 3 2"
)

CURRENT_GROUP=0

for round_entry in "${ROUNDS[@]}"; do
    ROUND_NUM=$(echo "$round_entry" | awk '{print $1}')
    GROUP=$(echo "$round_entry"     | awk '{print $2}')
    START=$(echo "$round_entry"     | awk '{print $3}')
    T1=$(echo "$round_entry"        | awk '{print $4}')
    T2=$(echo "$round_entry"        | awk '{print $5}')
    T3=$(echo "$round_entry"        | awk '{print $6}')
    T4=$(echo "$round_entry"        | awk '{print $7}')
    T5=$(echo "$round_entry"        | awk '{print $8}')
    T6=$(echo "$round_entry"        | awk '{print $9}')

    # Stage changes at the start of each group (rounds 1, 4, 7)
    # clear_staged_changes inside stage_changes_for_group prevents stacking
    if [ "$GROUP" != "$CURRENT_GROUP" ]; then
        CURRENT_GROUP=$GROUP
        stage_changes_for_group "$GROUP"
    fi

    log "========== ROUND ${ROUND_NUM} =========="
    log "Detected starting state: $(state_name $START)"
    log "Sequence: $START $T1 $T2 $T3 $T4 $T5 $T6"

    PREV=$START
    for TO in $T1 $T2 $T3 $T4 $T5 $T6; do
        FROM_NAME="$(state_name $PREV)"
        LABEL="${FROM_NAME} -> $(state_name $TO)"

        run_transition "$TO" "$FROM_NAME"
        EXIT_CODE=$?

        if [ $EXIT_CODE -ne 0 ]; then
            FAIL=$((FAIL + 1))
            log "FAIL: ${LABEL}"
            FAIL_LIST="${FAIL_LIST}  Round ${ROUND_NUM}: ${LABEL}\n"
        else
            PASS=$((PASS + 1))
            log "PASS: ${LABEL}"
        fi

        PREV=$TO
    done

    log "========== ROUND ${ROUND_NUM} COMPLETE — PASSED: ${PASS} =========="
done

# ====================================================================
# Final report
# ====================================================================
log "=================================================="
log "Test Run Complete"
log "TOTAL PASSED: ${PASS} / 54"
log "TOTAL FAILED: ${FAIL} / 54"
if [ -n "$FAIL_LIST" ]; then
    log "Failed transitions:"
    printf "%b" "$FAIL_LIST" | while IFS= read -r line; do
        [ -n "$line" ] && log "  $line"
    done
fi
log "=================================================="

exit $FAIL
