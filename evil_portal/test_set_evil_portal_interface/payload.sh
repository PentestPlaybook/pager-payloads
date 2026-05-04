#!/bin/bash
# Name: Test Set Evil Portal Interface (Automated)
# Description: Runs all 9 rounds (54 transitions) without user input. Stages a unique UCI buffer value before each transition to verify | tail -1 correctly picks the most recent staged value from a dirty buffer. Continues on failure and reports full pass/fail summary at end.
# Author: PentestPlaybook
# Version: 1.7
# Category: Evil Portal

PORTAL_IP_EVIL="10.0.0.1"
PORTAL_IP_LAN="172.16.52.1"
BRIDGE_IF_EVIL="br-evil"
BRIDGE_IF_LAN="br-lan"
LOG_FILE="/tmp/evil_portal_transition_test.log"
PASS=0
FAIL=0
FAIL_LIST=""

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

run_transition() {
    local to="$1"
    local from_name="$2"
    local exp_wpa_ssid="$3"
    local exp_wpa_key="$4"
    local exp_open_ssid="$5"
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

    log "Raw UCI buffer:"
    uci changes wireless | while IFS= read -r line; do log "  ${line}"; done

    PENDING_SSID_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.key=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_SSID_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.key=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_SSID_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.ssid=" | cut -d= -f2- | tr -d "'" | tail -1)
    PENDING_KEY_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.key=" | cut -d= -f2- | tr -d "'" | tail -1)

    log "Pending SSID WPA: ${PENDING_SSID_WPA:-none}"
    log "Pending KEY WPA: ${PENDING_KEY_WPA:-none}"
    log "Pending SSID OPEN: ${PENDING_SSID_OPEN:-none}"
    log "Pending KEY OPEN: ${PENDING_KEY_OPEN:-none}"
    log "Pending SSID MGMT: ${PENDING_SSID_MGMT:-none}"
    log "Pending KEY MGMT: ${PENDING_KEY_MGMT:-none}"

    log "Expected SSID WPA: ${exp_wpa_ssid}"
    log "Expected KEY WPA: ${exp_wpa_key}"
    log "Expected SSID OPEN: ${exp_open_ssid}"

    # Verify | tail -1 picked the correct (most recently staged) values
    if [ "$PENDING_SSID_WPA" != "$exp_wpa_ssid" ]; then
        log "ERROR: PENDING_SSID_WPA='${PENDING_SSID_WPA}' but expected '${exp_wpa_ssid}'"
        return 1
    fi
    if [ "$PENDING_KEY_WPA" != "$exp_wpa_key" ]; then
        log "ERROR: PENDING_KEY_WPA mismatch: expected '${exp_wpa_key}'"
        return 1
    fi
    if [ "$PENDING_SSID_OPEN" != "$exp_open_ssid" ]; then
        log "ERROR: PENDING_SSID_OPEN='${PENDING_SSID_OPEN}' but expected '${exp_open_ssid}'"
        return 1
    fi
    log "SUCCESS: Pending values match expected (| tail -1 correct)"

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
# Main - 9 rounds, 54 transitions
# A unique WPA SSID/key and Open SSID is staged before each transition.
# The buffer is naturally dirty from the previous transition's re-staged
# values, so | tail -1 is exercised on every run from transition 2 onward.
# ====================================================================
> "$LOG_FILE"

log "=================================================="
log "Evil Portal Interface Transition Test (Automated)"
log "9 rounds, 54 transitions, dirty buffer | tail -1 verification"
log "=================================================="

log "========== ROUND 1 =========="
log "Detected starting state: $(state_name 3)"
log "Sequence: 3 1 2 3 2 1 3"

# Transition 1: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net001'
uci set wireless.wlan0wpa.key='Pass001!'
uci set wireless.wlan0open.ssid='Open001'
log "Staged buffer for transition 1: WPA=Net001 KEY=Pass001! OPEN=Open001"

run_transition 1 "$(state_name 3)" 'Net001' 'Pass001!' 'Open001'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 2: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net002'
uci set wireless.wlan0wpa.key='Pass002!'
uci set wireless.wlan0open.ssid='Open002'
log "Staged buffer for transition 2: WPA=Net002 KEY=Pass002! OPEN=Open002"

run_transition 2 "$(state_name 1)" 'Net002' 'Pass002!' 'Open002'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 3: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net003'
uci set wireless.wlan0wpa.key='Pass003!'
uci set wireless.wlan0open.ssid='Open003'
log "Staged buffer for transition 3: WPA=Net003 KEY=Pass003! OPEN=Open003"

run_transition 3 "$(state_name 2)" 'Net003' 'Pass003!' 'Open003'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 4: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net004'
uci set wireless.wlan0wpa.key='Pass004!'
uci set wireless.wlan0open.ssid='Open004'
log "Staged buffer for transition 4: WPA=Net004 KEY=Pass004! OPEN=Open004"

run_transition 2 "$(state_name 3)" 'Net004' 'Pass004!' 'Open004'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 5: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net005'
uci set wireless.wlan0wpa.key='Pass005!'
uci set wireless.wlan0open.ssid='Open005'
log "Staged buffer for transition 5: WPA=Net005 KEY=Pass005! OPEN=Open005"

run_transition 1 "$(state_name 2)" 'Net005' 'Pass005!' 'Open005'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 6: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net006'
uci set wireless.wlan0wpa.key='Pass006!'
uci set wireless.wlan0open.ssid='Open006'
log "Staged buffer for transition 6: WPA=Net006 KEY=Pass006! OPEN=Open006"

run_transition 3 "$(state_name 1)" 'Net006' 'Pass006!' 'Open006'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 1: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

log "========== ROUND 1 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 2 =========="
log "Detected starting state: $(state_name 3)"
log "Sequence: 3 1 2 3 2 1 3"

# Transition 7: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net007'
uci set wireless.wlan0wpa.key='Pass007!'
uci set wireless.wlan0open.ssid='Open007'
log "Staged buffer for transition 7: WPA=Net007 KEY=Pass007! OPEN=Open007"

run_transition 1 "$(state_name 3)" 'Net007' 'Pass007!' 'Open007'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 8: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net008'
uci set wireless.wlan0wpa.key='Pass008!'
uci set wireless.wlan0open.ssid='Open008'
log "Staged buffer for transition 8: WPA=Net008 KEY=Pass008! OPEN=Open008"

run_transition 2 "$(state_name 1)" 'Net008' 'Pass008!' 'Open008'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 9: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net009'
uci set wireless.wlan0wpa.key='Pass009!'
uci set wireless.wlan0open.ssid='Open009'
log "Staged buffer for transition 9: WPA=Net009 KEY=Pass009! OPEN=Open009"

run_transition 3 "$(state_name 2)" 'Net009' 'Pass009!' 'Open009'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 10: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net010'
uci set wireless.wlan0wpa.key='Pass010!'
uci set wireless.wlan0open.ssid='Open010'
log "Staged buffer for transition 10: WPA=Net010 KEY=Pass010! OPEN=Open010"

run_transition 2 "$(state_name 3)" 'Net010' 'Pass010!' 'Open010'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 11: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net011'
uci set wireless.wlan0wpa.key='Pass011!'
uci set wireless.wlan0open.ssid='Open011'
log "Staged buffer for transition 11: WPA=Net011 KEY=Pass011! OPEN=Open011"

run_transition 1 "$(state_name 2)" 'Net011' 'Pass011!' 'Open011'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 12: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net012'
uci set wireless.wlan0wpa.key='Pass012!'
uci set wireless.wlan0open.ssid='Open012'
log "Staged buffer for transition 12: WPA=Net012 KEY=Pass012! OPEN=Open012"

run_transition 3 "$(state_name 1)" 'Net012' 'Pass012!' 'Open012'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 2: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

log "========== ROUND 2 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 3 =========="
log "Detected starting state: $(state_name 3)"
log "Sequence: 3 1 2 3 2 1 3"

# Transition 13: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net013'
uci set wireless.wlan0wpa.key='Pass013!'
uci set wireless.wlan0open.ssid='Open013'
log "Staged buffer for transition 13: WPA=Net013 KEY=Pass013! OPEN=Open013"

run_transition 1 "$(state_name 3)" 'Net013' 'Pass013!' 'Open013'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 14: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net014'
uci set wireless.wlan0wpa.key='Pass014!'
uci set wireless.wlan0open.ssid='Open014'
log "Staged buffer for transition 14: WPA=Net014 KEY=Pass014! OPEN=Open014"

run_transition 2 "$(state_name 1)" 'Net014' 'Pass014!' 'Open014'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 15: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net015'
uci set wireless.wlan0wpa.key='Pass015!'
uci set wireless.wlan0open.ssid='Open015'
log "Staged buffer for transition 15: WPA=Net015 KEY=Pass015! OPEN=Open015"

run_transition 3 "$(state_name 2)" 'Net015' 'Pass015!' 'Open015'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 16: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net016'
uci set wireless.wlan0wpa.key='Pass016!'
uci set wireless.wlan0open.ssid='Open016'
log "Staged buffer for transition 16: WPA=Net016 KEY=Pass016! OPEN=Open016"

run_transition 2 "$(state_name 3)" 'Net016' 'Pass016!' 'Open016'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 17: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net017'
uci set wireless.wlan0wpa.key='Pass017!'
uci set wireless.wlan0open.ssid='Open017'
log "Staged buffer for transition 17: WPA=Net017 KEY=Pass017! OPEN=Open017"

run_transition 1 "$(state_name 2)" 'Net017' 'Pass017!' 'Open017'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 18: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net018'
uci set wireless.wlan0wpa.key='Pass018!'
uci set wireless.wlan0open.ssid='Open018'
log "Staged buffer for transition 18: WPA=Net018 KEY=Pass018! OPEN=Open018"

run_transition 3 "$(state_name 1)" 'Net018' 'Pass018!' 'Open018'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 3: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

log "========== ROUND 3 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 4 =========="
log "Detected starting state: $(state_name 1)"
log "Sequence: 1 2 3 1 3 2 1"

# Transition 19: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net019'
uci set wireless.wlan0wpa.key='Pass019!'
uci set wireless.wlan0open.ssid='Open019'
log "Staged buffer for transition 19: WPA=Net019 KEY=Pass019! OPEN=Open019"

run_transition 2 "$(state_name 1)" 'Net019' 'Pass019!' 'Open019'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 20: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net020'
uci set wireless.wlan0wpa.key='Pass020!'
uci set wireless.wlan0open.ssid='Open020'
log "Staged buffer for transition 20: WPA=Net020 KEY=Pass020! OPEN=Open020"

run_transition 3 "$(state_name 2)" 'Net020' 'Pass020!' 'Open020'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 21: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net021'
uci set wireless.wlan0wpa.key='Pass021!'
uci set wireless.wlan0open.ssid='Open021'
log "Staged buffer for transition 21: WPA=Net021 KEY=Pass021! OPEN=Open021"

run_transition 1 "$(state_name 3)" 'Net021' 'Pass021!' 'Open021'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 22: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net022'
uci set wireless.wlan0wpa.key='Pass022!'
uci set wireless.wlan0open.ssid='Open022'
log "Staged buffer for transition 22: WPA=Net022 KEY=Pass022! OPEN=Open022"

run_transition 3 "$(state_name 1)" 'Net022' 'Pass022!' 'Open022'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 23: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net023'
uci set wireless.wlan0wpa.key='Pass023!'
uci set wireless.wlan0open.ssid='Open023'
log "Staged buffer for transition 23: WPA=Net023 KEY=Pass023! OPEN=Open023"

run_transition 2 "$(state_name 3)" 'Net023' 'Pass023!' 'Open023'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 24: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net024'
uci set wireless.wlan0wpa.key='Pass024!'
uci set wireless.wlan0open.ssid='Open024'
log "Staged buffer for transition 24: WPA=Net024 KEY=Pass024! OPEN=Open024"

run_transition 1 "$(state_name 2)" 'Net024' 'Pass024!' 'Open024'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 4: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

log "========== ROUND 4 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 5 =========="
log "Detected starting state: $(state_name 1)"
log "Sequence: 1 2 3 1 3 2 1"

# Transition 25: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net025'
uci set wireless.wlan0wpa.key='Pass025!'
uci set wireless.wlan0open.ssid='Open025'
log "Staged buffer for transition 25: WPA=Net025 KEY=Pass025! OPEN=Open025"

run_transition 2 "$(state_name 1)" 'Net025' 'Pass025!' 'Open025'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 26: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net026'
uci set wireless.wlan0wpa.key='Pass026!'
uci set wireless.wlan0open.ssid='Open026'
log "Staged buffer for transition 26: WPA=Net026 KEY=Pass026! OPEN=Open026"

run_transition 3 "$(state_name 2)" 'Net026' 'Pass026!' 'Open026'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 27: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net027'
uci set wireless.wlan0wpa.key='Pass027!'
uci set wireless.wlan0open.ssid='Open027'
log "Staged buffer for transition 27: WPA=Net027 KEY=Pass027! OPEN=Open027"

run_transition 1 "$(state_name 3)" 'Net027' 'Pass027!' 'Open027'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 28: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net028'
uci set wireless.wlan0wpa.key='Pass028!'
uci set wireless.wlan0open.ssid='Open028'
log "Staged buffer for transition 28: WPA=Net028 KEY=Pass028! OPEN=Open028"

run_transition 3 "$(state_name 1)" 'Net028' 'Pass028!' 'Open028'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 29: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net029'
uci set wireless.wlan0wpa.key='Pass029!'
uci set wireless.wlan0open.ssid='Open029'
log "Staged buffer for transition 29: WPA=Net029 KEY=Pass029! OPEN=Open029"

run_transition 2 "$(state_name 3)" 'Net029' 'Pass029!' 'Open029'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 30: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net030'
uci set wireless.wlan0wpa.key='Pass030!'
uci set wireless.wlan0open.ssid='Open030'
log "Staged buffer for transition 30: WPA=Net030 KEY=Pass030! OPEN=Open030"

run_transition 1 "$(state_name 2)" 'Net030' 'Pass030!' 'Open030'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 5: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

log "========== ROUND 5 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 6 =========="
log "Detected starting state: $(state_name 1)"
log "Sequence: 1 2 3 1 3 2 1"

# Transition 31: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net031'
uci set wireless.wlan0wpa.key='Pass031!'
uci set wireless.wlan0open.ssid='Open031'
log "Staged buffer for transition 31: WPA=Net031 KEY=Pass031! OPEN=Open031"

run_transition 2 "$(state_name 1)" 'Net031' 'Pass031!' 'Open031'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 32: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net032'
uci set wireless.wlan0wpa.key='Pass032!'
uci set wireless.wlan0open.ssid='Open032'
log "Staged buffer for transition 32: WPA=Net032 KEY=Pass032! OPEN=Open032"

run_transition 3 "$(state_name 2)" 'Net032' 'Pass032!' 'Open032'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 33: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net033'
uci set wireless.wlan0wpa.key='Pass033!'
uci set wireless.wlan0open.ssid='Open033'
log "Staged buffer for transition 33: WPA=Net033 KEY=Pass033! OPEN=Open033"

run_transition 1 "$(state_name 3)" 'Net033' 'Pass033!' 'Open033'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 34: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net034'
uci set wireless.wlan0wpa.key='Pass034!'
uci set wireless.wlan0open.ssid='Open034'
log "Staged buffer for transition 34: WPA=Net034 KEY=Pass034! OPEN=Open034"

run_transition 3 "$(state_name 1)" 'Net034' 'Pass034!' 'Open034'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 35: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net035'
uci set wireless.wlan0wpa.key='Pass035!'
uci set wireless.wlan0open.ssid='Open035'
log "Staged buffer for transition 35: WPA=Net035 KEY=Pass035! OPEN=Open035"

run_transition 2 "$(state_name 3)" 'Net035' 'Pass035!' 'Open035'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

# Transition 36: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net036'
uci set wireless.wlan0wpa.key='Pass036!'
uci set wireless.wlan0open.ssid='Open036'
log "Staged buffer for transition 36: WPA=Net036 KEY=Pass036! OPEN=Open036"

run_transition 1 "$(state_name 2)" 'Net036' 'Pass036!' 'Open036'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 6: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

log "========== ROUND 6 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 7 =========="
log "Detected starting state: $(state_name 2)"
log "Sequence: 2 3 1 2 1 3 2"

# Transition 37: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net037'
uci set wireless.wlan0wpa.key='Pass037!'
uci set wireless.wlan0open.ssid='Open037'
log "Staged buffer for transition 37: WPA=Net037 KEY=Pass037! OPEN=Open037"

run_transition 3 "$(state_name 2)" 'Net037' 'Pass037!' 'Open037'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 38: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net038'
uci set wireless.wlan0wpa.key='Pass038!'
uci set wireless.wlan0open.ssid='Open038'
log "Staged buffer for transition 38: WPA=Net038 KEY=Pass038! OPEN=Open038"

run_transition 1 "$(state_name 3)" 'Net038' 'Pass038!' 'Open038'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 39: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net039'
uci set wireless.wlan0wpa.key='Pass039!'
uci set wireless.wlan0open.ssid='Open039'
log "Staged buffer for transition 39: WPA=Net039 KEY=Pass039! OPEN=Open039"

run_transition 2 "$(state_name 1)" 'Net039' 'Pass039!' 'Open039'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 40: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net040'
uci set wireless.wlan0wpa.key='Pass040!'
uci set wireless.wlan0open.ssid='Open040'
log "Staged buffer for transition 40: WPA=Net040 KEY=Pass040! OPEN=Open040"

run_transition 1 "$(state_name 2)" 'Net040' 'Pass040!' 'Open040'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 41: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net041'
uci set wireless.wlan0wpa.key='Pass041!'
uci set wireless.wlan0open.ssid='Open041'
log "Staged buffer for transition 41: WPA=Net041 KEY=Pass041! OPEN=Open041"

run_transition 3 "$(state_name 1)" 'Net041' 'Pass041!' 'Open041'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 42: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net042'
uci set wireless.wlan0wpa.key='Pass042!'
uci set wireless.wlan0open.ssid='Open042'
log "Staged buffer for transition 42: WPA=Net042 KEY=Pass042! OPEN=Open042"

run_transition 2 "$(state_name 3)" 'Net042' 'Pass042!' 'Open042'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 7: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

log "========== ROUND 7 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 8 =========="
log "Detected starting state: $(state_name 2)"
log "Sequence: 2 3 1 2 1 3 2"

# Transition 43: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net043'
uci set wireless.wlan0wpa.key='Pass043!'
uci set wireless.wlan0open.ssid='Open043'
log "Staged buffer for transition 43: WPA=Net043 KEY=Pass043! OPEN=Open043"

run_transition 3 "$(state_name 2)" 'Net043' 'Pass043!' 'Open043'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 44: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net044'
uci set wireless.wlan0wpa.key='Pass044!'
uci set wireless.wlan0open.ssid='Open044'
log "Staged buffer for transition 44: WPA=Net044 KEY=Pass044! OPEN=Open044"

run_transition 1 "$(state_name 3)" 'Net044' 'Pass044!' 'Open044'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 45: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net045'
uci set wireless.wlan0wpa.key='Pass045!'
uci set wireless.wlan0open.ssid='Open045'
log "Staged buffer for transition 45: WPA=Net045 KEY=Pass045! OPEN=Open045"

run_transition 2 "$(state_name 1)" 'Net045' 'Pass045!' 'Open045'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 46: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net046'
uci set wireless.wlan0wpa.key='Pass046!'
uci set wireless.wlan0open.ssid='Open046'
log "Staged buffer for transition 46: WPA=Net046 KEY=Pass046! OPEN=Open046"

run_transition 1 "$(state_name 2)" 'Net046' 'Pass046!' 'Open046'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 47: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net047'
uci set wireless.wlan0wpa.key='Pass047!'
uci set wireless.wlan0open.ssid='Open047'
log "Staged buffer for transition 47: WPA=Net047 KEY=Pass047! OPEN=Open047"

run_transition 3 "$(state_name 1)" 'Net047' 'Pass047!' 'Open047'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 48: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net048'
uci set wireless.wlan0wpa.key='Pass048!'
uci set wireless.wlan0open.ssid='Open048'
log "Staged buffer for transition 48: WPA=Net048 KEY=Pass048! OPEN=Open048"

run_transition 2 "$(state_name 3)" 'Net048' 'Pass048!' 'Open048'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 8: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

log "========== ROUND 8 COMPLETE — PASSED: ${PASS} =========="

log "========== ROUND 9 =========="
log "Detected starting state: $(state_name 2)"
log "Sequence: 2 3 1 2 1 3 2"

# Transition 49: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net049'
uci set wireless.wlan0wpa.key='Pass049!'
uci set wireless.wlan0open.ssid='Open049'
log "Staged buffer for transition 49: WPA=Net049 KEY=Pass049! OPEN=Open049"

run_transition 3 "$(state_name 2)" 'Net049' 'Pass049!' 'Open049'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 2) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 3)"
fi

# Transition 50: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net050'
uci set wireless.wlan0wpa.key='Pass050!'
uci set wireless.wlan0open.ssid='Open050'
log "Staged buffer for transition 50: WPA=Net050 KEY=Pass050! OPEN=Open050"

run_transition 1 "$(state_name 3)" 'Net050' 'Pass050!' 'Open050'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 3) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 1)"
fi

# Transition 51: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net051'
uci set wireless.wlan0wpa.key='Pass051!'
uci set wireless.wlan0open.ssid='Open051'
log "Staged buffer for transition 51: WPA=Net051 KEY=Pass051! OPEN=Open051"

run_transition 2 "$(state_name 1)" 'Net051' 'Pass051!' 'Open051'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 1) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 2)"
fi

# Transition 52: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net052'
uci set wireless.wlan0wpa.key='Pass052!'
uci set wireless.wlan0open.ssid='Open052'
log "Staged buffer for transition 52: WPA=Net052 KEY=Pass052! OPEN=Open052"

run_transition 1 "$(state_name 2)" 'Net052' 'Pass052!' 'Open052'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 2) -> $(state_name 1)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 2) -> $(state_name 1)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 2) -> $(state_name 1)"
fi

# Transition 53: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net053'
uci set wireless.wlan0wpa.key='Pass053!'
uci set wireless.wlan0open.ssid='Open053'
log "Staged buffer for transition 53: WPA=Net053 KEY=Pass053! OPEN=Open053"

run_transition 3 "$(state_name 1)" 'Net053' 'Pass053!' 'Open053'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 1) -> $(state_name 3)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 1) -> $(state_name 3)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 1) -> $(state_name 3)"
fi

# Transition 54: stage unique buffer values
uci set wireless.wlan0wpa.ssid='Net054'
uci set wireless.wlan0wpa.key='Pass054!'
uci set wireless.wlan0open.ssid='Open054'
log "Staged buffer for transition 54: WPA=Net054 KEY=Pass054! OPEN=Open054"

run_transition 2 "$(state_name 3)" 'Net054' 'Pass054!' 'Open054'
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    FAIL=$((FAIL + 1))
    log "FAIL: $(state_name 3) -> $(state_name 2)"
    FAIL_LIST="${FAIL_LIST}  Round 9: $(state_name 3) -> $(state_name 2)\n"
else
    PASS=$((PASS + 1))
    log "PASS: $(state_name 3) -> $(state_name 2)"
fi

log "========== ROUND 9 COMPLETE — PASSED: ${PASS} =========="

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
