#!/bin/bash
# Name: Interface Manager
# Description: Displays interface status and manages interface activation
# Author: PentestPlaybook
# Version: 1.2
# Category: Evil Portal

disable_interface() {
    LOG "Info: Networking will be restarted."

    # Build menu with Evil Portal indicator
    WPA_EP=""
    OPEN_EP=""

    uci show wireless.wlan0wpa.network 2>/dev/null | grep -q "evil" && WPA_EP=" (Evil Portal)"
    uci show wireless.wlan0open.network 2>/dev/null | grep -q "evil" && OPEN_EP=" (Evil Portal)"

    MENU="Select interface to disable:\n\n"
    MENU="${MENU}1) Evil WPA${WPA_EP}\n"
    MENU="${MENU}2) Open AP${OPEN_EP}\n"
    MENU="${MENU}3) Management"

    LOG "$MENU"
    LOG "Press 'A' button to select."
    WAIT_FOR_BUTTON_PRESS A

    CHOICE=$(NUMBER_PICKER "Enter interface number" "")
    if [ $? -ne 0 ]; then
        exit 0
    fi

    case "$CHOICE" in
        1)
            SELECTED_IFACE="wlan0wpa"
            SELECTED_NAME="Evil WPA"
            ;;
        2)
            SELECTED_IFACE="wlan0open"
            SELECTED_NAME="Open AP"
            ;;
        3)
            SELECTED_IFACE="wlan0mgmt"
            SELECTED_NAME="Management"
            ;;
        *)
            ERROR_DIALOG "Invalid selection"
            exit 1
            ;;
    esac

    # Save any pending SSID/key changes before committing
    PENDING_SSID_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.ssid=" | cut -d= -f2- | tr -d "'")
    PENDING_KEY_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.key=" | cut -d= -f2- | tr -d "'")
    PENDING_SSID_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.ssid=" | cut -d= -f2- | tr -d "'")
    PENDING_KEY_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.key=" | cut -d= -f2- | tr -d "'")
    PENDING_SSID_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.ssid=" | cut -d= -f2- | tr -d "'")
    PENDING_KEY_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.key=" | cut -d= -f2- | tr -d "'")

    # Revert all pending SSID/key changes from the buffer
    [ -n "$PENDING_SSID_WPA" ] && uci revert wireless.wlan0wpa.ssid
    [ -n "$PENDING_KEY_WPA" ] && uci revert wireless.wlan0wpa.key
    [ -n "$PENDING_SSID_OPEN" ] && uci revert wireless.wlan0open.ssid
    [ -n "$PENDING_KEY_OPEN" ] && uci revert wireless.wlan0open.key
    [ -n "$PENDING_SSID_MGMT" ] && uci revert wireless.wlan0mgmt.ssid
    [ -n "$PENDING_KEY_MGMT" ] && uci revert wireless.wlan0mgmt.key

    LOG "Disabling ${SELECTED_NAME}..."
    uci set wireless.${SELECTED_IFACE}.disabled='1'
    uci commit wireless

    # Re-stage all pending SSID/key changes without committing
    [ -n "$PENDING_SSID_WPA" ] && uci set wireless.wlan0wpa.ssid="$PENDING_SSID_WPA"
    [ -n "$PENDING_KEY_WPA" ] && uci set wireless.wlan0wpa.key="$PENDING_KEY_WPA"
    [ -n "$PENDING_SSID_OPEN" ] && uci set wireless.wlan0open.ssid="$PENDING_SSID_OPEN"
    [ -n "$PENDING_KEY_OPEN" ] && uci set wireless.wlan0open.key="$PENDING_KEY_OPEN"
    [ -n "$PENDING_SSID_MGMT" ] && uci set wireless.wlan0mgmt.ssid="$PENDING_SSID_MGMT"
    [ -n "$PENDING_KEY_MGMT" ] && uci set wireless.wlan0mgmt.key="$PENDING_KEY_MGMT"

    LOG "Restarting Networking..."
    /etc/init.d/network restart
    sleep 10
    wifi
    sleep 35

    # Reload wifi if any values were restaged so interfaces reflect pending changes
    if [ -n "$PENDING_SSID_WPA" ] || [ -n "$PENDING_KEY_WPA" ] || \
       [ -n "$PENDING_SSID_OPEN" ] || [ -n "$PENDING_KEY_OPEN" ] || \
       [ -n "$PENDING_SSID_MGMT" ] || [ -n "$PENDING_KEY_MGMT" ]; then
        wifi reload
    fi

    LOG "Connectivity Restored"
    LOG ""
}

while true; do

    LOG "=================================================="
    LOG ""

    print_interface_status() {
        IFACE=$1

        # Get SSID
        SSID=$(uci get wireless.${IFACE}.ssid 2>/dev/null || echo "N/A")

        # Get encryption
        ENCRYPTION=$(uci get wireless.${IFACE}.encryption 2>/dev/null || echo "none")
        if echo "$ENCRYPTION" | grep -q "psk2"; then
            ENC_TYPE="WPA2"
        elif echo "$ENCRYPTION" | grep -q "psk"; then
            ENC_TYPE="WPA"
        else
            ENC_TYPE="Open"
        fi

        # Get passphrase
        if [ "$ENC_TYPE" = "Open" ]; then
            PASSPHRASE="N/A"
        else
            PASSPHRASE=$(uci get wireless.${IFACE}.key 2>/dev/null || echo "N/A")
        fi

        # Get status
        if iwinfo ${IFACE} info &>/dev/null; then
            STATUS="UP"
        else
            STATUS="DOWN"
        fi

        # Get Evil Portal status
        EP_BRIDGE=$(grep -o 'iifname "[^"]*"' /etc/init.d/evilportal 2>/dev/null | head -1 | grep -o '"[^"]*"' | tr -d '"')
        EP_RUNNING=0
        pgrep nginx > /dev/null && EP_RUNNING=1

        if [ "$EP_RUNNING" -eq 1 ]; then
            if [ "$EP_BRIDGE" = "br-lan" ]; then
                EVIL_PORTAL="Yes (All Interfaces)"
            elif [ "$EP_BRIDGE" = "br-evil" ]; then
                if uci show wireless.${IFACE}.network 2>/dev/null | grep -q "evil"; then
                    EVIL_PORTAL="Yes (Isolated)"
                else
                    EVIL_PORTAL="No"
                fi
            else
                EVIL_PORTAL="Not Installed"
            fi
        else
            EVIL_PORTAL="Not Installed"
        fi

        LOG "Interface: ${IFACE}"
        LOG "Encryption Type: ${ENC_TYPE}"
        LOG "SSID: ${SSID}"
        LOG "Passphrase: ${PASSPHRASE}"
        LOG "Status: ${STATUS}"
        LOG "Evil Portal: ${EVIL_PORTAL}"
        LOG ""
    }

    print_interface_status wlan0wpa
    print_interface_status wlan0open
    print_interface_status wlan0mgmt

    # Check interface states
    WPA_UP=0
    OPEN_UP=0
    MGMT_UP=0

    iwinfo wlan0wpa info &>/dev/null && WPA_UP=1
    iwinfo wlan0open info &>/dev/null && OPEN_UP=1
    iwinfo wlan0mgmt info &>/dev/null && MGMT_UP=1

    # Check if all three interfaces are up
    if [ "$WPA_UP" -eq 1 ] && [ "$OPEN_UP" -eq 1 ] && [ "$MGMT_UP" -eq 1 ]; then

        DIALOG_RESULT=$(CONFIRMATION_DIALOG "WARNING! All interfaces are up. Disable an interface to restore connectivity?")
        if [ "$DIALOG_RESULT" != "1" ]; then
            exit 0
        fi

        disable_interface
        continue

    fi

    # Check if Evil Portal interface is down
    EVIL_IFACE=""
    EVIL_IFACE_NAME=""

    if uci show wireless.wlan0wpa.network 2>/dev/null | grep -q "evil"; then
        EVIL_IFACE="wlan0wpa"
        EVIL_IFACE_NAME="Evil WPA"
    elif uci show wireless.wlan0open.network 2>/dev/null | grep -q "evil"; then
        EVIL_IFACE="wlan0open"
        EVIL_IFACE_NAME="Open AP"
    fi

    if [ -n "$EVIL_IFACE" ]; then
        EVIL_UP=0
        iwinfo ${EVIL_IFACE} info &>/dev/null && EVIL_UP=1

        if [ "$EVIL_UP" -eq 0 ]; then
            DIALOG_RESULT=$(CONFIRMATION_DIALOG "Evil Portal interface (${EVIL_IFACE_NAME}) is DOWN. Enable it?")
            if [ "$DIALOG_RESULT" = "1" ]; then

                # Check if enabling would cause 3 interfaces to be up
                INTERFACES_UP=$((WPA_UP + OPEN_UP + MGMT_UP))
                if [ "$INTERFACES_UP" -ge 2 ]; then
                    DIALOG_RESULT=$(CONFIRMATION_DIALOG "WARNING: Enabling ${EVIL_IFACE_NAME} would bring all 3 interfaces up. Disable an interface first?")
                    if [ "$DIALOG_RESULT" != "1" ]; then
                        exit 0
                    fi

                    # Build menu with Evil Portal indicator
                    WPA_EP=""
                    OPEN_EP=""

                    uci show wireless.wlan0wpa.network 2>/dev/null | grep -q "evil" && WPA_EP=" (Evil Portal)"
                    uci show wireless.wlan0open.network 2>/dev/null | grep -q "evil" && OPEN_EP=" (Evil Portal)"

                    MENU="Select interface to disable:\n\n"
                    MENU="${MENU}1) Evil WPA${WPA_EP}\n"
                    MENU="${MENU}2) Open AP${OPEN_EP}\n"
                    MENU="${MENU}3) Management"

                    LOG "$MENU"
                    LOG "Press 'A' button to select."
                    WAIT_FOR_BUTTON_PRESS A

                    CHOICE=$(NUMBER_PICKER "Enter interface number" "")
                    if [ $? -ne 0 ]; then
                        exit 0
                    fi

                    case "$CHOICE" in
                        1)
                            SELECTED_IFACE="wlan0wpa"
                            SELECTED_NAME="Evil WPA"
                            ;;
                        2)
                            SELECTED_IFACE="wlan0open"
                            SELECTED_NAME="Open AP"
                            ;;
                        3)
                            SELECTED_IFACE="wlan0mgmt"
                            SELECTED_NAME="Management"
                            ;;
                        *)
                            ERROR_DIALOG "Invalid selection"
                            exit 1
                            ;;
                    esac

                    # Save any pending SSID/key changes before committing
                    PENDING_SSID_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.ssid=" | cut -d= -f2- | tr -d "'")
                    PENDING_KEY_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.key=" | cut -d= -f2- | tr -d "'")
                    PENDING_SSID_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.ssid=" | cut -d= -f2- | tr -d "'")
                    PENDING_KEY_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.key=" | cut -d= -f2- | tr -d "'")
                    PENDING_SSID_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.ssid=" | cut -d= -f2- | tr -d "'")
                    PENDING_KEY_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.key=" | cut -d= -f2- | tr -d "'")

                    # Revert all pending SSID/key changes from the buffer
                    [ -n "$PENDING_SSID_WPA" ] && uci revert wireless.wlan0wpa.ssid
                    [ -n "$PENDING_KEY_WPA" ] && uci revert wireless.wlan0wpa.key
                    [ -n "$PENDING_SSID_OPEN" ] && uci revert wireless.wlan0open.ssid
                    [ -n "$PENDING_KEY_OPEN" ] && uci revert wireless.wlan0open.key
                    [ -n "$PENDING_SSID_MGMT" ] && uci revert wireless.wlan0mgmt.ssid
                    [ -n "$PENDING_KEY_MGMT" ] && uci revert wireless.wlan0mgmt.key

                    LOG "Disabling ${SELECTED_NAME}..."
                    uci set wireless.${SELECTED_IFACE}.disabled='1'
                    uci commit wireless

                    # Re-stage all pending SSID/key changes without committing
                    [ -n "$PENDING_SSID_WPA" ] && uci set wireless.wlan0wpa.ssid="$PENDING_SSID_WPA"
                    [ -n "$PENDING_KEY_WPA" ] && uci set wireless.wlan0wpa.key="$PENDING_KEY_WPA"
                    [ -n "$PENDING_SSID_OPEN" ] && uci set wireless.wlan0open.ssid="$PENDING_SSID_OPEN"
                    [ -n "$PENDING_KEY_OPEN" ] && uci set wireless.wlan0open.key="$PENDING_KEY_OPEN"
                    [ -n "$PENDING_SSID_MGMT" ] && uci set wireless.wlan0mgmt.ssid="$PENDING_SSID_MGMT"
                    [ -n "$PENDING_KEY_MGMT" ] && uci set wireless.wlan0mgmt.key="$PENDING_KEY_MGMT"
                fi

                # Save any pending SSID/key changes before committing
                PENDING_SSID_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.ssid=" | cut -d= -f2- | tr -d "'")
                PENDING_KEY_WPA=$(uci changes wireless | grep "^wireless\.wlan0wpa\.key=" | cut -d= -f2- | tr -d "'")
                PENDING_SSID_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.ssid=" | cut -d= -f2- | tr -d "'")
                PENDING_KEY_OPEN=$(uci changes wireless | grep "^wireless\.wlan0open\.key=" | cut -d= -f2- | tr -d "'")
                PENDING_SSID_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.ssid=" | cut -d= -f2- | tr -d "'")
                PENDING_KEY_MGMT=$(uci changes wireless | grep "^wireless\.wlan0mgmt\.key=" | cut -d= -f2- | tr -d "'")

                # Revert all pending SSID/key changes from the buffer
                [ -n "$PENDING_SSID_WPA" ] && uci revert wireless.wlan0wpa.ssid
                [ -n "$PENDING_KEY_WPA" ] && uci revert wireless.wlan0wpa.key
                [ -n "$PENDING_SSID_OPEN" ] && uci revert wireless.wlan0open.ssid
                [ -n "$PENDING_KEY_OPEN" ] && uci revert wireless.wlan0open.key
                [ -n "$PENDING_SSID_MGMT" ] && uci revert wireless.wlan0mgmt.ssid
                [ -n "$PENDING_KEY_MGMT" ] && uci revert wireless.wlan0mgmt.key

                LOG "Enabling ${EVIL_IFACE_NAME}..."
                uci set wireless.${EVIL_IFACE}.disabled='0'
                uci commit wireless

                # Re-stage all pending SSID/key changes without committing
                [ -n "$PENDING_SSID_WPA" ] && uci set wireless.wlan0wpa.ssid="$PENDING_SSID_WPA"
                [ -n "$PENDING_KEY_WPA" ] && uci set wireless.wlan0wpa.key="$PENDING_KEY_WPA"
                [ -n "$PENDING_SSID_OPEN" ] && uci set wireless.wlan0open.ssid="$PENDING_SSID_OPEN"
                [ -n "$PENDING_KEY_OPEN" ] && uci set wireless.wlan0open.key="$PENDING_KEY_OPEN"
                [ -n "$PENDING_SSID_MGMT" ] && uci set wireless.wlan0mgmt.ssid="$PENDING_SSID_MGMT"
                [ -n "$PENDING_KEY_MGMT" ] && uci set wireless.wlan0mgmt.key="$PENDING_KEY_MGMT"

                wifi reload
                sleep 35

                # Reload wifi if any values were restaged so interfaces reflect pending changes
                if [ -n "$PENDING_SSID_WPA" ] || [ -n "$PENDING_KEY_WPA" ] || \
                   [ -n "$PENDING_SSID_OPEN" ] || [ -n "$PENDING_KEY_OPEN" ] || \
                   [ -n "$PENDING_SSID_MGMT" ] || [ -n "$PENDING_KEY_MGMT" ]; then
                    wifi reload
                fi

                LOG "${EVIL_IFACE_NAME} enabled"
                LOG ""
                continue
            fi
        fi
    fi

    break

done
