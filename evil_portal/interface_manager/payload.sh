#!/bin/bash
# Name: Interface Manager
# Description: Displays interface status and manages interface activation
# Author: PentestPlaybook
# Version: 1.0
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

    LOG "Disabling ${SELECTED_NAME}..."
    uci set wireless.${SELECTED_IFACE}.disabled='1'
    uci commit wireless

    LOG "Restarting Networking..."
    /etc/init.d/network restart
    sleep 10
    wifi
    sleep 35

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
        if uci show wireless.${IFACE}.network 2>/dev/null | grep -q "evil"; then
            EVIL_PORTAL="Yes"
        else
            EVIL_PORTAL="No"
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

                    LOG "Disabling ${SELECTED_NAME}..."
                    uci set wireless.${SELECTED_IFACE}.disabled='1'
                    uci commit wireless
                fi

                LOG "Enabling ${EVIL_IFACE_NAME}..."
                uci set wireless.${EVIL_IFACE}.disabled='0'
                uci commit wireless
                wifi reload
                sleep 35

                LOG "${EVIL_IFACE_NAME} enabled"
                LOG ""
                continue
            fi
        fi
    fi

    break

done
