#!/bin/bash
# Name: Configure Evil Network
# Description: Create isolated evil network on wlan0wpa with separate IP range
# Author: alobe
# Version: 1.0
# Category: Network

ALERT "Configuring Evil Network..."

# Add evil network configuration
ALERT "Creating br-evil bridge and interface..."
echo -e "\nconfig device\n        option name 'br-evil'\n        option type 'bridge'\n\nconfig interface 'evil'\n        option device 'br-evil'\n        option proto 'static'\n        option ipaddr '10.0.0.1'\n        option netmask '255.255.255.0'" >> /etc/config/network

# Add DHCP configuration for evil network
ALERT "Configuring DHCP for evil network..."
echo -e "\nconfig dhcp 'evil'\n        option interface 'evil'\n        option start '100'\n        option limit '150'\n        option leasetime '1h'" >> /etc/config/dhcp

# Assign wlan0wpa to evil network
ALERT "Assigning wlan0wpa to evil network..."
sed -i "/config wifi-iface 'wlan0wpa'/,/option ifname/ s/\(option ifname 'wlan0wpa'\)/\1\n        option network 'evil'/" /etc/config/wireless

# Remove wlan0wpa from br-lan bridge
ALERT "Removing wlan0wpa from br-lan..."
sed -i "/list ports 'wlan0wpa'/d" /etc/config/network

# Add evil network to LAN firewall zone for internet access
ALERT "Adding evil network to firewall..."
uci add_list firewall.@zone[0].network='evil'
uci commit firewall
