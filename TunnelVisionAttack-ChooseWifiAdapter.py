#!/usr/bin/env python3

from scapy.all import sniff, DHCP
import subprocess
import os

def get_network_interfaces():
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, check=True)
        interfaces = [line.split(":")[1].strip() for line in result.stdout.split("\n") if ": " in line]
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"Failed to list network interfaces: {e}")
        return []

def choose_network_interface(interfaces):
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")
    while True:
        choice = input("Choose the network interface to capture DHCP packets on (enter number): ")
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
        print("Invalid choice. Please enter a valid number.")

def detect_suspicious_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options:
        for option in pkt[DHCP].options:
            if option[0] == 121:  # DHCP Option 121 (Classless Static Route)
                print("\033[91m\033[1mALERT: Suspicious DHCP Option 121 (Tunnel Vision Attack) found!\033[0m")
                print(f"Details: {option}")
            if option[0] == 120:  # DHCP Option 120 (SIP Servers)
                print(f"Suspicious DHCP Option 120 found: {option}")

def capture_dhcp_packets(interface):
    print(f"Starting DHCP capture on {interface}")
    sniff(filter="port 67 or port 68", prn=detect_suspicious_dhcp, iface=interface, store=0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires sudo privileges to run. Please run it with sudo.")
        exit(1)
    
    interfaces = get_network_interfaces()
    if interfaces:
        interface = choose_network_interface(interfaces)
        try:
            capture_dhcp_packets(interface)
        except PermissionError:
            print("Permission denied: You need to run this script as root.")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("No network interfaces could be determined. Exiting.")

