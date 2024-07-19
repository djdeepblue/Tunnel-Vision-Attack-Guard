# Tunnel-Vision-Attack-Guard
A script to detect suspicious DHCP options that might indicate a Tunnel Vision Attack

## Description

This script captures DHCP packets on a specified network interface and checks for suspicious DHCP options that could be indicative of a Tunnel Vision Attack.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)

## Usage

1. **Clone the repository:**
    ```sh
    git clone https://github.com/yourusername/TunnelVisionAttack-ChooseWifiAdapter.git
    cd TunnelVisionAttack-ChooseWifiAdapter
    ```

2. **Run the script with sudo privileges:**
    ```sh
    sudo python3 TunnelVisionAttack-ChooseWifiAdapter.py
    ```

3. **Follow the prompts** to choose a network interface and start capturing DHCP packets.

## Script Details

- **get_network_interfaces:** Lists available network interfaces.
- **choose_network_interface:** Allows the user to select a network interface.
- **detect_suspicious_dhcp:** Detects and alerts for suspicious DHCP options.
- **capture_dhcp_packets:** Captures DHCP packets on the chosen interface.

## License

This project is licensed under the  GNU GPLv3 License.
