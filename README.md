# NETWORK_TRAFFIC_CAPTURE_ANALYSER

## Overview

This project is a network traffic capture tool built using Python and the Scapy library. It captures packets from the network, filters and analyzes them, and then stores detailed packet information in multiple formats, including:

- **PCAP**: A packet capture file format.
- **CSV**: A CSV file containing detailed information about the captured packets.
- **PNG**: A bar graph showing the distribution of network protocols captured during the session.

The tool helps users analyze network traffic and is ideal for security monitoring, performance analysis, and network troubleshooting.

## Features

- **Packet Capture**: Captures packets from the network and filters for relevant protocols such as TCP, UDP, ICMP, DNS, ARP, and others.
- **CSV Export**: Exports detailed packet information such as timestamp, protocol, source and destination IPs, ports, length, and payload.
- **PCAP Export**: Saves captured packets in a PCAP file format for later analysis in Wireshark or similar tools.
- **Protocol Distribution Visualization**: Generates a bar graph visualizing the distribution of different network protocols and saves it as a PNG file.

## Requirements

- **Python 3.x**
- **Scapy**: A powerful Python-based packet manipulation tool used for network analysis.
  
  Install Scapy using pip:
  ```bash
  pip install scapy
