import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, wrpcap, DNS
from collections import Counter
import csv
from datetime import datetime

# Dictionary to map protocol numbers to human-readable names
protocol_dict = {
    1: "ICMP",          # Internet Control Message Protocol
    6: "TCP",           # Transmission Control Protocol
    17: "UDP",          # User Datagram Protocol
    2048: "IPv4",       # Internet Protocol version 4
    2054: "ARP",        # Address Resolution Protocol
    35020: "IPv6",      # Internet Protocol version 6
    53: "DNS",          # Domain Name System (DNS)
    80: "HTTP",         # Hypertext Transfer Protocol (HTTP)
    443: "HTTPS",       # Hypertext Transfer Protocol Secure (HTTPS)
    110: "POP3",        # Post Office Protocol 3 (POP3)
    143: "IMAP",        # Internet Message Access Protocol (IMAP)
    21: "FTP",          # File Transfer Protocol (FTP)
    22: "SSH",          # Secure Shell (SSH)
}

# Initialize counter for packet types
protocol_counter = Counter()
packets = []

def packet_callback(packet):
    """
    Callback function to process each captured packet and store detailed information.
    """
    # Extract timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(IP):  # Filter only IP packets
        # Get basic information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_proto = packet[IP].proto
        protocol_name = protocol_dict.get(ip_proto, "Other")
        
        # Capture port information for TCP/UDP
        src_port = dst_port = None
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

        # Packet length
        pkt_length = len(packet)

        # Optional: Capture payload data (may be large)
        payload_data = packet.payload if hasattr(packet, 'payload') else None
        payload_data = str(payload_data)[:100]  # Optional: Limit to first 100 chars for readability

        # Print detailed packet information (for debugging)
        print(f"Packet captured: {protocol_name} from {src_ip} to {dst_ip}, Protocol: {protocol_name}, "
              f"Src Port: {src_port}, Dst Port: {dst_port}, Length: {pkt_length}, Payload: {payload_data}")

        # Add packet data to a separate list for CSV export
        packets.append({
            "Timestamp": timestamp,
            "Protocol": protocol_name,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Length": pkt_length,
            "Payload": payload_data
        })

        # Count protocol occurrences
        protocol_counter[protocol_name] += 1

    # Optional: Handle non-IP traffic like ARP
    if packet.haslayer(ARP):
        protocol_counter["ARP"] += 1
        print("Packet captured: ARP")

        # ARP source and destination
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        # ARP packets don't have ports or protocols, so capture only the IPs
        packets.append({
            "Timestamp": timestamp,
            "Protocol": "ARP",
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Source Port": None,
            "Destination Port": None,
            "Length": len(packet),
            "Payload": "N/A"
        })

    # Add raw packet object to packets list for later saving to PCAP
    packets.append(packet)  # Here we store the raw packet object for PCAP

def save_packet_capture(filename="captured_traffic.pcap"):
    """
    Function to save captured packets to a PCAP file.
    """
    if packets:
        # Filter out dictionaries and keep only raw packets for saving
        raw_packets = [pkt for pkt in packets if isinstance(pkt, Ether)]
        wrpcap(filename, raw_packets)
        print(f"Captured packets saved to {filename}")
    else:
        print("No packets to save!")

def export_to_csv(filename='traffic_report.csv'):
    """
    Export the detailed packet information to a CSV file.
    """
    # Define the headers for the CSV file
    fieldnames = ["Timestamp", "Protocol", "Source IP", "Destination IP",
                  "Source Port", "Destination Port", "Length", "Payload"]

    # Write all the packet information to a CSV file
    with open(filename, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for packet_data in packets:
            # Ensure packet data is a dictionary with the correct structure
            if isinstance(packet_data, dict):
                writer.writerow(packet_data)

    print(f"Traffic report saved as {filename}")

def plot_protocol_distribution(filename='protocol_distribution.png'):
    """
    Function to plot a bar graph showing the protocol distribution.
    """
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())
    
    plt.bar(protocols, counts)
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Network Traffic Protocol Distribution')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the plot to a PNG file
    plt.savefig(filename)
    print(f"Protocol distribution plot saved as {filename}")
    plt.close()  # Close the plot to prevent it from displaying in interactive mode

def start_packet_capture():
    """
    Start capturing packets and process them until interrupted (Ctrl+C).
    """
    # Create a unique base filename based on the current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pcap_filename = f"captured_traffic_{timestamp}.pcap"
    csv_filename = f"traffic_report_{timestamp}.csv"
    png_filename = f"protocol_distribution_{timestamp}.png"

    print("Starting packet capture... Press Ctrl+C to stop the capture.")
    try:
        # Capture packets indefinitely until interrupted
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    # Plot the captured data and save to PNG
    plot_protocol_distribution(png_filename)

    # Save the PCAP file with captured packets
    save_packet_capture(pcap_filename)

    # Export the detailed packet information to a CSV file
    export_to_csv(csv_filename)

if __name__ == "__main__":
    # Start the capture process
    start_packet_capture()
