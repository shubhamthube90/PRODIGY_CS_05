import scapy.all as scapy

def sniff_packets(interface):
    """Sniffs packets on the specified interface and prints relevant information."""

    def packet_handler(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            # Get the protocol name based on the protocol number
            protocol_name = packet[IP].proto
            try:
                protocol_name = scapy.getprotobynumber(protocol_name)
            except Exception:
                protocol_name = "Unknown"

            # Extract payload data if desired
            payload = str(packet[IP].payload)

            print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol_name}, Payload: {payload[:30]}...")

    scapy.sniff(iface=interface, store=False, prn=packet_handler)

if name == "main":
    interface = "your_interface_name"  # Replace with your network interface
    sniff_packets(interface)