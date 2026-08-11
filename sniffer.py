from scapy.all import sniff,IP, TCP, UDP, IPv6,  ICMP, Raw, wrpcap
from datetime import datetime
import time

PACKET_COUNT =50
OUTPUT_FILE = "captured_packets.pcap"

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return "IP"
    elif packet.haslayer(IPv6):
        return "IPv6"
    else:
        return "Other"

def analyze_packet(packet):
    print("\n" +"-"*50)
    print(f"Packet #{analyze_packet.counter}")


    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst
        print(f"Source IP: {source}")
        print(f"Destination IP: {destination}")


    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        print(f"Source IP: {source}")
        print(f"Destination IP: {destination}")

    else:
        print("source and destination IP addresses not available for this packet")


    protocol = get_protocol(packet)
    print(f"Protocol: {protocol}")

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        print(f"Source Port: {source_port}")
        print(f"Destination Port: {destination_port}")

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        print(f"Source Port: {source_port}")
        print(f"Destination Port: {destination_port}")

    else:
        print("source and destination ports not available for this packet")

 
    if packet.haslayer(Raw):
        payloads =bytes(packet[Raw].load)
        print(f"payload length:{len(payloads)} bytes")
        hex_preview = payloads[:16].hex()
        print(f"Payload (first 16 bytes in hex): {hex_preview}")

    else:
        print("payload length:0 bytes")
        print("Payload: No application payload ")

    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"captured at: {timestamp}")
    print("-" * 50)
    analyze_packet.counter += 1
analyze_packet.counter = 1
time.sleep(1)

def main():
    print("=" * 50)
    print(" NETWORK SNIFFER")
    print("=" * 50)
    print("\n[+] scapy network sniffer started")
    print(f"[+] capturing {PACKET_COUNT} packets")
    print("[+] generate some network traffic")
    print("[+] press Ctrl+C to stop capturing packets\n")

    try:
        packets =sniff(
            count=PACKET_COUNT,
            prn=analyze_packet,
            store=True
        )

        wrpcap(OUTPUT_FILE, packets)
        print("\n" + "=" * 50)
        print("capture complete")
        print("=" * 50)
        print(f"\n[+] packets captured :{len(packets)}")
        print(f"[+] packets saved to : {OUTPUT_FILE}")
        print("\n[+] you can analyze the .pcap file using wireshark")
        print("[+]sniffing completed successfully")

    except PermissionError:
        print("\n[!] permission denied")
        print("[!] run as administrator")

    except KeyboardInterrupt:
        print("\n[!] capture stopped by user")

    except Exception as error:
        print("\n[!] an error occured")
        print(error)

if __name__ == "__main__":
    main()

    




