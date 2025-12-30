from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

LOG_FILE = "packet_logs.txt"
ALLOWED_PROTOCOLS = ["TCP", "UDP", "ICMP"]


def log_packet(data):
    """Save packet details to log file"""
    with open(LOG_FILE, "a") as file:
        file.write(
            f"{data['time']} | "
            f"{data['src']} -> {data['dst']} | "
            f"{data['protocol']} | "
            f"Sport: {data.get('sport', '-')}, "
            f"Dport: {data.get('dport', '-')}\n"
        )


def analyze_packet(packet):
    """Analyze captured packets"""
    if packet.haslayer(IP):
        data = {
            "time": datetime.now(),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "protocol": "OTHER"
        }

        if packet.haslayer(TCP):
            data["protocol"] = "TCP"
            data["sport"] = packet[TCP].sport
            data["dport"] = packet[TCP].dport

        elif packet.haslayer(UDP):
            data["protocol"] = "UDP"
            data["sport"] = packet[UDP].sport
            data["dport"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            data["protocol"] = "ICMP"

        # Filter allowed protocols
        if data["protocol"] in ALLOWED_PROTOCOLS:
            print(
                f"[{data['protocol']}] "
                f"{data['src']} -> {data['dst']} "
                f"Sport:{data.get('sport', '-')} "
                f"Dport:{data.get('dport', '-')}"
            )
            log_packet(data)


def main():
    print("🔍 Network Packet Analyzer Started")
    print("📡 Capturing live network traffic...")
    print("🛑 Press CTRL+C to stop\n")

    sniff(prn=analyze_packet, store=False)


if __name__ == "__main__":
    main()
