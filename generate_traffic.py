from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

packets = []

# Fictional client and DNS server
client = "192.0.2.10"
server = "192.0.2.53"

# Ordinary DNS requests
normal_domains = [
    "example.com",
    "example.org",
    "example.net",
]

for domain in normal_domains:
    packet = (
        IP(src=client, dst=server)
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
    packets.append(packet)

# A suspicious-looking DNS request: our challenge clue
suspicious_domain = "backup-check.example.com"

packet = (
    IP(src=client, dst=server)
    / UDP(sport=53001, dport=53)
    / DNS(rd=1, qd=DNSQR(qname=suspicious_domain))
)
packets.append(packet)

# Save the packets to a PCAP file
wrpcap("silent_packet.pcap", packets)

print(f"Created silent_packet.pcap with {len(packets)} DNS packets.")
