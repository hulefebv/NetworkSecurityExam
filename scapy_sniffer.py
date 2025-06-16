from scapy.all import sniff, Raw

INTERFACE = "client-eth0"  # Change if your interface is different

def handle_packet(pkt):
    print(pkt.summary())
    #print(pkt.show()) # full packet details
    if pkt.haslayer(Raw):
        print("Payload:", pkt[Raw].load)
    print("-" * 40)

def main():
    print(f"[*] Sniffing all packets on interface {INTERFACE}...")
    sniff(
        iface=INTERFACE,
        prn=handle_packet,
        store=0
    )

if __name__ == "__main__":
    main()
