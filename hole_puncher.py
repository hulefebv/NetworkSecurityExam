from scapy.all import sniff, send, IP, UDP, Raw
import time

CLIENT_IP = "10.0.0.2"
INTERFACE = "server-eth0"

def get_ports(pkt):
    if pkt.haslayer(UDP) and pkt[IP].src == CLIENT_IP:
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None

def main():
    print(f"[*] Waiting for UDP packet from {CLIENT_IP} on {INTERFACE}...")
    pkt = sniff(
        iface=INTERFACE,
        filter=f"udp and src host {CLIENT_IP}",
        count=1,
        timeout=30
    )
    if not pkt:
        print("[!] No packet received from client.")
        return

    client_port, server_port = get_ports(pkt[0])
    if not client_port or not server_port:
        print("[!] Could not determine ports.")
        return

    print("[*] Sleeping for 3 seconds before sending unsolicited packets...")
    time.sleep(3)

    print(f"[*] Sending 10 unsolicited UDP packets to {CLIENT_IP}:{client_port} "
          f"from source port {server_port}")

    for i in range(10):
        udp_pkt = IP(dst=CLIENT_IP) / UDP(dport=client_port, sport=server_port) / Raw(
            load=f"Unsolicited packet {i+1}"
        )
        send(udp_pkt, iface=INTERFACE, verbose=False)
    print("[*] Done.")

if __name__ == "__main__":
    main()
