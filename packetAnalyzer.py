from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import pap

captured_packets = []
packet_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

capture_thread = None
capturing = False

# IMPORTANT: Set this to your working interface
INTERFACE = "Wi-Fi"   # or "Wi-Fi" or "Npcap Loopback Adapter"


def packet_handler(pkt):
    try:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        else:
            src = "N/A"
            dst = "N/A"

        if TCP in pkt:
            proto = "TCP"
            packet_stats["TCP"] += 1
        elif UDP in pkt:
            proto = "UDP"
            packet_stats["UDP"] += 1
        elif ICMP in pkt:
            proto = "ICMP"
            packet_stats["ICMP"] += 1
        else:
            proto = "Other"
            packet_stats["Other"] += 1

        # Forward DNS packets to pap
        from scapy.layers.dns import DNS
        if pkt.haslayer(DNS):
            pap.process_packet(pkt)

        summary = pkt.summary()
        details = pkt.show(dump=True)

        captured_packets.append({
            "src": src,
            "dst": dst,
            "proto": proto,
            "summary": summary,
            "details": details
        })

        if len(captured_packets) > 100:
            captured_packets.pop(0)

    except Exception as e:
        print(f"[ERROR] packet_handler exception: {e}")

   


def _sniff_loop():
    global capturing
    try:
        sniff(
            prn=packet_handler,
            store=False,
            iface=INTERFACE,
            stop_filter=lambda x: not capturing
        )
    except Exception as e:
        print(f"[ERROR] sniff failed: {e}")


def start_capture():
    global capture_thread, capturing
    if capturing:
        return
    capturing = True
    capture_thread = threading.Thread(target=_sniff_loop, daemon=True)
    capture_thread.start()
    print("[DEBUG] Capture started")


def stop_capture():
    global capturing
    capturing = False
    print("[DEBUG] Capture stopped")


def get_packets():
    return captured_packets


# In packetAnalyzer.py, update the get_stats function:
def get_stats():
    # Return a copy of the stats with the capture state included
    stats = packet_stats.copy()
    stats['capturing'] = capturing 
    return stats
