from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP

captured_packets = []


def classify_dns(domain, rcode):
    """Return a risk label based on domain + DNS response code."""
    if not domain or domain == "N/A":
        return "None"

    domain = domain.lower()

    bad_tlds = (".xyz", ".top", ".click", ".zip", ".lol", ".quest", ".ru")

    if any(domain.endswith(tld) for tld in bad_tlds):
        return "Suspicious"

    if rcode in ("2", "3"):  # SERVFAIL, NXDOMAIN
        return "Warning"

    import re
    stripped = re.sub(r"[^a-z]", "", domain)
    if len(stripped) > 12 and len(stripped) > 0:
        alpha_ratio = sum(c.isalpha() for c in stripped) / len(stripped)
        if alpha_ratio > 0.9:
            return "Suspicious"

    return "None"


def process_packet(pkt):
    try:
        if not pkt.haslayer("DNS"): # Use string to be safer
            return None

        dns_layer = pkt["DNS"]

        # Safely extract IP info
        src = pkt["IP"].src if pkt.haslayer("IP") else "N/A"
        dst = pkt["IP"].dst if pkt.haslayer("IP") else "N/A"
        proto = "TCP" if pkt.haslayer("TCP") else ("UDP" if pkt.haslayer("UDP") else "Other")

        dns_query = "N/A"
        dns_type = "N/A"
        dns_ip = "N/A"
        dns_rcode = str(dns_layer.rcode)

        # Safely process Question section
        if dns_layer.qr == 0 and dns_layer.qd:
            # Check if qname exists before decoding
            if hasattr(dns_layer.qd, 'qname'):
                dns_query = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
            
            # Safer way to get type without calling get_field()
            dns_type = str(dns_layer.qd.qtype)

        # Safely process Answer section
        if dns_layer.qr == 1 and dns_layer.an:
            # Handle cases where multiple answers might be in a list
            answer = dns_layer.an[0] if isinstance(dns_layer.an, list) else dns_layer.an
            
            if hasattr(answer, 'rrname'):
                dns_query = answer.rrname.decode(errors="ignore").rstrip(".")
            
            if hasattr(answer, "rdata"):
                dns_ip = str(answer.rdata)
            
            dns_type = str(answer.type)

        record = {
            "src": src,
            "dst": dst,
            "proto": proto,
            "dns_query": dns_query,
            "dns_type": dns_type,
            "dns_ip": dns_ip,
            "dns_rcode": dns_rcode,
            "summary": pkt.summary(),
            "risk": classify_dns(dns_query, dns_rcode)
        }

        captured_packets.append(record)
        if len(captured_packets) > 100:
            captured_packets.pop(0)
            
        return record

    except Exception as e:
        # Silently ignore malformed packets or print for debugging
        # print(f"[DEBUG] Skipping packet: {e}") 
        return None


def process_pcap(filepath):
    try:
        packets = rdpcap(filepath)
        for pkt in packets:
            process_packet(pkt)
    except Exception as e:
        print(f"[ERROR] process_pcap exception: {e}")
