def load_pcap(filepath):
    from scapy.all import rdpcap
    return rdpcap(filepath)
