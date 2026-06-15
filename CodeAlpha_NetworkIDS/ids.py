from scapy.all import sniff
packet_count = {}
def detect(packet):
    try:
        src = packet["IP"].src

        if src not in packet_count:
            packet_count[src] = 1
        else:
            packet_count[src] += 1
        print(f"IP: {src} | Count: {packet_count[src]}")

        if packet_count[src] > 20:
            print(f"[ALERT] Suspicious Activity Detected From {src}")

    except:
        pass

print("IDS Started... Monitoring Traffic")
sniff(prn=detect, count=50)
