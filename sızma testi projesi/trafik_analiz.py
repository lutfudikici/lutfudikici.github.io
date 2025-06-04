import pyshark

# Tshark yolu elle belirtilirse buraya yaz (gerekirse)
# pyshark.tshark.tshark.get_process_path = lambda: '/usr/local/bin/tshark'

INTERFACE = 'en0'  # Wi-Fi genellikle en0 olur, ifconfig ile kontrol et
packet_limit = 200  # Kaç paketi analiz edeceğini belirt

print(f"{INTERFACE} arayüzü üzerinden ağ trafiği izleniyor... (limit: {packet_limit})")

capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="ip")

unique_connections = set()

try:
    for packet in capture.sniff_continuously(packet_count=packet_limit):
        try:
            ip_layer = packet.ip
            src = ip_layer.src
            dst = ip_layer.dst
            protocol = packet.transport_layer
            sport = packet[protocol].srcport
            dport = packet[protocol].dstport

            conn = (dst, dport)
            if conn not in unique_connections:
                unique_connections.add(conn)
                print(f"Bağlantı: {dst}:{dport} ({protocol})")
        except AttributeError:
            continue
except KeyboardInterrupt:
    print("\nDurduruldu.")