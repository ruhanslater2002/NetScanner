import scapy.all as scapy


class PacketHandler:
    def __init__(self, ipaddress: str, port: int):
        self.ipaddress = ipaddress
        self.port = port

    def send_tcp_packet(self) -> bool:
        # Create a TCP SYN packet
        tcp_packet: scapy.Packet = scapy.IP(dst=self.ipaddress) / scapy.TCP(dport=self.port, flags="S")

        # Send the packet and wait for a single response
        response: scapy.Packet = scapy.sr1(tcp_packet, timeout=1, verbose=0)

        # Check if a response was received
        if response:
            # Check if the response has a TCP layer with SYN-ACK flags
            tcp_layer = response.getlayer(scapy.TCP)
            if tcp_layer and tcp_layer.flags == "SA":
                return True
        return False
