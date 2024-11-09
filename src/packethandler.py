import scapy.all as scapy
from scapy.plist import SndRcvList


class PacketHandler:
    def __init__(self, target_ip: str):
        self.ipaddress = target_ip

    def send_tcp_packet(self, port: int) -> bool:
        # Create a TCP SYN packet
        tcp_packet: scapy.Packet = scapy.IP(dst=self.ipaddress) / scapy.TCP(dport=port, flags="S")

        # Send the packet and wait for a single response
        response: scapy.Packet = scapy.sr1(tcp_packet, timeout=3, verbose=0)

        # Check if a response was received
        if response:
            # Check if the response has a TCP layer with SYN-ACK flags
            tcp_layer = response.getlayer(scapy.TCP)
            if tcp_layer and tcp_layer.flags == "SA":
                return True
        return False

    def send_icmp_packet(self) -> bool:
        # Creates ICMP Packet
        icmp_packet: scapy.packet = scapy.IP(dst=self.ipaddress) / scapy.ICMP()
        # Sends ICMP packet
        response: scapy.packet = scapy.sr1(icmp_packet, timeout=3, verbose=0)
        if response:
            return True
        else:
            return False

    def send_arp_packet(self, target_mac: str) -> SndRcvList:
        arp_packet: scapy.packet = scapy.Ether(dst=target_mac) / scapy.ARP(pdst=self.ipaddress)
        responses: scapy.packet = scapy.srp(arp_packet, timeout=4, verbose=0)[0]
        return responses
