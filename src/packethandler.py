import scapy.all as scapy
from scapy.plist import SndRcvList


class PacketHandler:
    def __init__(self, target_ip: str):
        self.ipaddress = target_ip

    def send_tcp_packet(self, port: int, request_flag: str) -> bool:
        """
        Send a TCP packet with the given flag to the specified port.
        Returns True if the port is open, False if it is closed or filtered.
        """
        # Create a TCP packet with the specified flag
        tcp_packet: scapy.Packet = scapy.IP(dst=self.ipaddress) / scapy.TCP(dport=port, flags=request_flag)

        # Send the packet and wait for a single response
        response: scapy.Packet = scapy.sr1(tcp_packet, timeout=3, verbose=0)

        # Check if a response was received
        if response:
            # Get the TCP layer from the response
            tcp_layer = response.getlayer(scapy.TCP)

            # Handle SYN flag (SYN scan)
            if request_flag == "S":
                if tcp_layer and tcp_layer.flags == "SA":
                    return True  # Port is open (SYN-ACK received)
                elif tcp_layer and tcp_layer.flags == "RA":
                    return False  # Port is closed (RST received)

            # Handle ACK flag (ACK scan)
            elif request_flag == "A":
                if tcp_layer and tcp_layer.flags == "R":
                    return False  # Port is closed or unfiltered (RST received)
                else:
                    return True  # Port is unfiltered (no RST response)

            # Handle FIN flag (FIN scan)
            elif request_flag == "F":
                if tcp_layer and tcp_layer.flags == "R":
                    return False  # Port is closed (RST received)
                elif not tcp_layer:
                    return True  # Port is open (no response, FIN works on open ports)

            # Handle RST flag (RST scan)
            elif request_flag == "R":
                if tcp_layer and tcp_layer.flags == "R":
                    return False  # Port is closed (RST received)
                else:
                    return True  # Port is open (no response or unexpected flags)

            # Handle URG flag (Urgent scan)
            elif request_flag == "U":
                if tcp_layer and tcp_layer.flags == "U":
                    return True  # Port is open (URG received)
                else:
                    return False  # Port is closed or filtered

            # Handle PSH flag (Push scan)
            elif request_flag == "P":
                if tcp_layer and tcp_layer.flags == "P":
                    return True  # Port is open (PSH received)
                else:
                    return False  # Port is closed or filtered

            # Handle ECE flag (ECN Echo scan)
            elif request_flag == "E":
                if tcp_layer and tcp_layer.flags == "E":
                    return True  # Port is open (ECE received)
                else:
                    return False  # Port is closed or filtered

            # Handle Xmas scan (FPU flags)
            elif request_flag == "FPU":
                if tcp_layer and tcp_layer.flags == "FPU":
                    return True  # Port is open (FPU flags received)
                elif not tcp_layer:
                    return True  # Port is open (no response is typical for Xmas scan)
                else:
                    return False  # Port is closed or filtered

            # Handle Null scan (no flags)
            elif request_flag == "":
                if tcp_layer and tcp_layer.flags == "":
                    return True  # Port is open (no flags received)
                else:
                    return False  # Port is closed or filtered

        # If no response or response not matching the expected flags, return False (port likely filtered)
        return False

    def send_icmp_packet(self) -> bool:
        """
        Sends an ICMP packet to check if the target IP is reachable.
        Returns True if the host is reachable, False otherwise.
        """
        icmp_packet: scapy.packet = scapy.IP(dst=self.ipaddress) / scapy.ICMP()
        response: scapy.packet = scapy.sr1(icmp_packet, timeout=3, verbose=0)
        if response:
            return True  # Responded, so host is reachable
        else:
            return False  # No response, host unreachable

    def send_arp_packet(self, target_mac: str) -> SndRcvList:
        """
        Sends an ARP packet to the target MAC address.
        Returns the list of responses.
        """
        arp_packet: scapy.packet = scapy.Ether(dst=target_mac) / scapy.ARP(pdst=self.ipaddress)
        responses: scapy.packet = scapy.srp(arp_packet, timeout=4, verbose=0)[0]
        return responses
