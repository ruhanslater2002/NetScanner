import ipaddress
from packethandler import PacketHandler
from termcolor import colored
from portservices import PortServices


class Scanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.minus = colored("-", "red")
        self.plus = colored("+", "green")

    def scan_ports(self, target_port: int, port_range: int) -> None:
        if port_range < target_port:
            port_range = target_port + port_range + 1
        print('')
        print(' | PORT    | STATE\t| SERVICE')
        print(' ───────────────────────────────────')
        for port in range(target_port, port_range):
            packet_handler = PacketHandler(self.target_ip)
            response = packet_handler.send_tcp_packet(port)

            # Checks if response is a SYN-ACK, meaning the port is open
            if response:
                port_services = PortServices(port).get_port_service()
                print(f' | {port:<7} | {colored("OPEN", "green")} \t| {port_services}')

    def scan_network(self) -> None:
        print(f"[*] Scanning network {self.target_ip}")
        responses = []

        # Generate all IPs in the subnet
        subnet = ipaddress.ip_network(self.target_ip, strict=False)
        for ip in subnet.hosts():
            packet_handler = PacketHandler(str(ip))
            response = packet_handler.send_icmp_packet()
            if response:
                responses.append(str(ip))  # Append the actual responding IP

        # Display results
        print(f'[{self.plus}] Found {colored(len(responses), "green")} hosts.')
        print('')
        for response in responses:
            print(f'[{self.plus}] Response from {colored(response, "green")}')
