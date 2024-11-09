from termcolor import colored
from packethandler import PacketHandler
from portservices import PortServices


class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def scan_ports(self, target_port: int, port_range: int) -> None:
        print(f"[*] Scanning ports on {colored(self.target_ip, 'green')}\n")
        if port_range < target_port:
            port_range = target_port + port_range + 1
        print('')
        print(' | PORT    | STATE\t| SERVICE')
        print(' ───────────────────────────────────')
        for port in range(target_port, port_range):
            packet_handler: PacketHandler = PacketHandler(self.target_ip)
            response: bool = packet_handler.send_tcp_packet(port)

            # Checks if response is a SYN-ACK, meaning the port is open
            if response:
                port_services: str = PortServices(port).get_port_service()
                print(f' | {port:<7} | {colored("OPEN", "green")} \t| {port_services}')
