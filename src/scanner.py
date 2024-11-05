from packethandler import PacketHandler
from termcolor import colored
from portservices import PortServices


class Scanner:
    def __init__(self, targetip: str, targetport: int):
        self.targetip = targetip
        self.targetport = targetport

    def scan_ports(self, port_range: int):
        if port_range < self.targetport:
            port_range = self.targetport + port_range + 1
        print('')
        print(' | PORT    | STATE\t| SERVICE')
        print(' ───────────────────────────────────')
        for port in range(self.targetport, port_range):
            packet_handler: PacketHandler = PacketHandler(self.targetip, port)
            response: bool = packet_handler.send_tcp_packet()

            # Checks if response is a SYN-ACK, meaning the port is open
            if response:
                port_services: str = PortServices(port).get_port_service()
                print(f' | {port:<7} | {colored("OPEN", "green")} \t| {port_services}')
