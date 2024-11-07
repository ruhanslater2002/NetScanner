from packethandler import PacketHandler
from termcolor import colored
from portservices import PortServices


class Scanner:
    def __init__(self, targetip: str):
        self.targetip = targetip
        self.minus = colored("-", "red")
        self.plus = colored("+", "green")

    def scan_ports(self, target_port: int, port_range: int) -> None:
        if port_range < target_port:
            port_range = target_port + port_range + 1
        print('')
        print(' | PORT    | STATE\t| SERVICE')
        print(' ───────────────────────────────────')
        for port in range(target_port, port_range):
            packet_handler: PacketHandler = PacketHandler(self.targetip)
            response: bool = packet_handler.send_tcp_packet(port)

            # Checks if response is a SYN-ACK, meaning the port is open
            if response:
                port_services: str = PortServices(port).get_port_service()
                print(f' | {port:<7} | {colored("OPEN", "green")} \t| {port_services}')

    def scan_network(self) -> None:
        packet_handler: PacketHandler = PacketHandler(self.targetip)
        response: bool = packet_handler.send_icmp_packet()
        if response:
            print(f'[{self.plus}] Response from {colored(self.targetip, "green")}')
        else:
            print(f'[{self.minus}] No response from {colored(self.targetip, "green")}')
