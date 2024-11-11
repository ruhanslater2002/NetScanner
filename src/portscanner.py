from termcolor import colored
from packethandler import PacketHandler
from portservices import PortServices
from consolelogger import ConsoleLogger


class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.logger = ConsoleLogger("PORT SCANNER")

    def scan_ports(self, target_port: int, port_range: int) -> None:
        self.logger.info(f"Scanning ports on {colored(self.target_ip, 'green')}\n")
        open_ports_found: int = 0
        if port_range < target_port:
            port_range = target_port + port_range + 1
        for port in range(target_port, port_range):
            packet_handler: PacketHandler = PacketHandler(self.target_ip)
            response: bool = packet_handler.send_tcp_packet(port)

            # Checks if response is a SYN-ACK, meaning the port is open
            if response:
                port_services: str = PortServices(port).get_port_service()
                self.logger.info(f'PORT {colored(port, "green")} ({port_services}) is {colored("OPEN", "green")}')
                open_ports_found += 1
        print('')
        self.logger.info(f'Found {colored(open_ports_found, "green")} ports open.\n')
