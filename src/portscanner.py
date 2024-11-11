from termcolor import colored
from packethandler import PacketHandler
from portservices import PortServices
from consolelogger import ConsoleLogger


class PortScanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.logger = ConsoleLogger("PORT SCANNER")

    def scan_ports(self, target_port: int, port_range: int) -> None:
        # Start scan message
        self.logger.warning(f"Scanning ports on {colored(self.target_ip, 'green')} ...\n")

        # Initialize list to collect open ports
        open_ports_found = []

        # Define port range to scan
        if port_range < target_port:
            port_range = target_port + port_range + 1

        # Iterate through ports to scan
        for port in range(target_port, port_range):
            packet_handler = PacketHandler(self.target_ip)
            response = packet_handler.send_tcp_packet(port)

            # Check if the port is open
            if response:
                open_ports_found.append({'port': port, 'status': 'OPEN'})

        # Log open ports with their service names
        for open_port in open_ports_found:
            port_services = PortServices(open_port['port']).get_port_service()
            self.logger.info(
                f'PORT {colored(open_port["port"], "green")} ({port_services}) is {colored("OPEN", "green")}'
            )
        print('')
        # Final summary log
        if len(open_ports_found) > 0:
            self.logger.info(f'Found {colored(len(open_ports_found), "green")} ports open.\n')
        else:
            self.logger.warning(f'Found {colored(len(open_ports_found), "red")} ports open.\n')
        self.logger.info("Scanning completed.")
