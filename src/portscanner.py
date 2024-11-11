from termcolor import colored
from packethandler import PacketHandler
from portservices import PortServices
from consolelogger import ConsoleLogger


class PortScanner:
    def __init__(self, target_ip: str, tcp_flag: str):
        self.target_ip = target_ip
        self.flag = tcp_flag
        self.logger = ConsoleLogger("PORT-SCANNER")

    def scan_ports(self, target_port: int, port_range: int) -> None:
        # Start scan message
        self.logger.warning(f"Scanning ports ({colored(f"{target_port} " + "-" + f" {port_range}", "green")}) "
                            f"on {colored(self.target_ip, 'green')} using {colored(self.flag, "green")} flag ...\n")

        # Initialize list to collect open or filtered ports
        open_ports: list = []

        # Define port range to scan
        if port_range < target_port:
            port_range = target_port + port_range + 1

        # Iterate through ports to scan
        for port in range(target_port, port_range):
            packet_handler = PacketHandler(self.target_ip)
            response = packet_handler.send_tcp_packet(port, self.flag)

            # Only consider open or filtered ports
            if response:
                if self.flag == "S":  # SYN scan
                    open_ports.append({'port': port, 'status': 'OPEN'})
                elif self.flag == "A":  # ACK scan
                    open_ports.append({'port': port, 'status': 'FILTERED'})
                elif self.flag == "F":  # FIN scan
                    # No response (RST) means port is closed; otherwise, it's likely open
                    open_ports.append({'port': port, 'status': 'OPEN'})
                elif self.flag == "R":  # RST scan
                    # No valid response means port is open
                    open_ports.append({'port': port, 'status': 'OPEN'})
                elif self.flag == "P":  # PSH scan
                    # No response (RST) means port is closed; otherwise, it's likely open
                    open_ports.append({'port': port, 'status': 'OPEN'})
                elif self.flag == "U":  # URG scan
                    # No response (RST) means port is closed; otherwise, it's likely open
                    open_ports.append({'port': port, 'status': 'OPEN'})
                elif self.flag == "E":  # ECN Echo scan
                    # No response (RST) means port is closed; otherwise, it's likely open
                    open_ports.append({'port': port, 'status': 'OPEN'})

        # Log open or filtered ports with their service names
        for open_port in open_ports:
            port_services: str = PortServices(open_port['port']).get_port_service()
            self.logger.info(f'PORT {colored(open_port["port"], "green")} ({port_services}) is {colored(open_port["status"], "green")}')
        print('')

        # Final summary log
        if len(open_ports) > 0:
            open_count = len([p for p in open_ports if p['status'] == 'OPEN'])
            self.logger.info(f'Found {colored(open_count, "green")} open ports.\n')
        else:
            self.logger.warning(f'No open ports found.\n')

        self.logger.info("Scanning completed.")
