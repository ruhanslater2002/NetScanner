from networkscanner import NetworkScanner
from portscanner import PortScanner


class Scanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def scan_network(self) -> None:
        network_scanner: NetworkScanner = NetworkScanner(self.target_ip)
        network_scanner.scan_network_arp()

    def scan_ports(self, target_port: int, port_range: int) -> None:
        port_scanner: PortScanner = PortScanner(self.target_ip)
        port_scanner.scan_ports(target_port, port_range)
