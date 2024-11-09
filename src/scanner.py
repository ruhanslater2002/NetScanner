from networkscanner import NetworkScanner
from portscanner import PortScanner


class Scanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def scan_network(self):
        network_scanner: NetworkScanner = NetworkScanner(self.target_ip)
        network_scanner.scan_network_arp()
