from scanner import Scanner


class Main:
    def __init__(self):
        # self.target_ip = "192.168.0.0/24"
        self.target_ip = "192.168.0.1"
        # self.target_ip = "192.168.0.47"
        self.scanner: Scanner = Scanner(self.target_ip)

    def start(self) -> None:
        # self.scanner.scan_network()
        self.scanner.scan_ports(1, 80)


if __name__ == '__main__':
    Main().start()
