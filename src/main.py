from scanner import Scanner


class Main:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.scanner: Scanner = Scanner(self.target_ip)

    def start(self) -> None:
        self.scanner.scan_network()
        # scanner.scan_ports(155)


if __name__ == '__main__':
    Main("192.168.0.1").start()
