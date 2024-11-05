from scanner import Scanner


class Main:
    def __init__(self):
        scanner: Scanner = Scanner("192.168.0.1", 80)
        scanner.scan_ports(155)


if __name__ == '__main__':
    Main()
