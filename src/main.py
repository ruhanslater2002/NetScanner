from scanner import Scanner
import argparse


class Main:
    def __init__(self):
        self.logo = """
         _   _      _     _____                                 
        | \\ | |    | |   /  ___|                                
        |  \\| | ___| |_  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
        | . ` |/ _ \\ __|  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|
        | |\\  |  __/ |_  /\\__/ / (_| (_| | | | | | | |  __/ |   
        \\_| \\_/\\___|\\__| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   

        """
        print(self.logo)

        self.parser = argparse.ArgumentParser(description="Network scanner tool made for penetration testing.")
        self.parser.add_argument("target_ip", type=str, help="The target IP address to scan.")
        self.parser.add_argument("-sn", "--scan-network", action="store_true", help="Perform network scan.")
        self.parser.add_argument("-sps", "--syn-port-scan", action="store_true", help="Perform a SYN port scan.")
        self.parser.add_argument("-aps", "--ack-port-scan", action="store_true", help="Perform an ACK port scan.")
        self.parser.add_argument("-fps", "--fin-port-scan", action="store_true", help="Perform a FIN port scan.")
        self.parser.add_argument("-xps", "--xmas-port-scan", action="store_true", help="Perform a Xmas port scan.")
        self.parser.add_argument("-nps", "--null-port-scan", action="store_true", help="Perform a Null port scan.")
        self.parser.add_argument("-pss", "--push-port-scan", action="store_true", help="Perform a PSH port scan.")
        self.parser.add_argument("-urs", "--urg-port-scan", action="store_true", help="Perform a URG port scan.")
        self.parser.add_argument("-rss", "--rst-port-scan", action="store_true", help="Perform a RST port scan.")
        self.parser.add_argument("-ecs", "--ecn-port-scan", action="store_true", help="Perform an ECN port scan.")
        self.parser.add_argument("-ps", "--port-range", nargs=2, type=int, metavar=('START_PORT', 'END_PORT'),
                                 help="Range of ports to scan (start and end port).")

        self.args = self.parser.parse_args()
        self.scanner = Scanner(self.args.target_ip)

    def start(self) -> None:
        if self.args.scan_network:
            self.scanner.scan_network()

        if self.args.syn_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "S")  # SYN scan with "S" flag

        if self.args.ack_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "A")  # ACK scan with "A" flag

        if self.args.fin_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "F")  # FIN scan with "F" flag

        if self.args.xmas_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "FPU")  # Xmas scan with "FPU" flags

        if self.args.null_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "")  # Null scan with no flags

        if self.args.push_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "P")  # PSH scan with "P" flag

        if self.args.urg_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "U")  # URG scan with "U" flag

        if self.args.rst_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "R")  # RST scan with "R" flag

        if self.args.ecn_port_scan:
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port, "E")  # ECN scan with "E" flag

        if not any([self.args.scan_network, self.args.syn_port_scan, self.args.ack_port_scan,
                    self.args.fin_port_scan, self.args.xmas_port_scan, self.args.null_port_scan,
                    self.args.push_port_scan, self.args.urg_port_scan, self.args.rst_port_scan,
                    self.args.ecn_port_scan]):
            print("Please specify a scan option, e.g., -sn for network scan or -sps for SYN port scan.")


if __name__ == '__main__':
    Main().start()
