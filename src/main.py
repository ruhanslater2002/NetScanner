from scanner import Scanner
import argparse


class Main:
    def __init__(self):
        self.logo = f"""
         _   _      _     _____                                 
        | \\ | |    | |   /  ___|                                
        |  \\| | ___| |_  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
        | . ` |/ _ \\ __|  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|
        | |\\  |  __/ |_  /\\__/ / (_| (_| | | | | | | |  __/ |   
        \\_| \\_/\\___|\\__| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   

        """
        print(self.logo)

        # Set up argument parser
        self.parser = argparse.ArgumentParser(description="Network scanner tool made for penetration testing.")

        # Add arguments
        self.parser.add_argument("-sn", "--scan-network", action="store_true", help="Perform network scan.")
        self.parser.add_argument("target_ip", type=str, help="The target IP address to scan.")
        self.parser.add_argument("-sp", "--scan-ports", action="store_true", help="Perform a port scan.")
        self.parser.add_argument("-p", "--port-range", nargs=2, type=int, metavar=('START_PORT', 'END_PORT'),
                                 help="Range of ports to scan (start and end port).")

        # Parse the arguments
        self.args = self.parser.parse_args()

        # Initialize the scanner with the target IP
        self.scanner = Scanner(self.args.target_ip)

    def start(self) -> None:
        # Check if -sn (scan network) flag is used to start a network scan
        if self.args.scan_network:
            self.scanner.scan_network()

        # Check if -sp (scan ports) flag is used to start a port scan
        if self.args.scan_ports:
            # Use specified port range or default range 0-80
            start_port, end_port = (self.args.port_range if self.args.port_range else (0, 80))
            self.scanner.scan_ports(start_port, end_port)

        # If neither -sn nor -sp was specified, print usage info
        if not self.args.scan_network and not self.args.scan_ports:
            print("Please specify a scan option, e.g., -sn for network scan or -sp for port scan.")


if __name__ == '__main__':
    Main().start()
