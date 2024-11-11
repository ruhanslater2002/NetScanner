import ipaddress
import socket
from termcolor import colored
from packethandler import PacketHandler
from consolelogger import ConsoleLogger


class NetworkScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.logger = ConsoleLogger("SCANNER")

    def scan_network_icmp(self) -> None:
        self.logger.info(f"Scanning network {colored(self.target_ip, 'green')} ...\n")
        responses = []
        try:
            # Generate all IPs in the subnet
            subnet = ipaddress.ip_network(self.target_ip, strict=False)
            for ip in subnet.hosts():
                packet_handler: PacketHandler = PacketHandler(str(ip))
                response: bool = packet_handler.send_icmp_packet()
                if response:
                    responses.append(str(ip))  # Append the actual responding IP

            # Display results
            host_count = len(responses)
            self.logger.info(f'Found {colored(host_count, "green")} hosts.')
            for response in responses:
                self.logger.info(f'Response from {colored(response, "green")}')

        except Exception as e:
            self.logger.warning(f"Error occurred during scan: {e}")
            # Optionally, display any partial results collected before the error
            if responses:
                self.logger.info(f'\nFound {colored(len(responses), "green")} hosts before error.')
                for response in responses:
                    self.logger.info(f'Response from {colored(response, "green")}')

    def scan_network_arp(self) -> None:
        self.logger.info(f"Scanning {colored(self.target_ip, 'green')} ...\n")
        try:
            devices = []
            device_count = 0
            packet_handler = PacketHandler(self.target_ip)
            responses = packet_handler.send_arp_packet("ff:ff:ff:ff:ff:ff")
            for _, response in responses:
                ip = response.psrc
                mac = response.hwsrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = colored("Unknown", "red")
                devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
            #  Prints results
            for device in devices:
                self.logger.info(
                    f"Found -> "
                    f"IP: {colored(device['ip'], 'green')}, "
                    f"MAC: {colored(device['mac'], 'green')}, "
                    f"HOSTNAME: {colored(device['hostname'], 'green')}"
                )
                device_count += 1
            print('')
            self.logger.info(f"There are {colored(device_count, 'green')} devices found.\n")
        except Exception as e:
            self.logger.error(f"Error occurred during scan: {e}")
