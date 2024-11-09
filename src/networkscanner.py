import ipaddress
import socket
from termcolor import colored
from packethandler import PacketHandler


class NetworkScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.minus = colored("-", "red")
        self.plus = colored("+", "green")

    def scan_network_icmp(self) -> None:
        print(f"[*] Scanning network {colored(self.target_ip, 'green')}\n")
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
            print(f'\n[{self.plus}] Found {colored(host_count, "green")} hosts.')
            for response in responses:
                print(f'[{self.plus}] Response from {colored(response, "green")}')

        except Exception as e:
            print(f"[{self.minus}] Error occurred during scan: {e}")
            # Optionally, display any partial results collected before the error
            if responses:
                print(f'\n[{self.plus}] Found {colored(len(responses), "green")} hosts before error.')
                for response in responses:
                    print(f'[{self.plus}] Response from {colored(response, "green")}')

    def scan_network_arp(self):
        print(f"[*] Scanning network {colored(self.target_ip, 'green')}\n")
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
                    hostname = "Unknown"
                devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
            #  Prints results
            for device in devices:
                print(f"[{self.plus}] "
                      f"IP: {colored(device['ip'], "green")}, "
                      f"MAC: {colored(device['mac'], "green")}, "
                      f"HOSTNAME: {colored(device['hostname'], "green")}")
                device_count += 1
            print(f"\n[{self.plus}] There are {colored(device_count, 'green')} devices found.\n")
        except Exception as e:
            print(f"[{self.minus}] Error occurred during scan: {e}")
