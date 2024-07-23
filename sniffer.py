"""
Network Packet Sniffer Module

This module defines a Sniffer class that captures network packets on a specified interface,
provides traffic statistics, and optionally logs the output to a file.
"""
import signal
import logging
import sys
import os
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP

protocols = ["Unknown"] * 256
protocols[0] = "HOPOPT"
protocols[1] = "ICMP"
protocols[2] = "IGMP"
protocols[6] = "TCP"
protocols[17] = "UDP"
protocols[41] = "IPv6"
protocols[89] = "OSPF"
protocols[50] = "ESP"
protocols[51] = "AH"
protocols[132] = "SCTP"


class Sniffer:
    """
    A class to capture network packets and provide traffic statistics.

    Attributes:
        interface (str): The network interface to sniff packets from.
        gen_log (bool): Flag to enable logging of packet information.
        sniffed_packets (list): List of captured packets.
        protocol_count (dict): Dictionary to count packets by protocol.
        ip_src_count (dict): Dictionary to count packets by source IP address.
        ip_dst_count (dict): Dictionary to count packets by destination IP address.
    """

    def __init__(self, interface, gen_log):
        """
        Initializes the Sniffer with the given interface and log generation flag.

        Args:
            interface (str): The network interface to sniff packets from.
            gen_log (bool): Flag to enable logging of packet information.
        """
        self.interface = interface
        self.gen_log = gen_log
        self.sniffed_packets = []
        self.protocol_count = {}
        self.ip_src_count = {}
        self.ip_dst_count = {}

        log_file_path = "./sniffer.log"
        self.csv_file_path = "./sniffer.csv"

        if self.gen_log:
            if os.path.exists(log_file_path):
                os.remove(log_file_path)

            if os.path.exists(self.csv_file_path):
                os.remove(self.csv_file_path)

            logging.basicConfig(
                filename=log_file_path,
                level=logging.INFO,
                format="%(asctime)s - %(message)s",
            )

            self.csv_log = pd.DataFrame(columns=["timestamp", "from", "destiny", "protocol", "length"])
            self.csv_log.to_csv(self.csv_file_path, index=False)

    def __callback(self, packet):
        """
        Callback function to process each packet captured by Scapy.

        Args:
            packet (scapy.packet.Packet): The captured packet.
        """
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            packet_len = len(packet)

            target_packet = {
                "src": ip_src,
                "dst": ip_dst,
                "protocol": protocol,
                "packet_len": packet_len,
            }
            self.sniffed_packets.append(target_packet)

            min_width_ip = 15
            min_width_protocol = 5
            min_width_length = 6

            output = (
                f"FROM: {ip_src.ljust(
                    min_width_ip)} - DESTINY: {ip_dst.ljust(min_width_ip)} | "
                f"PROTOCOL: {str(protocols[int(protocol)]).rjust(min_width_protocol)} | LENGTH: {
                    str(packet_len).rjust(min_width_length)} bytes"
            )
            print(output)

            if self.gen_log:
                logging.info(output)
                new_row = pd.DataFrame([{
                    "timestamp": pd.Timestamp.now(),
                    "from": ip_src,
                    "destiny": ip_dst,
                    "protocol": protocols[int(protocol)] if int(protocol) < len(protocols) else protocol,
                    "length": packet_len,
                }])
                self.csv_log = pd.concat([self.csv_log, new_row], ignore_index=True)
                self.csv_log.to_csv(self.csv_file_path, index=False)

            if ip_src in self.ip_src_count:
                self.ip_src_count[ip_src] += 1
            else:
                self.ip_src_count[ip_src] = 1

            if ip_dst in self.ip_dst_count:
                self.ip_dst_count[ip_dst] += 1
            else:
                self.ip_dst_count[ip_dst] = 1

            if protocol in self.protocol_count:
                self.protocol_count[protocol] += 1
            else:
                self.protocol_count[protocol] = 1

    def print_data(self):
        """
        Prints the captured traffic statistics and logs them if logging is enabled.
        """
        summary = "\n--- Traffic Statistics ---\n"

        summary += f"Total Packets: {len(self.sniffed_packets)}\n"

        summary += "\nPackets by Protocol:\n"
        for proto, count in self.protocol_count.items():
            summary += f"Protocol {protocols[int(proto)] if int(
                proto) < len(protocols) else proto}: {count} packets\n"

        summary += "\nTop 5 Source IPs:\n"
        for ip, count in sorted(
            self.ip_src_count.items(), key=lambda item: item[1], reverse=True
        )[:5]:
            summary += f"{ip}: {count} packets\n"

        summary += "\nTop 5 Destination IPs:\n"
        for ip, count in sorted(
            self.ip_dst_count.items(), key=lambda item: item[1], reverse=True
        )[:5]:
            summary += f"{ip}: {count} packets\n"

        print(summary)

        if self.gen_log:
            logging.info(summary)

    def run(self):
        """
        Starts the packet capture and processes the captured packets.
        """
        data_displayed = False
        def handle_signal(signum, frame):
            """
            Signal handler to call print_data() on termination signals.
            """
            nonlocal data_displayed
            if not data_displayed:
                self.print_data()
                data_displayed = True
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            print("Starting packet capture. Press Ctrl+C to stop.")
            sniff(iface=self.interface, prn=self.__callback)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if not data_displayed:
                self.print_data()
                data_displayed = True
