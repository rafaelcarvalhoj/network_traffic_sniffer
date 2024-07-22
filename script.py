"""
Network Traffic Sniffer Script

This script captures network packets on a specified interface and provides traffic statistics.
You can also list available network interfaces without capturing packets.
"""

import argparse
import subprocess
import re
import sys

from sniffer import Sniffer


def list_interfaces():
    """
    List all available network interfaces.
    """
    try:
        result = subprocess.run(["ip", "a"], capture_output=True, text=True, check=True)

        # Regex pattern to extract interface names
        regex_pattern = r"^\d+: (\S+):"
        interfaces = re.findall(regex_pattern, result.stdout, re.MULTILINE)
        print("==== Available Network Interfaces ====")
        for idx, i in enumerate(interfaces):
            print(f"{idx+1}: {i}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing subprocess: {e}")


def main():
    """
    Script entrypoint
    """
    parser = argparse.ArgumentParser(
        description="Network traffic sniffer script using Scapy.\n"
        "This script captures network packets on a specified interface and"
        "provides traffic statistics.\n"
        "You can also list available network interfaces without capturing packets."
    )

    parser.add_argument(
        "interface",
        type=str,
        help="Network interface to sniff packets from.",
        nargs="?",
        default=None,
    )

    parser.add_argument(
        "-si",
        "--show-interfaces",
        action="store_true",
        help="List all available network interfaces instead of capturing packets.",
    )

    parser.add_argument(
        "-gl",
        "--gen-log",
        action="store_true",
        help="Enable log generation for script output.",
    )

    args = parser.parse_args()
    if args.show_interfaces and args.interface:
        print(
            "Error: Use only one argument. Either list interfaces"
            "or specify an interface to sniff."
        )
        sys.exit(0)

    if args.show_interfaces:
        list_interfaces()
    else:
        if args.interface:
            sniffer = Sniffer(args.interface, args.gen_log)
            sniffer.run()
        else:
            print(
                "Error: No network interface specified. Use -si to list available interfaces."
            )


if __name__ == "__main__":
    main()
