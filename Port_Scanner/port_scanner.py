# -*- coding: utf-8 -*-
"""
Created on Mon Aug 24 19:13:19 2026

@author: Simo Cyber
"""

import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    filename="port_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def scan_port(target, port, timeout=0.5):
   
    #Attempt to connect to a TCP port and determine its status.
   

    try:
        # Create an IPv4 TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set connection timeout
        sock.settimeout(timeout)

        # Attempt to connect to the target port
        result = sock.connect_ex((target, port))

        # Close the socket
        sock.close()

        # Determine the port status
        if result == 0:
            status = "OPEN"
        else:
            status = "CLOSED"

        # Get current time
        timestamp = datetime.now()

        # Print result to the terminal
        print(f"{timestamp} - Port {port}: {status}")

        # Save result to the log file
        logging.info(f"Port {port}: {status}")

        return port, status

    except socket.timeout:
        timestamp = datetime.now()

        print(f"{timestamp} - Port {port}: TIMEOUT")
        logging.warning(f"Port {port}: TIMEOUT")

        return port, "TIMEOUT"

    except socket.error as error:
        timestamp = datetime.now()

        print(f"{timestamp} - Port {port}: ERROR - {error}")
        logging.error(f"Port {port}: ERROR - {error}")

        return port, "ERROR"

    except Exception as error:
        timestamp = datetime.now()

        print(f"{timestamp} - Port {port}: UNEXPECTED ERROR - {error}")
        logging.exception(f"Port {port}: UNEXPECTED ERROR")

        return port, "ERROR"


def main():
    print("=" * 50)
    print("        PYTHON TCP PORT SCANNER")
    print("=" * 50)

    # Ask for target
    target = input("Enter target IP or hostname: ")

    try:
        # Resolve hostname to an IP address
        target_ip = socket.gethostbyname(target)

        print(f"\nTarget: {target}")
        print(f"IP Address: {target_ip}")

    except socket.gaierror:
        print(f"Error: Could not resolve '{target}'")
        return

    try:
        # Ask for port range
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

        # Validate port range
        if start_port < 1 or end_port > 65535:
            print("Error: Ports must be between 1 and 65535.")
            return

        if start_port > end_port:
            print("Error: Starting port must be less than ending port.")
            return

    except ValueError:
        print("Error: Please enter valid numbers.")
        return

    print(
        f"\nScanning ports {start_port}-{end_port} "
        f"on {target_ip}..."
    )

    print("-" * 50)

    # Create a thread pool
    # max_workers controls how many ports are scanned concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:

        # Submit all ports to the thread pool
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target_ip, port)

    print("-" * 50)
    print("Scan completed.")

    logging.info(
        f"Scan completed for {target_ip}, "
        f"ports {start_port}-{end_port}"
    )


# Start the program
if __name__ == "__main__":
    main()