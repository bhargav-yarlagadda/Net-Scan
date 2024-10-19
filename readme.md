# Network Scanner Project

This project is a network scanner built using **Django** and **Scapy**. It scans your local network to discover devices and provides detailed information such as IP addresses, MAC addresses, hostnames, and inferred device types. The scanner utilizes ARP requests to detect active devices and attempts to identify their types through MAC address lookups.

## Features

- **Local Network Scanning:** Automatically discover devices in a specified IP range using ARP requests.
- **Device Information:** Retrieve details for each device, including:
  - IP Address
  - MAC Address
  - Hostname (if available)
  - Device Type (inferred from the MAC address)
- **MAC Address Lookup:** Identify device manufacturers using an external MAC address lookup API.

## Installation

### Prerequisites

- Python 3.x
- Django
- Scapy
- Requests library


### Prerequisites

- Python 3.x
- pip (Python package manager)

### Steps to Run the Application

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/bhargav-yarlagadda/Net-Scan.git
   cd Net-Scan
   cd project
   ```
2. **Install Deps**
   ```bash
   pip install django scapy requests
   ```
3. **RUN THE  SERVER**
   ```bash
   python manage.py runserver
   ```
