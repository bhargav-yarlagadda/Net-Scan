# NetworkScanner

NetworkScanner is a Django web application that scans your local network for connected devices, displaying their IP addresses, MAC addresses, and device names. This application helps users monitor their network and understand connected devices.

## Features

- **Device Discovery**: Automatically scans the network to find all connected devices.
- **Device Information**: Displays IP addresses, MAC addresses, and device names.
- **User-Friendly Interface**: Simple and clean web interface for easy interaction.
- **Public IP Display**: Shows the public IP address of your network.

## Technologies Used

- **Django**: Python web framework for building the application.
- **Scapy**: Python library for network packet manipulation and scanning.
- **Requests**: Library for making HTTP requests, used to fetch public IP.
- **HTML/CSS**: Basic web technologies for front-end design.

## Installation

### Prerequisites

- Python 3.x
- pip (Python package manager)

### Steps to Run the Application

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/NetworkScanner.git
   cd NetworkScanner
   pip install django scapy requests
   ```
2. **Install Deps**
   ```bash
   pip install django scapy requests
   ```
3. **RUN THE  SERVER**
   ```bash
   python manage.py runserver
   ```