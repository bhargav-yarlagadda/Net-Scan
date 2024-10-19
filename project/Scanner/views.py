from django.shortcuts import render
from scapy.all import ARP, Ether, srp
import requests
import socket
import platform


def get_device_type(mac):
    """Function to determine device type based on MAC address."""
    # OUI prefixes for common manufacturers (you can still keep this for known types)
    oui_mapping = {
        "D8:07:B6": "Router",  # Example for a router
        "DC:1B:A1": "PC",
        "00:1A:2B": "Mobile",
        "00:1B:63": "Mobile",
        "00:1C:B3": "PC",
        "00:1D:A1": "PC",
        "A4:5E:60": "TV",
        # Add more OUI prefixes as needed from a public OUI database
    }

    # Extract the first three octets of the MAC address (OUI)
    oui = ':'.join(mac.split(':')[:3]).upper()

    # Check in the manual mapping first
    device_type = oui_mapping.get(oui, "Unknown")

    # If not found, try fetching from an external MAC lookup API
    if device_type == "Unknown":
        try:
            # Using the MAC Vendors API to look up the device manufacturer
            response = requests.get(f"https://api.macvendors.com/{mac}")
            if response.status_code == 200:
                vendor = response.text
                # You can map vendor names to device types if needed
                device_type = vendor
            else:
                device_type = "Unknown"
        except:
            device_type = "Unknown"

    return device_type

def get_device_name(ip):
    """Attempt to resolve hostname using gethostbyaddr, fallback to 'Unknown'."""
    try:
        device_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        device_name = "Unknown"  # If reverse DNS lookup fails
    return device_name

def networkScan(request):
    # Target IP range (adjust as needed)
    target_ip = '192.168.0.0/24'  # Adjust according to your network

    # Create an ARP request
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Create a list to store device information
    devices = []

    # Print the total number of responses received
    print(f"Total responses received: {len(result)}")
    
    # Iterate over the results
    for sent, received in result:
        # Try to resolve the device name (hostname), but fallback if it fails
        device_name = get_device_name(received.psrc)
        
        # Determine device type
        device_type = get_device_type(received.hwsrc)
        
        # Log the MAC, IP, and name for debugging
        print(f"MAC: {received.hwsrc}, IP: {received.psrc}, Device Name: {device_name}")

        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'name': device_name,  # Add the device name to the dictionary
            'type': device_type,   # Add device type to the dictionary
        })

    # Print detailed device information
    for device in devices:
        print(f"Device Name: {device['name']}, IP: {device['ip']}, MAC: {device['mac']}, Type: {device['type']}")

    # Initialize the variable for public IP retrieval
    public_ip = None
    try:
        public_ip = requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except:
        public_ip = "Could not retrieve public IP"

    # Render the template with the devices and public IP
    return render(request, 'C:\\Users\\bhargav\\OneDrive\\Desktop\\projects\\Net-Scan\\project\\Scanner\\templates\\network_scan.html', {'devices': devices, 'public_ip': public_ip})
