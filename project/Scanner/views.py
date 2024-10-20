from django.shortcuts import render
from scapy.all import ARP, Ether, srp  # Import ARP and Ether classes for packet manipulation
import requests  # Import requests to make HTTP requests
import socket  # Import socket for network-related functions

def get_device_type(mac):
    """
    Function to determine the device type based on MAC address.
    If the device type cannot be found in the API, it defaults to 'Unknown'.
    
    :param mac: MAC address of the device in string format (e.g., '00:1A:2B:3C:4D:5E')
    :return: Device type as a string
    """
    try:
        # Using the MAC Vendors API to look up the device manufacturer
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        
        # Check if the response status code is 200 (successful)
        if response.status_code == 200:
            vendor = response.text  # Extract the vendor name from the response
            return vendor  # Return the vendor name as the device type
        else:
            return "Unknown"  # Return "Unknown" if the API call fails

    except requests.exceptions.RequestException as e:
        # Log any request-related exceptions and return "Unknown"
        print(f"Error fetching device type for MAC {mac}: {e}")
        return "Unknown"

def get_device_name(ip):
    """
    Function to resolve the hostname (device name) for a given IP address.
    
    :param ip: IP address to resolve
    :return: Hostname as a string, or 'Unknown' if resolution fails
    """
    try:
        device_name = socket.gethostbyaddr(ip)[0]  # Attempt reverse DNS lookup
    except socket.herror:
        device_name = "Unknown"  # Return "Unknown" if lookup fails
    return device_name  # Return the resolved device name

def networkScan(request):
    """
    Main function to scan the local network for connected devices.
    
    :param request: Django request object
    :return: Renders a template displaying the list of discovered devices
    """
    target_ip = '192.168.0.0/24'  # Target IP range (adjust based on your network)

    # Create an ARP request packet
    arp = ARP(pdst=target_ip)  # Specify the target IP range for ARP requests
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Set Ethernet frame to broadcast
    packet = ether / arp  # Combine Ether and ARP to create the full packet

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]  # Receive responses

    # List to store device information
    devices = []

    # Print the total number of responses received
    print(f"Total responses received: {len(result)}")
    
    # Iterate over the results to gather device information
    for sent, received in result:
        # Resolve device name from the IP address
        device_name = get_device_name(received.psrc)
        
        # Determine device type by querying the external API using MAC address
        device_type = get_device_type(received.hwsrc)
        
        # Log the device information for debugging
        print(f"MAC: {received.hwsrc}, IP: {received.psrc}, Device Name: {device_name}")

        # Append discovered device's info to the list
        devices.append({
            'ip': received.psrc,  # Responding device's IP address
            'mac': received.hwsrc,  # Responding device's MAC address
            'name': device_name,  # Resolved device name
            'type': device_type,  # Retrieved device type
        })

    # Print detailed information for each discovered device
    for device in devices:
        print(f"Device Name: {device['name']}, IP: {device['ip']}, MAC: {device['mac']}, Type: {device['type']}")

    # Initialize variable to retrieve the public IP address
    public_ip = None
    try:
        # Get public IP using an external API
        public_ip = requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except requests.exceptions.RequestException as e:
        # Handle any errors that occur during the API call
        print(f"Could not retrieve public IP: {e}")
        public_ip = "Could not retrieve public IP"

    # Render the template with the devices and public IP address
    return render(request, r"C:\Users\bhargav\OneDrive\Desktop\projects\Net-Scan\project\Scanner\templates\network_scan.html", {'devices': devices, 'public_ip': public_ip})
