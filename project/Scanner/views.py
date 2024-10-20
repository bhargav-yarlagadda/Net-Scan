from django.shortcuts import render
from scapy.all import ARP, Ether, srp
import requests
import socket

def classify_device_type(vendor):
    """Classify device type based on the vendor name using a mapping dictionary."""
    
    # Comprehensive mapping of top brands to device types
    vendor_device_map = {
        "mobile": [
            "apple", "samsung", "xiaomi", "oneplus", "huawei", "oppo", "vivo",
            "motorola", "nokia", "sony", "lg", "htc", "realme", "lenovo", "asus",
            "google", "blackberry", "zte", "alcatel"
        ],
        "pc": [
            "microsoft", "hp", "dell", "lenovo", "acer", "asus", "apple", "samsung",
            "toshiba", "razer", "msi", "gigabyte", "alienware", "surface", "intel",
            "amd", "lg"
        ],
        "tv": [
            "samsung", "lg", "sony", "panasonic", "tcl", "philips", "sharp", 
            "vizio", "hisense", "insignia", "xiaomi", "oneplus", "motorola"
        ],
        "router": [
            "netgear", "linksys", "tp-link", "d-link", "asus", "xiaomi", "samsung", 
            "apple", "huawei", "belkin"
        ]
    }

    # Normalize the vendor name to lowercase for comparison
    vendor = vendor.lower()

    # Check against each category in the vendor_device_map
    for device_type, brands in vendor_device_map.items():
        if any(brand in vendor for brand in brands):
            return device_type  # Return the matched device type

    return "Unknown"  # Return "Unknown" if no matches are found

def get_device_details(mac):
    """Retrieve device details from the MAC Vendors API."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            vendor = response.text  # Get organization (vendor) name
            device_type = classify_device_type(vendor)  # Classify device type
            return {'vendor': vendor, 'type': device_type}
        else:
            return {'vendor': 'Unknown', 'type': 'Unknown'}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching device details for MAC {mac}: {e}")
        return {'vendor': 'Unknown', 'type': 'Unknown'}

def get_device_name(ip):
    """Resolve hostname (device name) for a given IP address."""
    try:
        device_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        device_name = "Unknown"
    return device_name

def networkScan(request):
    """Scan the local network for connected devices."""
    target_ip = '192.168.0.0/24'  # Adjust target IP range as needed
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    print(f"Total responses received: {len(result)}")
    
    for sent, received in result:
        device_name = get_device_name(received.psrc)
        device_info = get_device_details(received.hwsrc)
        
        print(f"MAC: {received.hwsrc}, IP: {received.psrc}, Device Name: {device_name}")
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'name': device_name,
            'vendor': device_info['vendor'],
            'type': device_info['type'],
        })

    for device in devices:
        print(f"Device Name: {device['name']}, IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Type: {device['type']}")

    public_ip = None
    try:
        public_ip = requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except requests.exceptions.RequestException as e:
        print(f"Could not retrieve public IP: {e}")
        public_ip = "Could not retrieve public IP"

    # Render the template with the devices and public IP
    return render(request, 'network_scan.html', {
        'devices': devices, 
        'public_ip': public_ip,
    })
