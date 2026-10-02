import socket
import logging

logger = logging.getLogger("MACVendor")

# Set global socket timeout for quick DNS resolution
socket.setdefaulttimeout(0.5)

# Common IEEE OUI Prefix Mappings (First 3 Octets of MAC Address)
OUI_VENDOR_MAP = {
    "00:0c:29": ("VMware, Inc.", "Servidor Virtual (VMware)"),
    "00:50:56": ("VMware, Inc.", "Servidor Virtual (VMware)"),
    "00:15:5d": ("Microsoft Corp", "Servidor Virtual (Hyper-V)"),
    "a4:83:e7": ("Apple, Inc.", "Apple Device (iPhone/MacBook)"),
    "bc:d0:74": ("Apple, Inc.", "Apple Device (iPhone/iPad)"),
    "f4:b5:20": ("Cisco Systems", "Equipamento Cisco"),
    "e0:8f:4c": ("Intel Corporation", "Computador Intel"),
    "10:62:e5": ("Intelbras", "Equipamento Intelbras"),
    "e0:d4:64": ("Intelbras", "Equipamento Intelbras"),
    "d8:36:5f": ("Intelbras", "Equipamento Intelbras"),
    "e4:5f:01": ("Raspberry Pi Foundation", "Raspberry Pi / IoT"),
    "ec:4c:8c": ("Dell Inc.", "Computador / Servidor Dell"),
    "b8:ca:3a": ("Dell Inc.", "Computador / Servidor Dell"),
    "3c:ec:ef": ("HP Inc.", "Computador / Impressora HP"),
    "00:11:32": ("Synology Inc.", "NAS Synology"),
    "d4:6e:0e": ("TP-Link", "Roteador / AP TP-Link"),
    "00:1c:42": ("Parallels", "Máquina Virtual"),
    "fc:ec:da": ("Ubiquiti Networks", "AP / Switch Ubiquiti")
}

def lookup_mac_vendor(mac: str) -> tuple[str, str]:
    """
    Returns (Vendor_Name, Device_Category) based on MAC address OUI prefix.
    """
    if not mac or len(mac) < 8:
        return ("Desconhecido", "Dispositivo de Rede")
        
    prefix = mac.lower()[:8] # e.g. '00:50:56'
    
    if prefix in OUI_VENDOR_MAP:
        return OUI_VENDOR_MAP[prefix]
        
    return ("Fabricante Padrão", "Dispositivo de Rede")

def resolve_hostname(ip: str) -> str:
    """
    Attempts fast reverse DNS resolution to find the device's hostname.
    """
    if not ip or ip == 'Pending':
        return 'N/A'
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return f"HOST-{ip.replace('.', '-')}"
