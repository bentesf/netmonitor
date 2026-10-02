"""
DHCP Fingerprinting Module (Passive OS Identification)
Maps Option 60 (Vendor Class Identifier) and Option 55 (Parameter Request List)
to Operating Systems in a vendor-agnostic way.
"""

# Common Option 60 string patterns
VENDOR_OPTION60_MAP = {
    "MSFT 5.0": "Windows 10 / 11 / Server",
    "MSFT 4.0": "Windows NT / 2000",
    "dhcpcd": "Linux (Generic / Raspberry Pi)",
    "android-dhcp": "Android Mobile Device",
    "MacBook": "macOS",
    "Apple": "iOS / macOS",
    "iBridge": "macOS TouchBar",
    "HP": "Impressora HP",
    "EPSON": "Impressora Epson",
    "Hikvision": "Câmera Hikvision",
    "Intelbras": "Câmera / Equipamento Intelbras",
    "Axis": "Câmera IP Axis",
    "Cisco": "Telefone / Equipamento Cisco",
    "MikroTik": "Roteador MikroTik"
}

# Common Option 55 parameter sequence patterns
OPTION55_MAP = {
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows 10 / 11",
    "1,121,3,6,15,119,252,95,44,46": "Windows Server / Enterprise",
    "1,3,6,15,119,95,252,44,46": "Windows 7 / 8",
    "1,3,6,15,119,252": "macOS / iOS",
    "1,3,6,15,26,28,51,58,59,43": "Android Device",
    "1,28,2,3,15,6,119,12,44,47,26,121,42": "Ubuntu / Debian Linux",
    "1,3,6,12,15,28,42": "Linux / IoT Device"
}

def identify_os(option60: str = None, option55: str = None) -> tuple[str, str]:
    """
    Returns a tuple of (OS_Name, Vendor_Info) based on DHCP options.
    """
    detected_os = "Desconhecido"
    detected_vendor = "Desconhecido"

    if option60:
        detected_vendor = option60
        for pattern, os_name in VENDOR_OPTION60_MAP.items():
            if pattern.lower() in option60.lower():
                detected_os = os_name
                break

    if detected_os == "Desconhecido" and option55:
        clean_opt55 = option55.strip()
        if clean_opt55 in OPTION55_MAP:
            detected_os = OPTION55_MAP[clean_opt55]

    return detected_os, detected_vendor
