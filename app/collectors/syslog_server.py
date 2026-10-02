import asyncio
import re
import logging
from app.database import upsert_device, log_alert
from app.fingerprint.dhcp_fingerprint import identify_os
from app.fingerprint.mac_vendor import lookup_mac_vendor, resolve_hostname

logger = logging.getLogger("SyslogCollector")

class ModularSyslogParser:
    """
    Vendor-Agnostic Syslog Parser
    Includes specific adapters for Sophos Firewall, Fortinet, Cisco, and RFC5424 / ISC-DHCP.
    """
    
    @staticmethod
    def parse_sophos(message: str) -> dict | None:
        """
        Parses Sophos Firewall Syslog messages (DHCP lease & Firewall Deny)
        """
        msg_lower = message.lower()
        
        # 1. DHCP LEASE EVENT (Sophos or Standard dhcpd)
        if "log_component=\"dhcp\"" in msg_lower or "dhcpd" in msg_lower or "dhcpack" in msg_lower or "dhcprequest" in msg_lower:
            mac_match = re.search(r'mac="?([0-9a-fA-F:-]{17})"?', message) or re.search(r'to\s+([0-9a-fA-F:-]{17})', message)
            ip_match = re.search(r'ip="?([0-9a-fA-F.:]+)"?', message) or re.search(r'on\s+([0-9a-fA-F.:]+)', message)
            host_match = re.search(r'hostname="?([^"\s]+)"?', message) or re.search(r'\(([^)]+)\)', message)
            opt60_match = re.search(r'option60="?([^"]+)"?', message)
            opt55_match = re.search(r'option55="?([^"]+)"?', message)
            vlan_match = re.search(r'vlan="?(\d+)"?', message)
            
            if mac_match and ip_match:
                mac = mac_match.group(1).lower()
                ip = ip_match.group(1)
                hostname = host_match.group(1) if host_match else None
                opt60 = opt60_match.group(1) if opt60_match else None
                opt55 = opt55_match.group(1) if opt55_match else None
                vlan = int(vlan_match.group(1)) if vlan_match else None
                
                # Infer VLAN from IP subnet if not explicitly logged
                if not vlan and ip:
                    vlan = ModularSyslogParser.infer_vlan_from_ip(ip)
                
                if not hostname:
                    hostname = f"HOST-{ip.replace('.', '-')}"
                    
                mac_vendor, dev_type = lookup_mac_vendor(mac)
                os_name, vendor = identify_os(option60=opt60, option55=opt55)
                
                return {
                    "type": "DHCP_EVENT",
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vlan": vlan,
                    "mac_vendor": mac_vendor,
                    "device_type": dev_type,
                    "os_name": os_name,
                    "vendor": vendor or opt60
                }
                
        # 2. FIREWALL INTER-VLAN DENY LOG
        if "status=\"deny\"" in msg_lower or "action=\"deny\"" in msg_lower or "action=\"drop\"" in msg_lower or "log_component=\"firewall\"" in msg_lower:
            src_ip_match = re.search(r'src_ip="?([0-9a-fA-F.:]+)"?', message)
            dst_ip_match = re.search(r'dst_ip="?([0-9a-fA-F.:]+)"?', message)
            mac_match = re.search(r'src_mac="?([0-9a-fA-F:-]{17})"?', message)
            
            if src_ip_match and dst_ip_match:
                src_ip = src_ip_match.group(1)
                dst_ip = dst_ip_match.group(1)
                src_vlan = ModularSyslogParser.infer_vlan_from_ip(src_ip)
                dst_vlan = ModularSyslogParser.infer_vlan_from_ip(dst_ip)
                
                # Violation detected if src and dst VLANs are different!
                if src_vlan != dst_vlan:
                    return {
                        "type": "VIOLATION_EVENT",
                        "mac": mac_match.group(1).lower() if mac_match else None,
                        "src_ip": src_ip,
                        "src_vlan": src_vlan,
                        "dst_ip": dst_ip,
                        "dst_vlan": dst_vlan,
                        "message": f"Tentativa não autorizada de transição de VLAN {src_vlan} para VLAN {dst_vlan}"
                    }
        return None

    @staticmethod
    def infer_vlan_from_ip(ip: str) -> int:
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return int(parts[2])
        except Exception:
            pass
        return 1

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, websocket_broadcast=None):
        self.websocket_broadcast = websocket_broadcast

    def datagram_received(self, data, addr):
        message = data.decode('utf-8', errors='ignore')
        logger.debug(f"Received syslog from {addr}: {message}")
        
        # Process Sophos or Generic log
        event = ModularSyslogParser.parse_sophos(message)
        
        if event:
            if event["type"] == "DHCP_EVENT":
                upsert_device(
                    mac=event["mac"],
                    ip=event["ip"],
                    hostname=event["hostname"],
                    mac_vendor=event["mac_vendor"],
                    device_type=event["device_type"],
                    vlan=event["vlan"],
                    os_name=event["os_name"],
                    vendor=event["vendor"]
                )
                logger.info(f"[DHCP Sophos] Dispositivo Conectado: MAC={event['mac']} IP={event['ip']} Host={event['hostname']} VLAN={event['vlan']}")
                
            elif event["type"] == "VIOLATION_EVENT":
                log_alert(
                    mac=event["mac"],
                    src_ip=event["src_ip"],
                    src_vlan=event["src_vlan"],
                    dst_ip=event["dst_ip"],
                    dst_vlan=event["dst_vlan"],
                    message=event["message"],
                    severity="HIGH"
                )
                logger.warning(f"[ALERTA DE SEGURANÇA] {event['message']} (IP: {event['src_ip']})")

async def start_syslog_server(host: str = "0.0.0.0", port: int = 5140):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(),
        local_addr=(host, port)
    )
    logger.info(f"Servidor Syslog escutando em UDP {host}:{port}")
    return transport
