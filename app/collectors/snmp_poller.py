"""
Standard RFC SNMP Poller for Intelbras & Multi-Vendor Switches
Captures MAC Addresses, Ports, and VLANs safely without generating fake IP entries.
"""

import asyncio
import logging
from pysnmp.hlapi.v3arch.asyncio import *
from app.database import upsert_device
from app.fingerprint.mac_vendor import lookup_mac_vendor

logger = logging.getLogger("SNMPPoller")

class RealSNMPPoller:
    def __init__(self, target_ip: str = "172.128.100.8", user: str = "sw", password: str = "Summer01"):
        self.target_ip = target_ip
        self.user = user
        self.password = password

    async def poll_intelbras_mac_table(self):
        """
        Polls MAC address & VLAN mapping from Intelbras switch via SNMPv3.
        Updates MAC, VLAN, Port, and Vendor without corrupting L3 IP data.
        """
        logger.info(f"Iniciando varredura SNMPv3 no Switch Intelbras ({self.target_ip})...")
        
        snmp_engine = SnmpEngine()
        user_data = UsmUserData(self.user, self.password, authProtocol=usmHMACMD5AuthProtocol)
        
        try:
            target = await UdpTransportTarget.create((self.target_ip, 161), timeout=5, retries=2)
            root_oid = "1.3.6.1.2.1.17.7.1.2.2.1.2" # dot1qTpFdbPort
            count = 0
            
            async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                snmp_engine, user_data, target, ContextData(),
                ObjectType(ObjectIdentity(root_oid))
            ):
                if errorIndication or errorStatus:
                    break
                    
                for vb in varBinds:
                    oid_str = str(vb[0])
                    # Strictly check that OID stays inside dot1qTpFdbPort subtree
                    if not oid_str.startswith(root_oid):
                        break
                        
                    oid_parts = oid_str.split('.')
                    if len(oid_parts) >= 18:
                        vlan_id = int(oid_parts[-7])
                        mac_dec = oid_parts[-6:]
                        mac_hex = ":".join(f"{int(b):02x}" for b in mac_dec)
                        port = f"Porta {vb[1]}"
                        
                        vendor_name, dev_category = lookup_mac_vendor(mac_hex)
                        
                        # Upsert MAC, VLAN, Port and Switch IP without overwriting real IP from DHCP if present
                        upsert_device(
                            mac=mac_hex,
                            vlan=vlan_id,
                            port=port,
                            switch_ip=self.target_ip,
                            mac_vendor=vendor_name,
                            device_type=dev_category
                        )
                        count += 1

            logger.info(f"Varredura SNMP no switch concluída com sucesso! {count} portas/MACs mapeados.")

        except Exception as e:
            logger.error(f"Exceção durante a varredura SNMP em {self.target_ip}: {e}")

    async def run_periodic_polling(self, interval_seconds: int = 120):
        await asyncio.sleep(2)
        while True:
            try:
                await self.poll_intelbras_mac_table()
            except Exception as e:
                logger.error(f"Erro no ciclo do SNMP Poller: {e}")
            await asyncio.sleep(interval_seconds)
