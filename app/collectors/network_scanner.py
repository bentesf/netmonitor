import asyncio
import subprocess
import re
import logging
import platform
import socket
from app.database import upsert_device
from app.fingerprint.mac_vendor import lookup_mac_vendor

logger = logging.getLogger("NetworkScanner")

class LocalNetworkScanner:
    """
    Active Subnet Ping Sweeper & ARP Collector
    Scans subnets in parallel to discover all 100+ active devices on the network.
    """
    
    def __init__(self, target_subnets: list[str] = None):
        # Default subnets if auto-detection doesn't specify
        self.target_subnets = target_subnets or ["172.128.100", "192.168.0", "172.26.112"]

    @staticmethod
    async def _ping_host(ip: str, semaphore: asyncio.Semaphore):
        async with semaphore:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            cmd = ['ping', param, '1', timeout_param, '250', ip]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                return proc.returncode == 0
            except Exception:
                return False

    async def sweep_subnet(self, subnet_prefix: str):
        """
        Executes fast async ICMP ping sweep across 254 IPs of the given subnet prefix.
        """
        logger.info(f"Iniciando varredura ativa de Ping na subrede {subnet_prefix}.0/24...")
        semaphore = asyncio.Semaphore(60) # 60 concurrent pings
        tasks = [self._ping_host(f"{subnet_prefix}.{i}", semaphore) for i in range(1, 255)]
        results = await asyncio.gather(*tasks)
        active_count = sum(1 for r in results if r)
        logger.info(f"Varredura concluída na subnet {subnet_prefix}.x! {active_count} hosts responderam ao PING.")

    def parse_and_save_arp(self):
        """
        Reads local ARP table and saves all active IP <-> MAC mappings into netmonitor.db.
        """
        logger.info("Atualizando inventário no banco de dados com a tabela ARP...")
        devices_saved = 0
        
        try:
            output = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
            lines = output.splitlines()
            
            for line in lines:
                match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F:-]{17})', line)
                if match:
                    ip = match.group(1)
                    mac_raw = match.group(2).replace('-', ':').lower()
                    
                    # Ignore multicast, broadcast and invalid MACs
                    if ip.startswith('224.') or ip.startswith('239.') or ip.endswith('.255') or mac_raw == 'ff:ff:ff:ff:ff:ff':
                        continue
                        
                    vlan = 1
                    try:
                        octets = ip.split('.')
                        if len(octets) == 4:
                            vlan = int(octets[2])
                    except Exception:
                        pass
                        
                    mac_vendor, dev_type = lookup_mac_vendor(mac_raw)
                    hostname = f"HOST-{ip.replace('.', '-')}"
                    
                    upsert_device(
                        mac=mac_raw,
                        ip=ip,
                        hostname=hostname,
                        mac_vendor=mac_vendor,
                        device_type=dev_type,
                        vlan=vlan,
                        port="Switch Port (Local Subnet)",
                        switch_ip="172.128.100.8",
                        os_name="Dispositivo Ativo na Rede",
                        vendor="Rede Corporativa"
                    )
                    devices_saved += 1
                    
            logger.info(f"Inventário atualizado com sucesso! Total de {devices_saved} dispositivos salvos no banco de dados.")
            return devices_saved
            
        except Exception as e:
            logger.error(f"Erro ao processar tabela ARP: {e}")
            return 0

    async def run_periodic_scan(self, interval_seconds: int = 45):
        """
        Runs periodic active subnet sweeps and updates the database continuously.
        """
        await asyncio.sleep(1)
        while True:
            try:
                for subnet in self.target_subnets:
                    await self.sweep_subnet(subnet)
                self.parse_and_save_arp()
            except Exception as e:
                logger.error(f"Erro durante ciclo de varredura: {e}")
            await asyncio.sleep(interval_seconds)
