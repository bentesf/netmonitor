import asyncio
import subprocess
import shutil
import json
import logging
from app.database import upsert_device, get_device_by_ip

logger = logging.getLogger("NmapScanner")

COMMON_PORTS = {
    21: ("FTP", "Transferência de Arquivos"),
    22: ("SSH", "Acesso Remoto Seguro (Linux/Rede)"),
    23: ("Telnet", "Acesso Remoto Não Criptografado"),
    53: ("DNS", "Serviço de Nomes de Domínio"),
    80: ("HTTP", "Servidor Web / Painel de Gerenciamento"),
    135: ("RPC", "Microsoft RPC Service"),
    139: ("NetBIOS", "Samba / NetBIOS Windows"),
    443: ("HTTPS", "Servidor Web Criptografado (SSL)"),
    445: ("SMB", "Compartilhamento de Arquivos Windows"),
    1433: ("MSSQL", "Banco de Dados Microsoft SQL"),
    3306: ("MySQL", "Banco de Dados MySQL / MariaDB"),
    3389: ("RDP", "Área de Trabalho Remota Windows"),
    5432: ("PostgreSQL", "Banco de Dados PostgreSQL"),
    5900: ("VNC", "Acesso Remoto VNC"),
    8080: ("HTTP-Alt", "Servidor Web Alternativo / Proxy"),
    8443: ("HTTPS-Alt", "Servidor Web Seguro Alternativo")
}

class NmapDeviceScanner:
    """
    On-Demand Device Inspection Module
    Supports System Nmap CLI (if installed) & Native Async Socket Scanner (Fallback)
    """

    @staticmethod
    def is_nmap_installed() -> bool:
        return shutil.which("nmap") is not None

    @staticmethod
    async def probe_port(ip: str, port: int, timeout: float = 0.8) -> dict | None:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            banner = ""
            try:
                # Try reading banner bytes
                data = await asyncio.wait_for(reader.read(256), timeout=0.4)
                banner = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
                
            writer.close()
            await writer.wait_closed()
            
            service_name, service_desc = COMMON_PORTS.get(port, ("Desconhecido", "Serviço Ativo"))
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service_name,
                "description": service_desc,
                "banner": banner[:60] if banner else "Sem banner"
            }
        except Exception:
            return None

    @classmethod
    async def scan_device(cls, ip: str) -> dict:
        logger.info(f"Iniciando inspeção Nmap / Port Scan no IP: {ip}")
        open_ports = []
        refined_os = None

        # Check if System Nmap Binary is installed
        if cls.is_nmap_installed():
            logger.info("Executando Nmap CLI nativo do sistema...")
            try:
                cmd = ["nmap", "-sV", "--top-ports", "20", "-T4", ip]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                out_str = stdout.decode('utf-8', errors='ignore')
                
                for line in out_str.splitlines():
                    # Parse open ports from Nmap output
                    match = re.search(r'(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)', line)
                    if match:
                        port_num = int(match.group(1))
                        svc = match.group(3)
                        ver = match.group(4)
                        open_ports.append({
                            "port": port_num,
                            "protocol": match.group(2),
                            "state": "open",
                            "service": svc,
                            "description": ver or "Serviço Nmap",
                            "banner": ver
                        })
            except Exception as e:
                logger.error(f"Erro ao executar Nmap CLI: {e}")

        # Native Async Socket Port Scanner (Fast Fallback Engine)
        if not open_ports:
            tasks = [cls.probe_port(ip, port) for port in COMMON_PORTS.keys()]
            results = await asyncio.gather(*tasks)
            open_ports = [r for r in results if r is not None]

        # Infer Refined OS based on Open Ports
        ports_set = {p["port"] for p in open_ports}
        if 3389 in ports_set or 135 in ports_set or 445 in ports_set:
            refined_os = "Windows OS (Detectado via RDP/SMB)"
        elif 22 in ports_set:
            refined_os = "Linux / Unix (Detectado via SSH)"
        elif 80 in ports_set or 443 in ports_set:
            refined_os = "Dispositivo Web / Impressora / Switch"

        # Update database with discovered open ports & refined OS
        dev = get_device_by_ip(ip)
        if dev:
            ports_json = json.dumps(open_ports)
            os_name = refined_os or dev.get('os_name') or 'Desconhecido'
            upsert_device(
                mac=dev['mac'],
                ip=ip,
                os_name=os_name,
                open_ports=ports_json
            )

        return {
            "ip": ip,
            "scan_engine": "Nmap CLI" if cls.is_nmap_installed() else "NetMonitor Async Socket Scanner",
            "open_ports_count": len(open_ports),
            "refined_os": refined_os,
            "open_ports": open_ports
        }
