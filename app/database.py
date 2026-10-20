import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "netmonitor.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table for tracked devices across VLANs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT DEFAULT 'N/A',
            mac_vendor TEXT DEFAULT 'Desconhecido',
            device_type TEXT DEFAULT 'Dispositivo de Rede',
            vlan INTEGER,
            port TEXT,
            switch_ip TEXT,
            os_name TEXT DEFAULT 'Desconhecido',
            dhcp_vendor TEXT,
            open_ports TEXT DEFAULT '[]',
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            status TEXT DEFAULT 'online'
        )
    ''')
    
    # Check and safely add missing columns for existing databases
    cursor.execute("PRAGMA table_info(devices)")
    columns = [row['name'] for row in cursor.fetchall()]
    
    for col_name, col_type in [
        ('hostname', "TEXT DEFAULT 'N/A'"),
        ('mac_vendor', "TEXT DEFAULT 'Desconhecido'"),
        ('device_type', "TEXT DEFAULT 'Dispositivo de Rede'"),
        ('open_ports', "TEXT DEFAULT '[]'")
    ]:
        if col_name not in columns:
            try:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass
        
    # Table for inter-VLAN violation alerts & security events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            src_ip TEXT,
            src_vlan INTEGER,
            dst_ip TEXT,
            dst_vlan INTEGER,
            rule_action TEXT,
            message TEXT,
            severity TEXT DEFAULT 'WARNING',
            timestamp TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def upsert_device(mac: str, ip: str = None, hostname: str = None, mac_vendor: str = None, device_type: str = None, vlan: int = None, port: str = None, switch_ip: str = None, os_name: str = None, vendor: str = None, open_ports: str = None):
    init_db() # Ensures columns exist
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac.lower(),))
    row = cursor.fetchone()
    
    if row:
        # Update existing device fields if provided
        new_ip = ip or row['ip']
        new_host = hostname or row['hostname']
        new_mac_vendor = mac_vendor or row['mac_vendor']
        new_device_type = device_type or row['device_type']
        new_vlan = vlan if vlan is not None else row['vlan']
        new_port = port or row['port']
        new_switch = switch_ip or row['switch_ip']
        new_os = os_name or row['os_name']
        new_dhcp_vendor = vendor or row['dhcp_vendor']
        new_open_ports = open_ports if open_ports is not None else row['open_ports']
        
        cursor.execute('''
            UPDATE devices 
            SET ip = ?, hostname = ?, mac_vendor = ?, device_type = ?, vlan = ?, port = ?, switch_ip = ?, os_name = ?, dhcp_vendor = ?, open_ports = ?, last_seen = ?, status = 'online'
            WHERE mac = ?
        ''', (new_ip, new_host, new_mac_vendor, new_device_type, new_vlan, new_port, new_switch, new_os, new_dhcp_vendor, new_open_ports, now, mac.lower()))
    else:
        # Insert new device
        cursor.execute('''
            INSERT INTO devices (mac, ip, hostname, mac_vendor, device_type, vlan, port, switch_ip, os_name, dhcp_vendor, open_ports, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
        ''', (mac.lower(), ip, hostname or 'N/A', mac_vendor or 'Desconhecido', device_type or 'Dispositivo de Rede', vlan or 1, port or 'N/A', switch_ip or 'N/A', os_name or 'Desconhecido', vendor or 'Desconhecido', open_ports or '[]', now, now))
        
    conn.commit()
    conn.close()

def delete_device(mac: str) -> bool:
    """Deletes a device from SQLite DB by MAC address"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE mac = ?", (mac.lower(),))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0

def get_device_by_mac(mac: str):
    """Retrieves full detail of a specific device along with its alert history"""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac.lower(),))
    device = cursor.fetchone()
    
    if not device:
        conn.close()
        return None
        
    dev_dict = dict(device)
    
    # Get associated alerts for this device
    cursor.execute("SELECT * FROM alerts WHERE mac = ? OR src_ip = ? ORDER BY timestamp DESC", (mac.lower(), dev_dict.get('ip')))
    alerts = [dict(r) for r in cursor.fetchall()]
    dev_dict['alerts'] = alerts
    
    conn.close()
    return dev_dict

def get_device_by_ip(ip: str):
    """Retrieves a device record by IP address"""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
    device = cursor.fetchone()
    conn.close()
    return dict(device) if device else None

def log_alert(mac: str, src_ip: str, src_vlan: int, dst_ip: str, dst_vlan: int, message: str, severity: str = "HIGH"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO alerts (mac, src_ip, src_vlan, dst_ip, dst_vlan, message, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (mac.lower() if mac else 'Desconhecido', src_ip, src_vlan, dst_ip, dst_vlan, message, severity, now))
    
    conn.commit()
    conn.close()

def get_devices():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM devices WHERE status = 'online'")
    total_devices = cursor.fetchone()['total']
    
    cursor.execute("SELECT vlan, COUNT(*) as count FROM devices GROUP BY vlan")
    vlans = {row['vlan']: row['count'] for row in cursor.fetchall() if row['vlan']}
    
    cursor.execute("SELECT os_name, COUNT(*) as count FROM devices GROUP BY os_name")
    os_dist = {row['os_name']: row['count'] for row in cursor.fetchall()}
    
    cursor.execute("SELECT COUNT(*) as total FROM alerts")
    total_alerts = cursor.fetchone()['total']
    
    conn.close()
    return {
        "total_devices": total_devices,
        "vlans": vlans,
        "os_distribution": os_dist,
        "total_alerts": total_alerts
    }
