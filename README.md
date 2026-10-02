# NetMonitor Pro - Sistema de Monitoramento & Segurança Inter-VLAN

Software personalizado e multi-fabricante para monitoramento de VLANs, inventário em tempo real, detecção passiva de Sistema Operacional (DHCP Fingerprinting) e alertas de violação de tráfego inter-VLAN.

---

## 🚀 Como Executar o Projeto

### 1. Requisitos
- Python 3.10+
- Dependências listadas em `requirements.txt`

### 2. Instalação das Dependências
```bash
pip install -r requirements.txt
```

### 3. Iniciar a Aplicação
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Acesse o Dashboard no navegador:
`http://localhost:8000`

---

## ⚙️ Configuração do Firewall e Switches

### 1. Configuração do Firewall Sophos (ou qualquer outro Firewall)
1. Acesse o painel do **Sophos Firewall**.
2. Vá em **System > Services > Log Settings**.
3. Adicione um novo **Syslog Server**:
   - **IP:** IP da máquina onde o NetMonitor está rodando.
   - **Porta:** `5140` (UDP).
   - **Facility:** DAEMON / LOCAL0.
4. Habilite o envio de logs das seguintes categorias:
   - **DHCP Server Logs** (para identificação de conexão e Sistema Operacional).
   - **Firewall Traffic / Deny Logs** (para detecção de violação inter-VLAN).

### 2. Configuração nos Switches (SNMP Multi-Vendor)
Habilite o SNMP v2c nos seus switches (Cisco, Aruba, MikroTik, Dell, Huawei, etc.):
```text
snmp-server community public RO
```
O NetMonitor consulta as MIBs padrões `Q-BRIDGE-MIB` e `IP-MIB` para mapear MAC address e portas.

---

## 🛠️ Teste Rápido no Dashboard
Mesmo sem conectar equipamentos de rede reais imediatamente, você pode testar a ferramenta abrindo a interface web (`http://localhost:8000`):
- Clique em **"Simular Dispositivo"** para gerar a conexão simulada de um host com seu respectivo SO (Windows, Android, macOS, Linux).
- Clique em **"Simular Violação de VLAN"** para disparar o alerta visual vermelho de tentativa não autorizada de navegação entre subredes.
