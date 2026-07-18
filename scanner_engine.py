import nmap
import subprocess
import os
import re
import platform
from typing import Dict, List, Any

# Optional dependencies for deep packet inspection and host analytics
try:
    from scapy.all import rdpcap, TCP, IP, Raw, ICMP
except ImportError:
    pass

try:
    import psutil
except ImportError:
    psutil = None

# =====================================================================
# 1. NMAP SCANNING & THREAT DICTIONARY
# =====================================================================

def run_nmap_scan(target_ip: str) -> nmap.PortScanner | None:
    nm = nmap.PortScanner()
    arguments = '-sT -sV --top-ports 100' 
    try:
        nm.scan(hosts=target_ip, arguments=arguments)
        return nm
    except Exception as e:
        print(f"Nmap Scan Error: {e}")
        return None

def parse_nmap_results(nm_object: nmap.PortScanner, target_ip: str) -> Dict[str, Any]:
    if not nm_object or target_ip not in nm_object.all_hosts():
        return {"error": f"Host {target_ip} not found or scan failed."}

    scan_results = {
        "host": target_ip,
        "hostname": nm_object[target_ip].hostname(),
        "status": nm_object[target_ip].state(),
        "open_ports": [],
        "port_threats": [] 
    }
    
    for proto in nm_object[target_ip].all_protocols():
        lport = nm_object[target_ip][proto].keys()
        for port in sorted(lport):
            port_info = nm_object[target_ip][proto][port]
            if port_info['state'] == 'open':
                scan_results['open_ports'].append({
                    "port": port,
                    "protocol": proto.upper(),
                    "service": port_info.get('name', 'unknown'),
                    "version": port_info.get('version', 'unknown')
                })
                
                # Threat Dictionary Evaluation
                if port in [21, 23, 69, 445]:
                    scan_results['port_threats'].append({"tool": "Nmap", "type": "Critical Port", "severity": "Critical", "summary": f"Highly dangerous unencrypted/SMB port exposed: {port} ({port_info.get('name')})"})
                elif port in [3389, 5900, 3306, 5432, 1433]:
                    scan_results['port_threats'].append({"tool": "Nmap", "type": "High Risk Port", "severity": "High", "summary": f"Database or RDP port exposed directly to network: {port}"})
                elif port in [22, 53]:
                    scan_results['port_threats'].append({"tool": "Nmap", "type": "Monitored Port", "severity": "Medium", "summary": f"Management/DNS port exposed: {port}"})

    return scan_results

# =====================================================================
# 2. TSHARK & SCAPY ANALYSIS
# =====================================================================

def run_tshark_capture(duration: int = 15, filename: str = "capture.pcap") -> str | None:
    tshark_command = ['tshark', '-a', f'duration:{duration}', '-w', filename, '-q']
    try:
        subprocess.run(tshark_command, capture_output=True, text=True, check=True) 
        return filename
    except Exception:
        return None

def analyze_pcap_data(pcap_filename: str) -> List[Dict[str, Any]] | List[str]:
    findings = []
    try:
        if not os.path.exists(pcap_filename):
             return [{"tool": "Scapy", "type": "Error", "severity": "Info", "summary": "PCAP file not found. TShark may have failed."}]
        packets = rdpcap(pcap_filename)
    except Exception as e:
        return [{"tool": "Scapy", "type": "Error", "severity": "Info", "summary": f"Error reading PCAP: {e}"}]

    icmp_count = 0
    for packet in packets:
        if packet.haslayer(TCP) and (packet[TCP].dport in [80, 21, 23] or packet[TCP].sport in [80, 21, 23]):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(keyword in payload for keyword in ['GET', 'POST', 'USER', 'PASS']):
                    findings.append({
                        "tool": "Scapy", "type": "Clear-text Traffic", "severity": "Medium",
                        "summary": f"Unencrypted data/credentials found on port {packet[TCP].dport}. Source: {packet[IP].src}"
                    })
        
        if packet.haslayer(ICMP):
            icmp_count += 1
    
    if icmp_count > 30 and len(packets) > 0: 
         findings.append({
            "tool": "Scapy", "type": "ICMP Flood Anomaly", "severity": "High",
            "summary": f"High volume of ICMP packets detected ({icmp_count} in 15s). Potential DoS reconnaissance."
        })

    try:
        os.remove(pcap_filename)
    except Exception:
        pass

    if not findings:
        return [{"tool": "Scapy", "type": "Traffic", "severity": "Info", "summary": "No critical security anomalies detected in live traffic capture."}]
    return findings

# =====================================================================
# 3. SECONDARY TOOLS (DNSRECON)
# =====================================================================

def run_dnsrecon(target_host: str) -> List[Dict[str, str]]:
    if target_host == "127.0.0.1" or target_host.startswith("192.168"): return []
    cmd = ['dnsrecon', '-d', target_host, '-t', 'std']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        findings = []
        if "Zone Transfer was successful" in proc.stdout:
            findings.append({"tool": "DNSRecon", "type": "Zone Transfer", "severity": "Critical", "summary": "Zone Transfer Success."})
        return findings
    except Exception: return []

# =====================================================================
# 4. HOST AUDIT FUNCTIONS
# =====================================================================

def run_host_audit() -> List[Dict[str, str]]:
    findings = []
    
    # 1. OS Info
    try:
        sys_info = f"{platform.system()} {platform.release()} (Ver: {platform.version()})"
        findings.append({"tool": "HostAudit", "type": "System Info", "severity": "Info", "summary": f"OS Detected: {sys_info}"})
    except: pass

    # 2. Windows Firewall Check
    try:
        cmd = ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object Name, Enabled"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if "False" in proc.stdout:
            findings.append({"tool": "HostAudit", "type": "Firewall", "severity": "Critical", "summary": "Windows Firewall is disabled on one or more profiles."})
        else:
            findings.append({"tool": "HostAudit", "type": "Firewall", "severity": "Info", "summary": "Windows Firewall appears enabled for all profiles."})
    except Exception: pass

    # 3. Comprehensive Antivirus Check (Detects K7, McAfee, Defender, etc.)
    try:
        ps_script = """
        $avList = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntivirusProduct -ErrorAction SilentlyContinue
        if ($avList) {
            foreach ($av in $avList) {
                # The state is encoded in hex. We parse the specific byte that indicates if it's Enabled/Disabled.
                $state = ($av.productState -band 0xFF00) -shr 8
                $status = if ($state -eq 16 -or $state -eq 17) { 'Enabled' } else { 'Disabled' }
                Write-Output "$($av.displayName)|$status"
            }
        } else {
            Write-Output "No AV Registered|Disabled"
        }
        """
        cmd = ["powershell", "-NoProfile", "-Command", ps_script]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        av_engines = []
        is_protected = False
        
        for line in proc.stdout.strip().split('\n'):
            if '|' in line:
                name, status = line.split('|', 1)
                av_engines.append(f"{name.strip()} ({status.strip()})")
                if status.strip() == "Enabled":
                    is_protected = True
                    
        av_list_str = ", ".join(av_engines)
        
        if is_protected:
            findings.append({"tool": "HostAudit", "type": "Antivirus", "severity": "Info", "summary": f"Active AV protection detected: {av_list_str}"})
        else:
            findings.append({"tool": "HostAudit", "type": "Antivirus", "severity": "Critical", "summary": f"System VULNERABLE. All AV engines disabled or missing: {av_list_str}"})
    except Exception: 
        pass

    # 4. Password Policy Check 
    try:
        cmd = ["net", "accounts"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if re.search(r"Minimum password length:\s+0", proc.stdout, re.IGNORECASE):
             findings.append({"tool": "HostAudit", "type": "Policy", "severity": "High", "summary": "Minimum password length is set to 0 (Blank passwords allowed)."})
        else:
             findings.append({"tool": "HostAudit", "type": "Policy", "severity": "Info", "summary": "Strong minimum password policy detected."})
    except Exception: pass

    # 5. USB Policy Audit 
    try:
        cmd = ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "/v", "Start"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if "0x3" in proc.stdout:
            findings.append({"tool": "HostAudit", "type": "USB Policy", "severity": "Medium", "summary": "USB Mass Storage is currently ENABLED."})
        elif "0x4" in proc.stdout:
            findings.append({"tool": "HostAudit", "type": "USB Policy", "severity": "Info", "summary": "USB Mass Storage is securely DISABLED."})
    except Exception: pass

    # 6. Process Anomaly Detection 
    if psutil:
        proc_count = len(psutil.pids())
        if proc_count > 350:
            findings.append({"tool": "HostAudit", "type": "Processes", "severity": "High", "summary": f"Abnormal process count detected ({proc_count}). Possible malware/bloatware."})
        elif proc_count > 250:
            findings.append({"tool": "HostAudit", "type": "Processes", "severity": "Medium", "summary": f"Elevated process count detected ({proc_count})."})
        else:
            findings.append({"tool": "HostAudit", "type": "Processes", "severity": "Info", "summary": f"Normal running processes: {proc_count}"})

    return findings