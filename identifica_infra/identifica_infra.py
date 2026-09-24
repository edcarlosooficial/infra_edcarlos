from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Mareo Identifica Infra"
APP_VERSION = "0.1.0-demo"
MAX_HOSTS = 256
COMMON_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389, 5985, 8080]
PORT_NAMES = {
    22: "SSH", 53: "DNS", 80: "HTTP", 135: "MS-RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 5985: "WinRM", 8080: "HTTP-Alt"
}

@dataclass
class HostResult:
    ip: str
    online: bool
    hostname: str = ""
    mac: str = ""
    ttl: Optional[int] = None
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    os_hint: str = "Indeterminado"
    diagnosis: list[str] = field(default_factory=list)

def run_hidden(cmd: list[str], timeout: float = 8):
    kwargs = dict(capture_output=True, text=True, errors="replace", timeout=timeout)
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, **kwargs)

def parse_targets(value: str) -> list[str]:
    value = value.strip()
    if not value:
        raise ValueError("Informe um IP, rede CIDR ou faixa de IPs.")

    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError("Esta amostra suporta IPv4.")
        targets = list(network.hosts())
    elif "-" in value:
        left, right = [p.strip() for p in value.split("-", 1)]
        start, end = ipaddress.ip_address(left), ipaddress.ip_address(right)
        if start.version != 4 or end.version != 4:
            raise ValueError("Esta amostra suporta IPv4.")
        if int(end) < int(start):
            raise ValueError("Faixa inválida.")
        targets = [ipaddress.ip_address(n) for n in range(int(start), int(end) + 1)]
    else:
        ip = ipaddress.ip_address(value)
        if ip.version != 4:
            raise ValueError("Esta amostra suporta IPv4.")
        targets = [ip]

    if len(targets) > MAX_HOSTS:
        raise ValueError(f"Limite da amostra: {MAX_HOSTS} hosts por execução.")
    return [str(ip) for ip in targets]

def ping_host(ip: str):
    cmd = ["ping", "-n", "1", "-w", "700", ip] if os.name == "nt" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        cp = run_hidden(cmd, timeout=2.5)
        text = (cp.stdout or "") + (cp.stderr or "")
        ttl = re.search(r"ttl[=:\s](\d+)", text, re.I)
        return cp.returncode == 0, int(ttl.group(1)) if ttl else None
    except Exception:
        return False, None

def tcp_probe(ip: str, ports: Iterable[int], timeout: float = 0.22) -> list[int]:
    opened = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                opened.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return opened

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def read_arp_mac(ip: str) -> str:
    try:
        cp = run_hidden(["arp", "-a"], timeout=3)
        pattern = rf"\b{re.escape(ip)}\b\s+([0-9a-fA-F]{{2}}(?:[:-][0-9a-fA-F]{{2}}){{5}})"
        m = re.search(pattern, cp.stdout or "")
        return m.group(1).replace("-", ":").upper() if m else ""
    except Exception:
        return ""

def infer_os(ttl: Optional[int], ports: list[int]) -> str:
    p = set(ports)
    if p.intersection({135, 139, 445, 3389, 5985}):
        return "Windows (indício por serviços)"
    if 22 in p:
        return "Linux/Unix ou appliance (indício por SSH)"
    if ttl is not None:
        if ttl <= 64:
            return "Linux/Unix/appliance (indício por TTL)"
        if ttl <= 128:
            return "Windows/appliance (indício por TTL)"
    return "Indeterminado"

def diagnose(open_ports: list[int], hostname: str) -> list[str]:
    p = set(open_ports)
    notes = []
    if not p:
        notes.append("Host respondeu, mas nenhuma porta comum da amostra foi detectada.")
    if 80 in p or 443 in p or 8080 in p:
        notes.append("Serviço web detectado.")
    if 445 in p:
        notes.append("SMB detectado; valide se a exposição é necessária neste segmento.")
    if 3389 in p:
        notes.append("RDP detectado; restrinja acesso conforme a política da organização.")
    if 22 in p:
        notes.append("SSH detectado.")
    if 5985 in p:
        notes.append("WinRM detectado.")
    if hostname:
        notes.append(f"Nome resolvido: {hostname}.")
    return notes

def powershell_json(script: str, timeout: float = 20):
    if os.name != "nt":
        return {}
    cp = run_hidden(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)
    if cp.returncode != 0 or not (cp.stdout or "").strip():
        return {}
    try:
        return json.loads(cp.stdout)
    except json.JSONDecodeError:
        return {}

def local_inventory() -> dict:
    inv = {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "computer": socket.gethostname(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "hardware": {}, "software": [], "peripherals": []
    }
    if os.name != "nt":
        return inv

    hw = r"""
    $cs = Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,TotalPhysicalMemory
    $cpu = Get-CimInstance Win32_Processor | Select -First 1 Name,NumberOfCores,NumberOfLogicalProcessors
    $bios = Get-CimInstance Win32_BIOS | Select SerialNumber,SMBIOSBIOSVersion
    $os = Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture
    $disk = Get-CimInstance Win32_DiskDrive | Select Model,Size,InterfaceType
    [PSCustomObject]@{Computer=$cs;CPU=$cpu;BIOS=$bios;OS=$os;Disks=$disk} | ConvertTo-Json -Depth 5 -Compress
    """
    inv["hardware"] = powershell_json(hw) or {}

    sw = r"""
    $paths = @(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
      'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
      Where-Object {$_.DisplayName} |
      Select DisplayName,DisplayVersion,Publisher |
      Sort DisplayName -Unique |
      ConvertTo-Json -Depth 3 -Compress
    """
    software = powershell_json(sw, 25)
    inv["software"] = [software] if isinstance(software, dict) else (software or [])

    per = r"""
    $classes = @('Monitor','Keyboard','Mouse','Printer','DiskDrive','Net','USB')
    Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
      Where-Object {$_.PNPClass -in $classes -and $_.Status -eq 'OK'} |
      Select Name,Manufacturer,PNPClass,DeviceID |
      Sort PNPClass,Name -Unique |
      ConvertTo-Json -Depth 3 -Compress
    """
    peripherals = powershell_json(per, 25)
    inv["peripherals"] = [peripherals] if isinstance(peripherals, dict) else (peripherals or [])
    return inv

def scan_one(ip: str) -> HostResult:
    online, ttl = ping_host(ip)
    ports = tcp_probe(ip, COMMON_PORTS)
    if ports:
        online = True
    if not online:
        return HostResult(ip=ip, online=False)

    hostname = reverse_dns(ip)
    mac = read_arp_mac(ip)
    services = [PORT_NAMES[p] for p in ports]
    return HostResult(
        ip=ip, online=True, hostname=hostname, mac=mac, ttl=ttl,
        open_ports=ports, services=services, os_hint=infer_os(ttl, ports),
        diagnosis=diagnose(ports, hostname)
    )

def sniff_metadata(seconds: int = 10) -> dict:
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
    except Exception as exc:
        raise RuntimeError("Sniffer indisponível. Instale Scapy/Npcap.") from exc

    stats = {"packets": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0, "icmp": 0, "hosts": {}}

    def on_packet(pkt):
        stats["packets"] += 1
        src = dst = None
        if IP in pkt:
            stats["ipv4"] += 1; src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            stats["ipv6"] += 1; src, dst = pkt[IPv6].src, pkt[IPv6].dst
        if TCP in pkt: stats["tcp"] += 1
        elif UDP in pkt: stats["udp"] += 1
        elif ICMP in pkt: stats["icmp"] += 1
        for host in (src, dst):
            if host:
                stats["hosts"][host] = stats["hosts"].get(host, 0) + 1

    sniff(timeout=seconds, prn=on_packet, store=False)
    stats["hosts"] = dict(sorted(stats["hosts"].items(), key=lambda kv: kv[1], reverse=True)[:20])
    return stats

class MareoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — {APP_VERSION}")
        self.geometry("1040x690")
        self.minsize(900, 600)
        self.results = []
        self.local_inv = {}
        self._build()

    def _build(self):
        self.configure(bg="#0B1F33")
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("TFrame", background="#F4F7F8")
        style.configure("TLabel", background="#F4F7F8", foreground="#1F2D38", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#F4F7F8", foreground="#0B1F33", font=("Segoe UI", 18, "bold"))
        style.configure("Sub.TLabel", background="#F4F7F8", foreground="#647784", font=("Segoe UI", 9))

        side = tk.Frame(self, bg="#0B1F33", width=265)
        side.pack(side="left", fill="y"); side.pack_propagate(False)
        brand = tk.Canvas(side, width=230, height=75, bg="#0B1F33", highlightthickness=0)
        brand.pack(pady=(25, 10))
        brand.create_line(38, 14, 38, 50, fill="#22B8C7", width=2)
        brand.create_polygon(35,16,18,43,35,39,fill="#22B8C7",outline="")
        brand.create_polygon(41,16,60,41,41,37,fill="#4CA7D8",outline="")
        brand.create_polygon(18,47,61,47,54,54,27,54,fill="#B58A45",outline="")
        brand.create_text(83,31,text="MAREO",anchor="w",fill="white",font=("Segoe UI",19,"bold"))
        brand.create_text(84,50,text="TECNOLOGIA",anchor="w",fill="#22B8C7",font=("Segoe UI",8,"bold"))
        tk.Label(side,text="IDENTIFICA INFRA",bg="#0B1F33",fg="#B58A45",font=("Segoe UI",9,"bold")).pack(anchor="w",padx=26)
        tk.Label(side,text="Amostra pública de inventário\ne diagnóstico de infraestrutura.",justify="left",bg="#0B1F33",fg="#CBD9E2",font=("Segoe UI",10)).pack(anchor="w",padx=26,pady=(8,24))
        tk.Label(side,text="Use somente em redes próprias\nou com autorização explícita.",justify="left",bg="#0B1F33",fg="#9FB4C1",font=("Segoe UI",9)).pack(anchor="w",padx=26)

        main = ttk.Frame(self,padding=24); main.pack(side="left",fill="both",expand=True)
        ttk.Label(main,text="Diagnóstico rápido de rede",style="Title.TLabel").pack(anchor="w")
        ttk.Label(main,text="Informe um IP, CIDR ou faixa. Limite da demonstração: 256 hosts.",style="Sub.TLabel").pack(anchor="w",pady=(2,15))
        top = ttk.Frame(main); top.pack(fill="x")
        self.target = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(top,textvariable=self.target,font=("Consolas",11)).pack(side="left",fill="x",expand=True)
        ttk.Button(top,text="Analisar",command=self.start_scan).pack(side="right",padx=(10,0))

        actions=ttk.Frame(main); actions.pack(fill="x",pady=10)
        ttk.Button(actions,text="Inventário deste PC",command=self.collect_local).pack(side="left")
        ttk.Button(actions,text="Sniffer 10s (metadados)",command=self.start_sniff).pack(side="left",padx=8)
        ttk.Button(actions,text="Exportar JSON",command=self.export_json).pack(side="right")
        ttk.Button(actions,text="Exportar CSV",command=self.export_csv).pack(side="right",padx=8)

        cols=("ip","status","hostname","mac","os","services")
        self.tree=ttk.Treeview(main,columns=cols,show="headings")
        headings={"ip":"IP","status":"Status","hostname":"Hostname","mac":"MAC","os":"Indício de SO","services":"Serviços"}
        widths={"ip":110,"status":70,"hostname":145,"mac":125,"os":210,"services":180}
        for col in cols:
            self.tree.heading(col,text=headings[col]); self.tree.column(col,width=widths[col],anchor="w")
        self.tree.pack(fill="both",expand=True)
        self.tree.bind("<<TreeviewSelect>>",self.show_selected)
        self.status=tk.StringVar(value="Pronto para analisar.")
        ttk.Label(main,textvariable=self.status,style="Sub.TLabel").pack(anchor="w",pady=(8,4))
        self.detail=tk.Text(main,height=7,wrap="word",font=("Consolas",9),relief="flat",bg="#EAF0F2",fg="#20313E")
        self.detail.pack(fill="x")

    def set_detail(self,text):
        self.detail.delete("1.0","end"); self.detail.insert("1.0",text)

    def start_scan(self):
        try: targets=parse_targets(self.target.get())
        except Exception as exc:
            messagebox.showerror(APP_NAME,str(exc)); return
        if not messagebox.askyesno(APP_NAME,f"Você confirma que tem autorização para analisar {len(targets)} host(s)?"):
            return
        self.results=[]
        for row in self.tree.get_children(): self.tree.delete(row)
        self.status.set(f"Analisando {len(targets)} host(s)...")
        threading.Thread(target=self._scan,args=(targets,),daemon=True).start()

    def _scan(self,targets):
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32,max(4,len(targets)))) as ex:
            futures=[ex.submit(scan_one,ip) for ip in targets]
            for i,f in enumerate(concurrent.futures.as_completed(futures),1):
                r=f.result(); self.results.append(r)
                self.after(0,self.tree.insert,"","end",None,values=(r.ip,"ATIVO" if r.online else "—",r.hostname,r.mac,r.os_hint if r.online else "",", ".join(r.services)))
                self.after(0,self.status.set,f"Analisando... {i}/{len(targets)}")
        online=sum(1 for r in self.results if r.online)
        self.after(0,self.status.set,f"Concluído: {online} ativo(s) em {len(targets)} analisado(s).")

    def show_selected(self,_=None):
        sel=self.tree.selection()
        if not sel: return
        ip=self.tree.item(sel[0],"values")[0]
        r=next((x for x in self.results if x.ip==ip),None)
        if not r: return
        if not r.online:
            self.set_detail(f"{r.ip}: sem resposta ICMP/TCP nas portas comuns da amostra."); return
        text=[f"IP: {r.ip}",f"Hostname: {r.hostname or '-'}",f"MAC: {r.mac or '-'}",f"TTL: {r.ttl or '-'}",f"Indício de SO: {r.os_hint}",f"Portas: {', '.join(map(str,r.open_ports)) or '-'}","","Diagnóstico:"]
        text += [f"• {x}" for x in r.diagnosis]
        self.set_detail("\n".join(text))

    def collect_local(self):
        self.status.set("Coletando hardware, software e periféricos deste computador...")
        def worker():
            self.local_inv=local_inventory()
            self.after(0,self.set_detail,json.dumps(self.local_inv,indent=2,ensure_ascii=False)[:12000])
            self.after(0,self.status.set,"Inventário local concluído.")
        threading.Thread(target=worker,daemon=True).start()

    def start_sniff(self):
        if not messagebox.askyesno(APP_NAME,"Capturar somente metadados de tráfego por 10 segundos? Nenhum payload será armazenado."):
            return
        self.status.set("Sniffer ativo por 10 segundos...")
        def worker():
            try:
                stats=sniff_metadata(10)
                self.after(0,self.set_detail,json.dumps(stats,indent=2,ensure_ascii=False))
                self.after(0,self.status.set,f"Sniffer concluído: {stats['packets']} pacote(s).")
            except Exception as exc:
                self.after(0,messagebox.showerror,APP_NAME,f"Sniffer indisponível.\n\n{exc}\n\nNo Windows, instale Npcap e execute como Administrador.")
                self.after(0,self.status.set,"Sniffer indisponível.")
        threading.Thread(target=worker,daemon=True).start()

    def export_json(self):
        if not self.results and not self.local_inv:
            messagebox.showinfo(APP_NAME,"Faça uma análise ou inventário antes de exportar."); return
        path=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")],initialfile="mareo_identifica_infra.json")
        if not path: return
        payload={"app":APP_NAME,"version":APP_VERSION,"generated_at":datetime.now().isoformat(timespec="seconds"),"hosts":[asdict(r) for r in self.results],"local_inventory":self.local_inv}
        Path(path).write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo(APP_NAME,"Faça uma análise antes de exportar."); return
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="mareo_hosts.csv")
        if not path: return
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f,delimiter=";")
            w.writerow(["ip","online","hostname","mac","ttl","os_hint","open_ports","services","diagnosis"])
            for r in self.results:
                w.writerow([r.ip,r.online,r.hostname,r.mac,r.ttl or "",r.os_hint,",".join(map(str,r.open_ports)),",".join(r.services)," | ".join(r.diagnosis)])

if __name__ == "__main__":
    MareoApp().mainloop()
