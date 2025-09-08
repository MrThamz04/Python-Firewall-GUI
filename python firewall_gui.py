import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading

# Firewall rules (will be updated by the UI)
blocked_ips = []
blocked_protocols = {"TCP": TCP, "UDP": UDP, "ICMP": ICMP}
selected_protocols = []

# Flag to control the packet sniffing thread
sniffing = False

def packet_filter(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Rule 1: Block blocked IPs
        if ip_src in blocked_ips or ip_dst in blocked_ips:
            log_message(f"BLOCKED - IP: {ip_src} -> {ip_dst}")
            return False
        
        # Rule 2: Block selected protocols
        for proto_name in selected_protocols:
           protocol = blocked_protocols[proto_name]
        if packet.haslayer(protocol):
                log_message(f"BLOCKED - {proto_name}: {ip_src} -> {ip_dst}")
                return False
    
    return True

def start_firewall():
    global sniffing
    if not sniffing:
        sniffing = True
        log_message("[+] Starting firewall...")
        # Start sniffing in a separate thread to avoid freezing the UI
        thread = threading.Thread(target=run_sniffer, daemon=True)
        thread.start()
        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)

def stop_firewall():
    global sniffing
    sniffing = False
    log_message("[+] Firewall stopped.")
    start_btn.config(state=tk.NORMAL)
    stop_btn.config(state=tk.DISABLED)

def run_sniffer():
    sniff(filter="ip", prn=lambda x: None, store=0, stop_filter=lambda x: not sniffing, lfilter=packet_filter)

def add_ip():
    ip = ip_entry.get()
    if ip and ip not in blocked_ips:
        blocked_ips.append(ip)
        update_ip_listbox()
        ip_entry.delete(0, tk.END)
        log_message(f"Added IP: {ip}")

def remove_ip():
    selected = ip_listbox.curselection()
    if selected:
        ip = ip_listbox.get(selected[0])
        blocked_ips.remove(ip)
        update_ip_listbox()
        log_message(f"Removed IP: {ip}")

def update_ip_listbox():
    ip_listbox.delete(0, tk.END)
    for ip in blocked_ips:
        ip_listbox.insert(tk.END, ip)

def toggle_protocol(proto):
    if proto in selected_protocols:
        selected_protocols.remove(proto)
    else:
        selected_protocols.append(proto)
    log_message(f"Toggled protocol: {proto}")

def log_message(message):
    log_area.insert(tk.END, message + "\n")
    log_area.see(tk.END)  # Auto-scroll to the bottom

# Create the main window
root = tk.Tk()
root.title("Simple Python Firewall")
root.geometry("600x500")

# IP Management Frame
ip_frame = tk.LabelFrame(root, text="IP Address Management", padx=5, pady=5)
ip_frame.pack(padx=10, pady=5, fill=tk.X)

tk.Label(ip_frame, text="IP to block:").grid(row=0, column=0, sticky="w")
ip_entry = tk.Entry(ip_frame)
ip_entry.grid(row=0, column=1, padx=5)
tk.Button(ip_frame, text="Add", command=add_ip).grid(row=0, column=2, padx=5)
tk.Button(ip_frame, text="Remove Selected", command=remove_ip).grid(row=0, column=3, padx=5)

ip_listbox = tk.Listbox(ip_frame, height=4)
ip_listbox.grid(row=1, column=0, columnspan=4, sticky="ew", pady=5)

# Protocol Management Frame
proto_frame = tk.LabelFrame(root, text="Protocol Management", padx=5, pady=5)
proto_frame.pack(padx=10, pady=5, fill=tk.X)

for proto in blocked_protocols:
    btn = tk.Checkbutton(proto_frame, text=proto, command=lambda p=proto: toggle_protocol(p))
    btn.pack(side=tk.LEFT, padx=5)

# Control Buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

start_btn = tk.Button(btn_frame, text="Start Firewall", command=start_firewall)
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = tk.Button(btn_frame, text="Stop Firewall", command=stop_firewall, state=tk.DISABLED)
stop_btn.pack(side=tk.LEFT, padx=5)

# Log Area
log_frame = tk.LabelFrame(root, text="Firewall Log", padx=5, pady=5)
log_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

log_area = scrolledtext.ScrolledText(log_frame, height=15)
log_area.pack(fill=tk.BOTH, expand=True)

root.mainloop()