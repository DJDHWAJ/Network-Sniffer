import scapy.all as scapy
import json, logging, threading, tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

# Set up logging
logging.basicConfig(filename="sniff_log.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Storage for packets
pktList = []

# Capture and process packets
def capturePackets(pkt):
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        protocol = pkt.sprintf("%IP.proto%")
    else:
        src_ip = dst_ip = protocol = "N/A"

    if pkt.haslayer(scapy.TCP):
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
    else:
        src_port = "N/A"
        dst_port = "N/A"

    # Oops, redundant check (but kinda realistic)
    if pkt.haslayer(scapy.TCP):
        flags = pkt.sprintf("%TCP.flags%")
    else:
        flags = "N/A"

    if pkt.haslayer(scapy.DNSQR):
        dns_query = pkt[scapy.DNSQR].qname.decode()
    else:
        dns_query = "N/A"

    pktData = {
        "timestamp": str(datetime.now()),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "length": len(pkt),
        "payload": pkt.summary(),
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "dns_query": dns_query
    }

    pktList.append(pktData)

    # Print debug messages alongside logging
    print("[DEBUG] Captured:", pktData)
    logging.info(json.dumps(pktData, indent=4))

    # Update GUI display
    if guiDisplay:
        guiDisplay.insert(tk.END, f"{pktData}\n")
        guiDisplay.yview(tk.END)

# Start sniffing packets
def sniffTraffic(iface):
    logging.info(f"Started sniffing on {iface}")
    
    try:
        scapy.sniff(iface=iface, store=False, prn=capturePackets)
    except PermissionError:
        print("[ERROR] Need root/admin privileges to sniff.")
        logging.error("Permission denied: Requires root/admin.")

# Save captured packets to JSON
def savePackets():
    with open("sniffed_pkts.json", "w") as f:
        json.dump(pktList, f, indent=4)
    print("[*] Packets saved to sniffed_pkts.json")
    logging.info("Saved packets to JSON.")

# GUI for network sniffing
def startGUI():
    global guiDisplay

    def startCapture():
        iface = ifaceBox.get().strip()
        if not iface:
            guiDisplay.insert(tk.END, "[!] Please enter a valid network interface.\n")
            return
        guiDisplay.insert(tk.END, f"[*] Capturing on {iface}...\n")
        
        # Run sniffing in a separate thread (prevents GUI freezing)
        threading.Thread(target=sniffTraffic, args=(iface,), daemon=True).start()

    root = tk.Tk()
    root.title("Network Sniffer")

    tk.Label(root, text="Network Interface:").grid(row=0, column=0)
    ifaceBox = tk.Entry(root)
    ifaceBox.grid(row=0, column=1)

    guiDisplay = scrolledtext.ScrolledText(root, width=100, height=30)
    guiDisplay.grid(row=1, column=0, columnspan=2)

    tk.Button(root, text="Start Sniffing", command=startCapture).grid(row=2, column=0)
    tk.Button(root, text="Save Packets", command=savePackets).grid(row=2, column=1)

    root.mainloop()

# Run GUI when script is executed
if __name__ == "__main__":
    startGUI()
