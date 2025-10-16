import re
import tkinter as tk

import nmap
import socket
import logging
from tkinter import Canvas,Entry,Button,PhotoImage,messagebox
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkVulnerabilityScanner:
    def __init__(self, target_network):
        self.target_network = target_network
        self.scanner = nmap.PortScanner()
        self.services = {
            "Telnet": 23, "FTP": 21, "HTTP": 80, "RSH": 514,
            "SNMP": 161, "POP3": 110, "IMAP": 143
        }

    def scan_network(self):
        logging.info(f"Scanning network: {self.target_network}")
        try:
            self.scanner.scan(hosts=self.target_network, arguments='-sS -sV -O', timeout=60)
            return self.scanner.all_hosts()
        except nmap.PortScannerError as e:
            logging.error(f"Nmap scan failed: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error during scanning: {e}")
            return []

    def scan_services(self, target):
        logging.info(f"\nScanning services on target: {target}")
        for service, port in self.services.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((target, port))
                    
                    if result == 0:
                        logging.info(f"[+] {service} (Port {port}) is OPEN")
                        self.scanner.scan(target, str(port), arguments="-sV")
                        
                        if target in self.scanner.all_hosts():
                            service_info = self.scanner[target]['tcp'].get(port, {})
                            service_name = service_info.get('name', 'Unknown')
                            service_version = service_info.get('version', 'Unknown')
                            logging.info(f"    Service: {service_name} - Version: {service_version}")

                            if service in ["Telnet", "FTP", "HTTP", "RSH", "POP3", "IMAP"]:
                                logging.warning("  Potential Risk: Unencrypted protocol detected.")
                            if "outdated" in service_version.lower():
                                logging.warning("  Service may be outdated. Consider updating.")
                    else:
                        logging.info(f"[-] {service} (Port {port}) is CLOSED")
            except Exception as e:
                logging.error(f"Error scanning {service} on port {port}: {e}")

    def detect_unauthorized_devices(self):
        logging.info("[INFO] Detecting unauthorized devices")
        unauthorized_devices = []
        allowed_devices = self.get_allowed_devices()

        for host in self.scanner.all_hosts():
            mac = self.scanner[host]['addresses'].get('mac', 'UNKNOWN')
            if mac != 'UNKNOWN' and mac not in allowed_devices:
                unauthorized_devices.append({"host": host, "mac": mac})

        return unauthorized_devices

    def get_allowed_devices(self):
        return ["00:1A:2B:3C:4D:5E", "11:22:33:44:55:66"]

    def display_report(self, report):
        print("\n=== Network Vulnerability Report ===")
        print(report)
        print("===================================\n")

    def run(self):
        logging.info("[INFO] Starting vulnerability assessment")
        hosts = self.scan_network()
        report = "Network Vulnerability Report\n"
        report += f"Target: {self.target_network}\n\n"

        for host in hosts:
            report += f"Host: {host}\n"
            self.scan_services(host)

        unauthorized_devices = self.detect_unauthorized_devices()
        report += f"\nUnauthorized Devices: {unauthorized_devices}\n"

        self.display_report(report)

def is_valid_ip(ip):
    """Validate the IP address format."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False

def on_button_click():
    """Validate IP and start scan if valid."""
    ip_address = entry_1.get()
    if is_valid_ip(ip_address):
        messagebox.showinfo("Validation", "Valid IP Address. Scanning...")
        scanner = NetworkVulnerabilityScanner(ip_address)
        scanner.run()
    else:
        messagebox.showerror("Validation", "Invalid IP Address. Please enter a valid IP.")


# Create GUI
OUTPUT_PATH=Path(__file__).parent
ASSETS_PATH=OUTPUT_PATH/Path(r"D:\python\build\assets\frame0")

def relative_to_assets(path:str)-> Path:
    return ASSETS_PATH/Path(path)

window = tk.Tk()
window.geometry("600x400")
window.configure(bg="#FFFFFF")

canvas = Canvas(
    window,
    bg="#FFFFFF",
    height=400,
    width=600,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)
canvas.place(x=0, y=0)

canvas.create_rectangle(313.0, 0.0, 600.0, 406.0, fill="#0A1332", outline="")

canvas.create_text(
    394.0, 45.0,
    anchor="nw",
    text="SAFEHAVEN",
    fill="#FFFFFF",
    font=("GajrajOne Regular", 20 * -1)
)

canvas.create_text(
    326.0, 151.0,
    anchor="nw",
    text="ENTER THE IP ADDRESS:",
    fill="#FFFFFF",
    font=("GajrajOne Regular", 20 * -1)
)

entry_image_1 = PhotoImage(file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(453.5, 209.5, image=entry_image_1)

entry_1 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_1.place(x=332.0, y=192.0, width=243.0, height=33.0)

canvas.create_text(
    325.0, 87.0,
    anchor="nw",
    text="To use our website, you will need to enter\nthe IP address of the network that you \nwant to scan and make sure it is secure.",
    fill="#FFFFFF",
    font=("Galindo Regular", 12 * -1)
)

button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=on_button_click,
    relief="flat"
)
button_1.place(x=372.0, y=250.0, width=140.0, height=55.0)

button_image_hover_1 = PhotoImage(file=relative_to_assets("button_hover_1.png"))


def button_1_hover(e):
    button_1.config(image=button_image_hover_1)


def button_1_leave(e):
    button_1.config(image=button_image_1)


button_1.bind('<Enter>', button_1_hover)
button_1.bind('<Leave>', button_1_leave)

image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(156.0, 200.0, image=image_image_1)

window.resizable(False, False)
window.mainloop()
root = tk.Tk()
root.title("Network Scanner")
root.geometry("400x200")




