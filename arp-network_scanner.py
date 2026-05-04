from scapy.all import ARP, Ether, srp
import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import threading

def scan_network(ip_range, progress_callback):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    output = []
    total = len(result)
    for idx, (sent, received) in enumerate(result):
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        output.append(f"IP: {received.psrc}    MAC: {received.hwsrc}    Hostname: {hostname}")
        progress_callback(int((idx + 1) / total * 100))
    return output

def threaded_scan():
    ip_range = ip_entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter a valid IP range.")
        return
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, "Scanning...\n")
    progress_bar['value'] = 0

    def run():
        try:
            results = scan_network(ip_range, lambda v: progress_bar.step(v - progress_bar['value']))
            result_box.delete("1.0", tk.END)
            if results:
                result_box.insert(tk.END, "\n".join(results))
            else:
                result_box.insert(tk.END, "No hosts found.")
            progress_bar['value'] = 100
        except Exception as e:
            result_box.delete("1.0", tk.END)
            result_box.insert(tk.END, f"Error: {str(e)}")

    threading.Thread(target=run).start()

# GUI Setup
window = tk.Tk()
window.title("Advanced ARP Network Scanner")
window.geometry("720x480")

tk.Label(window, text="Enter IP Range (e.g., 192.168.1.0/24):").pack(pady=10)
ip_entry = tk.Entry(window, width=50)
ip_entry.pack()

scan_button = tk.Button(window, text="Start Scan", command=threaded_scan)
scan_button.pack(pady=10)

progress_bar = ttk.Progressbar(window, orient='horizontal', length=500, mode='determinate')
progress_bar.pack(pady=5)

result_box = scrolledtext.ScrolledText(window, height=18, width=85)
result_box.pack(padx=10, pady=10)

window.mainloop()