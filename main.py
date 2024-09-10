import scapy.all as scapy
import socket
from tkinter import *
from tkinter import ttk

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        try:
            client_dict["name"] = socket.gethostbyaddr(element[1].psrc)[0]
        except socket.herror:
            client_dict["name"] = "Unknown"
        clients_list.append(client_dict)
    return clients_list

def start_scan():
    ip_range = ip_entry.get()
    if ip_range:
        scan_results = scan(ip_range)
        update_tree(scan_results)

def update_tree(clients_list):
    tree.delete(*tree.get_children())  # 清除现有的树视图内容
    for client in clients_list:
        tree.insert("", "end", values=(client["ip"], client["mac"], client["name"]))

def filter_results(event):
    search_term = search_var.get().lower()
    filtered_results = [client for client in scan_results if
                        search_term in client["ip"].lower() or
                        search_term in client["mac"].lower() or
                        search_term in client["name"].lower()]
    update_tree(filtered_results)

root = Tk()
root.title("LAN Scanner")

Label(root, text="IP Range:").pack(side="top", fill="x", padx=20, pady=5)
ip_entry = Entry(root)
ip_entry.pack(side="top", fill="x", padx=20, expand=True)
ip_entry.insert(0, "192.168.1.1/24")  # 默认值

scan_button = Button(root, text="Scan Network", command=start_scan)
scan_button.pack(side="top", fill="x", padx=20, pady=10)

Label(root, text="Search:").pack(side="top", fill="x", padx=20, pady=5)
search_var = StringVar()
search_entry = Entry(root, textvariable=search_var)
search_entry.pack(side="top", fill="x", padx=20, expand=True)
search_entry.bind("<KeyRelease>", filter_results)

tree = ttk.Treeview(root, columns=("IP", "MAC", "Name"), show="headings")
tree.heading("IP", text="IP Address")
tree.heading("MAC", text="MAC Address")
tree.heading("Name", text="Device Name")
tree.pack(side="top", fill="both", expand=True, padx=20, pady=20)

root.mainloop()
