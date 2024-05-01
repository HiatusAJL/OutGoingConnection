import subprocess
import re
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from functools import lru_cache
import ipinfo
import requests
import psutil 

# Replace with your actual access tokens
ipinfo_access_token = 'your_ipinfo_access_token'
handler = ipinfo.getHandler(ipinfo_access_token)
abuseipdb_key = 'your_abuseipdb_key'

@lru_cache(maxsize=512)
def get_ip_info(ip):
  #"""Fetch IP details using the IPinfo service."""
    try:
        details = handler.getDetails(ip)
        return details.country, details.city, details.region, details.org
    except Exception as e:
        print(f"Failed to fetch IP info: {str(e)}")
        return 'Error', 'Error', 'Error', 'Error'

@lru_cache(maxsize=512)
def check_ip_reputation(ip):
#""Check IP reputation using the AbuseIPDB API."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': abuseipdb_key}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    return data['data']['abuseConfidenceScore'] > 20

def fetch_outgoing_connections():
 #""Fetch current outgoing TCP connections using netstat."""
    result = subprocess.run(['netstat', '-nao'], capture_output=True, text=True)
    pattern = re.compile(r'\s*TCP\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+([\d+\.]+:\d+)\s+ESTABLISHED\s+(\d+)', re.MULTILINE)
    connections = []
    for conn in pattern.findall(result.stdout):
        if not conn[1].startswith("192.168.") and not conn[1].startswith("127."):
            local_address = conn[0]
            remote_address = conn[1].split(':')[0]
            pid = conn[2]
            process_name = get_process_name_by_pid(int(pid))
            connections.append((local_address, remote_address, process_name, pid))
    return connections

def get_process_name_by_pid(pid):
#""Retrieve process name by PID, handle errors gracefully."""
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown or Access Denied"

def treeview_sort_column(tv, col, reverse):
  #""Sort tree column when a column header is clicked."""
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    try:
        l.sort(key=lambda x: int(x[0]), reverse=reverse)
    except ValueError:
        l.sort(key=lambda x: x[0], reverse=reverse)
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)
    tv.heading(col, command=lambda: treeview_sort_column(tv, col, not reverse))

def setup_treeview_sorting(tv, columns):
#""Setup sortable columns for the treeview."""
    for col in columns:
        tv.heading(col, text=col, command=lambda c=col: treeview_sort_column(tv, c, False))

def refresh_treeview():
    #""Refresh the contents of the treeview by re-fetching the connection data."""
    tree.delete(*tree.get_children())  # Clear all current entries in the tree
    connections = fetch_outgoing_connections()  # Fetch new data
    for conn in connections:
        local, remote, process_name, pid = conn
        country, city, region, org = get_ip_info(remote)
        is_malicious = check_ip_reputation(remote)
        malicious_status = "Yes" if is_malicious else "No"
        tree.insert('', 'end', values=(local, remote, country, city, region, org, malicious_status, process_name, pid))


def actual_refresh_treeview():
    #""Command for refresh button to update the treeview."""

    for i in tree.get_children():
        tree.delete(i)
    connections = fetch_outgoing_connections()
    for conn in connections:
        local, remote, process_name, pid = conn
        country, city, region, org = get_ip_info(remote)
        is_malicious = check_ip_reputation(remote)
        malicious_status = "Yes" if is_malicious else "No"
        tree.insert('', 'end', values=(local, remote, country, city, region, org, malicious_status, process_name, pid))

def monitor_connections():
    #""Background thread function to monitor new connections and update GUI."""
    old_connections = set()
    while True:
        current_connections = set(fetch_outgoing_connections())
        new_connections = current_connections.difference(old_connections)
        if new_connections:
            # Schedule the refresh_treeview function to run in the main thread
            root.after(0, refresh_treeview)
        old_connections = current_connections
        time.sleep(10)  # Adjust as necessary for the refresh rate

def on_right_click(event):
    #""Handle the right-click event on a treeview item."""
    tree.selection_set(tree.identify_row(event.y))  # Set selection at the point of right click
    row_id = tree.selection()[0]
    item = tree.item(row_id)
    pid = int(item['values'][8])  # Ensure this index matches the PID column in your tree

    # Define actions for the menu options
    def terminate():
        terminate_process(pid)

    def explore_more():
        # Attempt to open Task Manager focused on the specific PID
        try:
            subprocess.run(f'taskmgr /FI "PID eq {pid}"', check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Task Manager for PID {pid}: {e}")

    # Create a popup menu
    popup_menu = tk.Menu(root, tearoff=0)
    popup_menu.add_command(label="Terminate Process", command=terminate)
    popup_menu.add_command(label="Explore More in Task Manager", command=explore_more)
    
    popup_menu.tk_popup(event.x_root, event.y_root)


def terminate_process(pid):
    #""Terminate the process given its PID using taskkill."""
    try:
        subprocess.run(['taskkill', '/PID', str(pid), '/F'], check=True)
        messagebox.showinfo("Success", f"Process {pid} terminated successfully.")
        refresh_treeview()  # Refresh the treeview to reflect the changes
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to terminate process {pid}: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# GUI setup
root = tk.Tk()
root.title("Outgoing Connections Viewer")
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#333", fieldbackground="#333", foreground="white")
style.configure("Treeview.Heading", background="#555", foreground="white")
frame = ttk.Frame(root, padding="3 3 12 12", style='TFrame')
frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
frame.columnconfigure(0, weight=1)
frame.rowconfigure(0, weight=1)
columns = ('Local Address', 'Remote IP', 'Country', 'City', 'Region', 'Organization', 'Malicious', 'Process Name', 'PID')
tree = ttk.Treeview(frame, columns=columns, show="headings")
setup_treeview_sorting(tree, columns)
tree.grid(column=0, row=0, sticky='nsew')
tree.bind("<Button-3>", on_right_click)
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
frame.columnconfigure(0, weight=1)
frame.rowconfigure(0, weight=1)
tree.columnconfigure(0, weight=1)
tree.rowconfigure(0, weight=1)
refresh_button = ttk.Button(frame, text="Refresh", command=refresh_treeview)
refresh_button.grid(column=0, row=1, sticky='ew', padx=10, pady=10)
monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
monitor_thread.start()
root.mainloop()

