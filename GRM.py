import os
import psutil
import socket
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
import ctypes
import sys
from cryptography.fernet import Fernet

# Suspicious keywords (for highlighting remote access processes)
SUSPICIOUS_KEYWORDS = ["ScreenConnect", "RemoteAccess", "TeamViewer", "AnyDesk", "RDP", "ConnectWise", "2go"]
LOG_FILE = "suspicious_log.enc"
KEY_FILE = "log_key.key"
WHITELISTED_PROCESSES = ["explorer.exe", "svchost.exe", "wininit.exe", "services.exe", "lsass.exe"]
WHITELISTED_IPS = ["127.0.0.1"]

# Generate encryption key if not exists
def generate_key():
    if not os.path.exists(KEY_FILE):
        try:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            print("Key generated and saved.")
        except Exception as e:
            print(f"Error generating key: {e}")

# Load encryption key
def load_key():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

# Encrypt logs
def encrypt_log(message):
    key = load_key()
    if key:
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        try:
            with open(LOG_FILE, "ab") as log:
                log.write(encrypted_message + b"\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")
    else:
        print("No encryption key available.")

# Decrypt logs
def decrypt_logs():
    if not os.path.exists(LOG_FILE):
        return "No logs available."

    key = load_key()
    if not key:
        return "Unable to load encryption key."

    fernet = Fernet(key)
    decrypted_logs = []
    try:
        with open(LOG_FILE, "rb") as log:
            lines = log.readlines()
            for line in lines:
                try:
                    decrypted = fernet.decrypt(line.strip()).decode()
                    decrypted_logs.append(decrypted)
                except Exception as e:
                    print(f"Error decrypting line: {e}")
                    continue
        return "\n".join(decrypted_logs)
    except Exception as e:
        print(f"Error reading log file: {e}")
        return "Error reading log file."

# Function to request admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin():
    if not is_admin():
        # Re-launch the script with admin privileges
        script = sys.argv[0]
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit()

# Common ports and their descriptions
PORT_DESCRIPTIONS = {
    80: "HTTP - Used by web servers to serve web pages.",
    443: "HTTPS - Used for secure web traffic.",
    21: "FTP - Used for file transfers.",
    22: "SSH - Used for secure shell access.",
    25: "SMTP - Used for sending emails.",
    110: "POP3 - Used for receiving emails.",
    143: "IMAP - Used for receiving emails.",
    3389: "RDP - Used for remote desktop access.",
    # Add more ports as needed
}

# Function to get port description
def get_port_description(port):
    return PORT_DESCRIPTIONS.get(port, "Unknown port. Could be used by various applications.")

# Function to get DNS for an IP
def get_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# Function to terminate a process
def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        encrypt_log(f"Terminated process with PID: {pid}")
        messagebox.showinfo("Success", f"Terminated process with PID: {pid}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to terminate process: {e}")

# Function to block IP
def block_ip(ip):
    try:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}',
            shell=True,
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        encrypt_log(f"Blocked IP: {ip}")
        messagebox.showinfo("Success", f"Blocked IP: {ip}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to block IP: {e}")

# Function to unblock IP
def unblock_ip(ip):
    try:
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="Block {ip}"',
            shell=True,
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        encrypt_log(f"Unblocked IP: {ip}")
        messagebox.showinfo("Success", f"Unblocked IP: {ip}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to unblock IP: {e}")

# Function to list blocked IPs
def list_blocked_ips():
    try:
        result = subprocess.run(
            'netsh advfirewall firewall show rule name=all',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        rules = result.stdout.splitlines()
        blocked_ips = []
        for i in range(len(rules)):
            if "Rule Name: Block" in rules[i]:
                ip = rules[i + 4].split(":")[1].strip()
                blocked_ips.append(ip)
        return blocked_ips
    except Exception as e:
        messagebox.showerror("Error", f"Failed to list blocked IPs: {e}")
        return []

# Fetch process explanations
def explain_process(process_name):
    safe_processes = {
        "explorer.exe": "File Explorer, a critical Windows process.",
        "svchost.exe": "Host process for Windows services.",
        "wininit.exe": "Windows Initialization process, essential for system boot.",
        "services.exe": "Manages Windows services.",
        "lsass.exe": "Local Security Authority Subsystem Service, critical for security policies."
    }
    return safe_processes.get(process_name.lower(), "Unknown process. Could be safe or malicious.")

# Search for processes
def search_tree(tree, query):
    for child in tree.get_children():
        values = tree.item(child, "values")
        if any(query.lower() in str(value).lower() for value in values):
            tree.selection_set(child)
            tree.see(child)
            return
    messagebox.showinfo("Search", "No match found.")

# Add context menu to TreeView
def add_context_menu(tree, root):
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Copy Details", command=lambda: copy_details(tree))
    menu.add_command(label="Terminate Process", command=lambda: terminate_selected(tree))
    menu.add_command(label="Block IP", command=lambda: block_selected_ip(tree))
    menu.add_command(label="Unblock IP", command=lambda: unblock_selected_ip(tree))
    menu.add_command(label="Open File Location", command=lambda: open_file_location(tree))

    def show_menu(event):
        if tree.selection():
            menu.post(event.x_root, event.y_root)

    tree.bind("<Button-3>", show_menu)

# Copy selected details
def copy_details(tree):
    selected = tree.selection()
    if selected:
        details = tree.item(selected[0], "values")
        root.clipboard_clear()
        root.clipboard_append(" | ".join(map(str, details)))
        root.update()
        messagebox.showinfo("Copied", "Details copied to clipboard.")

# Terminate selected process
def terminate_selected(tree):
    selected = tree.selection()
    if selected:
        for item in selected:
            pid = int(tree.item(item, "values")[4])
            terminate_process(pid)

# Block selected IP
def block_selected_ip(tree):
    selected = tree.selection()
    if selected:
        for item in selected:
            ip = tree.item(item, "values")[1]
            block_ip(ip)

# Unblock selected IP
def unblock_selected_ip(tree):
    selected = tree.selection()
    if selected:
        for item in selected:
            ip = tree.item(item, "values")[1]
            unblock_ip(ip)

# Open file location
def open_file_location(tree):
    selected = tree.selection()
    if selected:
        for item in selected:
            file_path = tree.item(item, "values")[5]
            if os.path.exists(file_path):
                subprocess.run(f'explorer /select,"{file_path}"', creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                messagebox.showerror("Error", "File path not found.")

# Export logs to plaintext
def export_logs():
    logs = decrypt_logs()
    if logs != "No logs available.":
        with open("suspicious_log_export.txt", "w") as file:
            file.write(logs)
        messagebox.showinfo("Export", "Logs exported to suspicious_log_export.txt")
    else:
        messagebox.showinfo("Export", "No logs to export.")

# Monitor processes and remote connections
def monitor_connections(known_tree, unknown_tree, status_label):
    tracked_connections = {}

    def update():
        status_label.config(text="Scanning processes...")
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                pid = conn.pid

                if remote_ip in WHITELISTED_IPS or pid in tracked_connections:
                    continue

                dns = get_dns(remote_ip)

                # Process details
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                    process_path = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Unknown"
                    process_path = "Unknown"

                # Determine target TreeView
                target_tree = known_tree if process_name.lower() in (p.lower() for p in WHITELISTED_PROCESSES) else unknown_tree

                # Check if process is suspicious
                is_suspicious = any(keyword.lower() in process_name.lower() for keyword in SUSPICIOUS_KEYWORDS)

                if process_name in WHITELISTED_PROCESSES:
                    is_suspicious = False

                # Log suspicious activities
                if is_suspicious:
                    encrypt_log(
                        f"Suspicious process detected: {process_name} (PID: {pid}, IP: {remote_ip}, DNS: {dns}, Port: {remote_port} - {get_port_description(remote_port)})"
                    )

                # Add or update the connection in the GUI
                target_tree.insert(
                    "",
                    "end",
                    values=(
                        process_name,
                        remote_ip,
                        dns,
                        f"{remote_port} - {get_port_description(remote_port)}",
                        pid,
                        process_path,
                        "Suspicious" if is_suspicious else "Normal",
                    ),
                )

                # Track the connection
                tracked_connections[pid] = {
                    "ip": remote_ip,
                    "port": remote_port,
                    "name": process_name,
                }

        status_label.config(text="Idle")
        root.after(5000, update)  # Schedule the next update in 5 seconds

    update()

# Function to perform a quick scan
def quick_scan(known_tree, unknown_tree, status_label):
    status_label.config(text="Performing quick scan...")
    tracked_connections = {}

    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid

            if remote_ip in WHITELISTED_IPS or pid in tracked_connections:
                continue

            dns = get_dns(remote_ip)

            # Process details
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
                process_path = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown"
                process_path = "Unknown"

            # Determine target TreeView
            target_tree = known_tree if process_name.lower() in (p.lower() for p in WHITELISTED_PROCESSES) else unknown_tree

            # Check if process is suspicious
            is_suspicious = any(keyword.lower() in process_name.lower() for keyword in SUSPICIOUS_KEYWORDS)

            if process_name in WHITELISTED_PROCESSES:
                is_suspicious = False

            # Log suspicious activities
            if is_suspicious:
                encrypt_log(
                    f"Suspicious process detected: {process_name} (PID: {pid}, IP: {remote_ip}, DNS: {dns}, Port: {remote_port} - {get_port_description(remote_port)})"
                )

            # Add or update the connection in the GUI
            target_tree.insert(
                "",
                "end",
                values=(
                    process_name,
                    remote_ip,
                    dns,
                    f"{remote_port} - {get_port_description(remote_port)}",
                    pid,
                    process_path,
                    "Suspicious" if is_suspicious else "Normal",
                ),
            )

            # Track the connection
            tracked_connections[pid] = {
                "ip": remote_ip,
                "port": remote_port,
                "name": process_name,
            }

    status_label.config(text="Quick scan completed.")

# GUI application
def start_gui():
    def on_search():
        query = search_entry.get().strip()
        if query:
            search_tree(unknown_tree, query)

    def on_list_blocked_ips():
        blocked_ips = list_blocked_ips()
        if blocked_ips:
            messagebox.showinfo("Blocked IPs", "\n".join(blocked_ips))
        else:
            messagebox.showinfo("Blocked IPs", "No blocked IPs found.")

    def on_quick_scan():
        quick_scan(known_tree, unknown_tree, status_label)

    # Main window
    root = tk.Tk()
    root.title("Security by Dr. Max")
    root.geometry("1200x750")

    # Notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Known processes tab
    known_frame = ttk.Frame(notebook)
    notebook.add(known_frame, text="Known Processes")

    known_columns = ("Process", "IP Address", "DNS", "Port", "PID", "File Path", "Status")
    known_tree = ttk.Treeview(known_frame, columns=known_columns, show="headings", height=20)
    for col in known_columns:
        known_tree.heading(col, text=col)
        known_tree.column(col, width=150 if col != "File Path" else 300)
    known_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    add_context_menu(known_tree, root)

    # Unknown processes tab
    unknown_frame = ttk.Frame(notebook)
    notebook.add(unknown_frame, text="Unknown Processes")

    unknown_columns = ("Process", "IP Address", "DNS", "Port", "PID", "File Path", "Status")
    unknown_tree = ttk.Treeview(unknown_frame, columns=unknown_columns, show="headings", height=20)
    for col in unknown_columns:
        unknown_tree.heading(col, text=col)
        unknown_tree.column(col, width=150 if col != "File Path" else 300)
    unknown_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    add_context_menu(unknown_tree, root)

    # Buttons for actions
    button_frame = tk.Frame(root)
    button_frame.pack(fill=tk.X, padx=10, pady=5)

    search_label = ttk.Label(button_frame, text="Search:")
    search_label.pack(side=tk.LEFT, padx=5)

    search_entry = ttk.Entry(button_frame)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    search_button = ttk.Button(button_frame, text="Search", command=on_search)
    search_button.pack(side=tk.LEFT, padx=5)

    export_button = ttk.Button(button_frame, text="Export Logs", command=export_logs)
    export_button.pack(side=tk.LEFT, padx=5)

    list_blocked_button = ttk.Button(button_frame, text="List Blocked IPs", command=on_list_blocked_ips)
    list_blocked_button.pack(side=tk.LEFT, padx=5)

    quick_scan_button = ttk.Button(button_frame, text="Scan", command=on_quick_scan)
    quick_scan_button.pack(side=tk.LEFT, padx=5)

    # Status bar
    status_label = tk.Label(root, text="Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_label.pack(fill=tk.X, side=tk.BOTTOM)

    # Start monitoring in a separate thread
    monitor_thread = Thread(target=monitor_connections, args=(known_tree, unknown_tree, status_label), daemon=True)
    monitor_thread.start()

    root.mainloop()

if __name__ == "__main__":
    generate_key()
    request_admin()
    start_gui()