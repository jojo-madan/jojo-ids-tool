import os
import time
import json
import smtplib
import threading
import subprocess
import sqlite3
import socket
import platform
import psutil
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ---------------- CONFIGURATION ----------------

# IP addresses considered safe (no alert)
SAFE_IPS = {"127.0.0.1", "192.168.18.10","192.168.18.5", "192.168.18.1"}

# Paths to monitor
FILE_MONITOR_PATH = os.path.expanduser("/home/jojo/Downloads")  # Change as needed
# Email settings (use your real credentials here)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "jojoids12@gmail.com"
EMAIL_PASS = "oxvx ocjb ebqw ezkf"  
EMAIL_RECEIVER = "jojoids12@gmail.com"

# Log file and database file
LOG_FILE = "ids_alerts.log"
DB_FILE = "ids_alerts.db"

# Network interface to sniff, None means default
INTERFACE = None

# ---------------- GLOBAL VARIABLES ----------------

# Store recent alerts in-memory (for session view and filtering)
SESSION_ALERTS = []

# Flag to control IDS running state
ids_running = False

# Watchdog observers for file 
file_observer = None

# Thread handles for monitors
threads = []

# GUI elements for updating alerts live
gui_text = None
gui_root = None
filter_var = None

# Lock for thread-safe updates
alert_lock = threading.Lock()

# ---------------- DATABASE FUNCTIONS ----------------

def init_db():
    """Initialize SQLite DB and create alerts table if not exists."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert_to_db(threat_type, details):
    """Insert a new alert into database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    details_json = json.dumps(details)
    cursor.execute("INSERT INTO alerts (timestamp, threat_type, details) VALUES (?, ?, ?)",
                   (timestamp, threat_type, details_json))
    conn.commit()
    conn.close()

def get_alerts_from_db(limit=100, threat_type=None):
    """Retrieve alerts from DB optionally filtered by threat_type."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if threat_type:
        cursor.execute("SELECT timestamp, threat_type, details FROM alerts WHERE threat_type=? ORDER BY id DESC LIMIT ?", (threat_type, limit))
    else:
        cursor.execute("SELECT timestamp, threat_type, details FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    alerts = []
    for ts, ttype, details in rows:
        try:
            details_obj = json.loads(details)
        except Exception:
            details_obj = details
        alerts.append({"timestamp": ts, "threat_type": ttype, "details": details_obj})
    return alerts

# ---------------- ALERT HANDLING ----------------

def log_alert(alert):
    """
    Log alert to file, DB, send email, store in session and update GUI.
    """
    alert_json = json.dumps(alert)
    # Append to log file
    with open(LOG_FILE, "a") as f:
        f.write(alert_json + "\n")

    # Insert into DB
    insert_alert_to_db(alert["threat_type"], alert["details"])

    # Store in session alerts
    with alert_lock:
        SESSION_ALERTS.append(alert)
        if len(SESSION_ALERTS) > 1000:
            SESSION_ALERTS.pop(0)

    # Print alert on console
    print(f"[!] ALERT: {alert_json}")

    # Send email alert (non-blocking)
    threading.Thread(target=send_email_alert, args=(f"IDS Alert: {alert['threat_type']}", alert_json), daemon=True).start()

    # Update GUI live if running
    if gui_text:
        with alert_lock:
            filter_value = filter_var.get() if filter_var else None
            if filter_value in ("All", None) or alert["threat_type"] == filter_value:
                gui_text.insert(tk.END, f"{alert['timestamp']} [{alert['threat_type']}] {alert['details']}\n")
                gui_text.see(tk.END)

def send_email_alert(subject, body):
    """Send email alert."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

# ---------------- FILE SYSTEM MONITOR ----------------

class FileEventHandler(FileSystemEventHandler):
    """Handles file system events."""

    def on_any_event(self, event):
        event_type = None
        if event.event_type == 'created':
            event_type = "file_created"
        elif event.event_type == 'deleted':
            event_type = "file_deleted"
        elif event.event_type == 'modified':
            event_type = "file_modified"
        elif event.event_type == 'moved':
            event_type = "file_renamed"

        if event_type:
            details = {
                "event": event_type,
                "file": event.src_path if event_type != "file_renamed" else f"{event.src_path} → {event.dest_path}"
            }
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "threat_type": "file_event",
                "details": details
            }
            log_alert(alert)

def start_file_monitor():
    """Start file system monitoring."""
    global file_observer
    file_observer = Observer()
    event_handler = FileEventHandler()
    file_observer.schedule(event_handler, FILE_MONITOR_PATH, recursive=True)
    file_observer.start()
    print(f"[+] File monitor started on: {FILE_MONITOR_PATH}")


# ---------------- NETWORK MONITOR ----------------

def packet_callback(packet):
    """Callback for every sniffed packet, detects common scans and pings."""
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    if src in SAFE_IPS or dst in SAFE_IPS:
        return

    alert = None

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        if icmp.type == 8:  # echo-request (ping)
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "threat_type": "icmp_ping",
                "details": {"source_ip": src, "destination_ip": dst, "type": "icmp_echo_request"}
            }
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.flags
        print(f"[DEBUG] TCP Flags: {flags} from {src} -> {dst}")
        if flags == 0x02:  # SYN only
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "threat_type": "syn_scan",
                "details": {"source_ip": src, "destination_ip": dst, "flags": str(flags)}
            }
        elif flags == 0x12:  # SYN+ACK
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "threat_type": "tcp_port_scan",
                "details": {"source_ip": src, "destination_ip": dst, "flags": str(flags)}
            }

    elif packet.haslayer(UDP):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_type": "udp_scan",
            "details": {"source_ip": src, "destination_ip": dst}
        }

    if alert:
        log_alert(alert)

def start_network_monitor():
    """Start network packet sniffing with a stop condition."""
    print("[+] Starting network monitor...")
    sniff(prn=packet_callback, iface=INTERFACE, store=False,
          stop_filter=lambda pkt: not ids_running)

# ---------------- SSH LOGIN MONITOR ----------------

def monitor_ssh_logins():
    """Monitor SSH login attempts using journalctl."""
    seen = set()
    while ids_running:
        try:
            proc = subprocess.Popen(
                ['journalctl', '-u', 'ssh', '--since', '10 minutes ago', '--no-pager'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output, _ = proc.communicate()

            for line in output.splitlines():
                if line not in seen and ("Accepted password for" in line or "Failed password for" in line):
                    seen.add(line)
                    alert = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "threat_type": "ssh_login_attempt",
                        "details": {"log_entry": line.strip()}
                    }
                    log_alert(alert)
        except Exception as e:
            print(f"[!] SSH login monitor error: {e}")

        time.sleep(5)

# ---------------- USER LOGIN/LOGOUT MONITOR ----------------
def monitor_user_logins():
    """Monitor user logins and 'su'/'sudo' events via loginctl and journalctl."""
    seen_sessions = {}
    seen_logins = set()

    while ids_running:
        try:
            output = subprocess.check_output(['loginctl', 'list-sessions', '--no-legend'], text=True)
            current_sessions = {}

            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 2:
                    session_id, user = parts[0], parts[1]
                    current_sessions[session_id] = user

                    if session_id not in seen_sessions:
                        seen_sessions[session_id] = user
                        alert = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "threat_type": "user_login",
                            "details": {"user": user, "session_id": session_id}
                        }
                        log_alert(alert)

            for session_id in set(seen_sessions) - set(current_sessions):
                alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "threat_type": "user_logout",
                    "details": {
                        "session_id": session_id,
                        "user": seen_sessions[session_id]
                    }
                }
                log_alert(alert)
                del seen_sessions[session_id]

        except Exception as e:
            print(f"[!] User login monitor error: {e}")

        # Monitor su and sudo
        try:
            output = subprocess.check_output(
                ["journalctl", "_COMM=sudo", "_COMM=su", "--since", "2 minutes ago", "--no-pager"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            for line in output.strip().split('\n'):
                if line and line not in seen_logins:
                    seen_logins.add(line)
                    alert = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "threat_type": "privilege_escalation_attempt",
                        "details": {"log": line.strip()}
                    }
                    log_alert(alert)
        except Exception as e:
            print(f"[!] sudo/su monitor error: {e}")

        time.sleep(5)


# ---------------- SYSTEM INFO ----------------

def get_system_info():
    """Return system info as formatted string."""
    info = {
        "Hostname": socket.gethostname(),
        "IP Address": socket.gethostbyname(socket.gethostname()),
        "OS": platform.system(),
        "OS Version": platform.version(),
        "CPU": platform.processor(),
        "RAM": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB"
    }
    return json.dumps(info, indent=4)

# ---------------- IDS CONTROL ----------------

def start_all_monitors():
    """Start all IDS monitoring threads and observers."""
    global ids_running, threads
    ids_running = True

    # Start file monitor observer
    start_file_monitor()

    # Start SSH login monitor thread
    t_ssh = threading.Thread(target=monitor_ssh_logins, daemon=True)
    t_ssh.start()
    threads.append(t_ssh)

    # Start user login monitor thread
    t_user = threading.Thread(target=monitor_user_logins, daemon=True)
    t_user.start()
    threads.append(t_user)

    # Start network monitor thread
    t_net = threading.Thread(target=start_network_monitor, daemon=True)
    t_net.start()
    threads.append(t_net)

def stop_all_monitors():
    """Stop all IDS monitoring threads and observers."""
    global ids_running, file_observer, usb_observer

    ids_running = False

    # Stop watchdog observers
    if file_observer:
        file_observer.stop()
        file_observer.join()
    alert = {"timestamp": datetime.utcnow().isoformat(), "threat_type": "info", "details": "IDS has been stopped by the user."}
    log_alert(alert)

    print("[*] IDS stopped.")

# ---------------- GUI ----------------

def gui_start_ids():
    if not ids_running:
        start_all_monitors()
        messagebox.showinfo("IDS", "Intrusion Detection System started.")
    else:
        messagebox.showwarning("IDS", "IDS is already running.")

def gui_stop_ids():
    if ids_running:
        stop_all_monitors()
        messagebox.showinfo("IDS", "Intrusion Detection System stopped.")
    else:
        messagebox.showwarning("IDS", "IDS is not running.")

def gui_clear_logs():
    if gui_text:
        gui_text.delete('1.0', tk.END)

def gui_show_system_info():
    info = get_system_info()
    messagebox.showinfo("System Information", info)

def gui_load_db_alerts():
    """Load recent alerts from DB and display in GUI."""
    if not gui_text:
        return
    gui_text.delete('1.0', tk.END)
    threat_type = filter_var.get()
    if threat_type == "All":
        threat_type = None
    alerts = get_alerts_from_db(limit=100, threat_type=threat_type)
    for alert in reversed(alerts):  # oldest first
        gui_text.insert(tk.END, f"{alert['timestamp']} [{alert['threat_type']}] {alert['details']}\n")

def gui_load_session_alerts():
    """Load recent alerts from current session and display in GUI."""
    if not gui_text:
        return
    gui_text.delete('1.0', tk.END)
    threat_type = filter_var.get()
    with alert_lock:
        filtered = [a for a in SESSION_ALERTS if (threat_type == "All" or a['threat_type'] == threat_type)]
    for alert in filtered:
        gui_text.insert(tk.END, f"{alert['timestamp']} [{alert['threat_type']}] {alert['details']}\n")

def on_filter_change(event=None):
    """Handle filter dropdown change - refresh alert view."""
    # By default show session alerts live filtered
    gui_load_session_alerts()

def build_gui():
    global gui_root, gui_text, filter_var

    gui_root = tk.Tk()
    gui_root.title("Intrusion Detection System (IDS)")
    gui_root.geometry("900x600")

    # Frame for buttons and filter
    top_frame = tk.Frame(gui_root)
    top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    # Start IDS button
    start_btn = tk.Button(top_frame, text="Start IDS", command=gui_start_ids)
    start_btn.pack(side=tk.LEFT, padx=5)

    # Stop IDS button
    stop_btn = tk.Button(top_frame, text="Stop IDS", command=gui_stop_ids)
    stop_btn.pack(side=tk.LEFT, padx=5)

    # Clear logs button
    clear_btn = tk.Button(top_frame, text="Clear Display", command=gui_clear_logs)
    clear_btn.pack(side=tk.LEFT, padx=5)

    # Show system info button
    sysinfo_btn = tk.Button(top_frame, text="System Info", command=gui_show_system_info)
    sysinfo_btn.pack(side=tk.LEFT, padx=5)

    # Load DB alerts button
    db_btn = tk.Button(top_frame, text="Latest 100 Alerts", command=gui_load_db_alerts)
    db_btn.pack(side=tk.LEFT, padx=5)

    # Dropdown filter for alert types
    filter_var = tk.StringVar(gui_root)
    filter_options = ["All", "file_event",
                      "icmp_ping", "syn_flood", "tcp_port_scan", "udp_scan",
                      "ssh_login_attempt", "user_login", "user_logout"]
    filter_var.set("All")  # default
    filter_label = tk.Label(top_frame, text="Filter Alerts:")
    filter_label.pack(side=tk.LEFT, padx=10)
    filter_dropdown = ttk.Combobox(top_frame, textvariable=filter_var, values=filter_options, state="readonly")
    filter_dropdown.pack(side=tk.LEFT)
    filter_dropdown.bind("<<ComboboxSelected>>", on_filter_change)

    # Text area for alerts display
    gui_text = scrolledtext.ScrolledText(gui_root, width=110, height=30, state=tk.NORMAL)
    gui_text.pack(padx=10, pady=10)

    # Load session alerts initially
    gui_load_session_alerts()

    gui_root.protocol("WM_DELETE_WINDOW", on_close)

    gui_root.mainloop()

def on_close():
    """Clean up before closing GUI."""
    if ids_running:
        if messagebox.askyesno("Exit", "IDS is running. Stop it before exit?"):
            gui_stop_ids()
            gui_root.destroy()
        else:
            # Ignore close
            return
    else:
        gui_root.destroy()

# ---------------- MAIN ----------------

if __name__ == "__main__":
    print("[*] Initializing IDS...")
    init_db()
    build_gui()
