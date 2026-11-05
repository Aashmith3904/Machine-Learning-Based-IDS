import tkinter as tk
import customtkinter
from scapy.all import sniff, IP, TCP, UDP
import pickle
import threading
import datetime
import queue
import time
import sys
import os
import winreg
import math
import argparse

try:
    import pystray
    from PIL import Image, ImageDraw
    _TRAY_AVAILABLE = True
except ImportError:
    _TRAY_AVAILABLE = False

# ── Detect launch mode ───────────────────────────────────────
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--minimized", action="store_true",
                     help="Start minimized to system tray (used on auto-startup)")
_ARGS, _ = _parser.parse_known_args()
LAUNCH_MINIMIZED = _ARGS.minimized

try:
    from plyer import notification
except ImportError:
    notification = None

last_notification_time = 0

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
    model_dir = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))
    model_dir = application_path

MODEL_PATH = os.path.join(model_dir, "ids_model.pkl")
LOG_DIR = os.path.join(application_path, "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
current_log_path = None

try:
    class IDS:
        def __init__(self, cic_model, cic_scaler):
            self.cic_model = cic_model
            self.cic_scaler = cic_scaler

        def predict(self, X, format_type='cic'):
            if format_type.lower() == 'cic':
                X_scaled = self.cic_scaler.transform(X)
                return self.cic_model.predict(X_scaled)
            else:
                raise ValueError("format_type must be 'cic'")

    model = pickle.load(open(MODEL_PATH, "rb"))
except Exception as e:
    import traceback
    print("Error loading model:", e)
    traceback.print_exc()
    sys.exit(1)

running = False
total_packets = 0
intrusion_count = 0
normal_count = 0
packet_queue = queue.Queue()

active_flows = {}
# {src_ip: [(timestamp, dst_port), ...]}  — sliding-window port-scan tracker
src_scan_events = {}          # keyed by src_ip
PORTSCAN_WINDOW   = 10.0      # seconds to look back for scan detection
PORTSCAN_THRESHOLD = 15       # unique dst ports within window = scan
SYNFLOOD_PPS      = 200       # SYN pps threshold for flood detection
_last_flow_cleanup = time.time()
FLOW_EXPIRY_SEC = 120         # expire flows older than this

# RFC-1918 private ranges — we only flag port scans FROM external IPs
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "127.", "169.254.")

def _is_private(ip):
    return ip.startswith(_PRIVATE_PREFIXES)

def _maybe_expire_flows():
    """Periodically remove stale flows and old scan events."""
    global _last_flow_cleanup
    now = time.time()
    if now - _last_flow_cleanup < FLOW_EXPIRY_SEC:
        return
    cutoff = now - FLOW_EXPIRY_SEC
    stale = [k for k, v in active_flows.items() if v['last_seen'] < cutoff]
    for k in stale:
        del active_flows[k]
    # also prune old scan events
    for ip in list(src_scan_events):
        src_scan_events[ip] = [(t, p) for t, p in src_scan_events[ip]
                               if now - t < PORTSCAN_WINDOW * 2]
        if not src_scan_events[ip]:
            del src_scan_events[ip]
    _last_flow_cleanup = now


def extract_features(packet):
    global active_flows, src_port_counts

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        packet_length = len(packet)
        ip_header_len = packet[IP].ihl * 4

        protocol_type = packet[IP].proto
        protocol_name = packet[IP].sprintf("%IP.proto%")

        src_port = 0
        dst_port = 0
        tcp_flags_F = 0
        tcp_flags_S = 0
        tcp_flags_R = 0
        tcp_flags_P = 0
        tcp_flags_A = 0
        tcp_flags_U = 0
        header_len = ip_header_len
        window = 0

        if TCP in packet:
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            header_len += packet[TCP].dataofs * 4
            window = packet[TCP].window

            flags = packet[TCP].flags
            if 'F' in flags: tcp_flags_F = 1
            if 'S' in flags: tcp_flags_S = 1
            if 'R' in flags: tcp_flags_R = 1
            if 'P' in flags: tcp_flags_P = 1
            if 'A' in flags: tcp_flags_A = 1
            if 'U' in flags: tcp_flags_U = 1

            # Port-scan detection: track inbound SYNs from external IPs only
            # (avoids flagging your own outbound browsing)
            if tcp_flags_S and not tcp_flags_A and not _is_private(src_ip):
                now_t = time.time()
                events = src_scan_events.setdefault(src_ip, [])
                events.append((now_t, dst_port))
                # prune events outside the window
                src_scan_events[src_ip] = [(t, p) for t, p in events
                                           if now_t - t < PORTSCAN_WINDOW]

        elif UDP in packet:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            header_len += 8

        # Per-flow key: bidirectional aggregation (normalise direction)
        key = (min(src_ip, dst_ip), max(src_ip, dst_ip),
               min(src_port, dst_port), max(src_port, dst_port),
               protocol_type)
        now = time.time()

        if key not in active_flows:
            active_flows[key] = {
                'start_time': now,
                'last_seen':  now,
                'count': 1,
                'total_len': packet_length,
                'max_len': packet_length,
                'min_len': packet_length,
                'sq_len': packet_length ** 2
            }
        else:
            flow = active_flows[key]
            flow['count'] += 1
            flow['last_seen'] = now
            flow['total_len'] += packet_length
            flow['max_len'] = max(flow['max_len'], packet_length)
            flow['min_len'] = min(flow['min_len'], packet_length)
            flow['sq_len'] += packet_length ** 2

        flow = active_flows[key]
        duration = now - flow['start_time']
        duration_micros = duration * 1_000_000
        mean_len = flow['total_len'] / flow['count']

        var_len = (flow['sq_len'] / flow['count']) - (mean_len ** 2)
        std_len = math.sqrt(max(var_len, 0))

        bytes_per_sec = flow['total_len'] / duration if duration > 0 else 0
        pkts_per_sec  = flow['count']     / duration if duration > 0 else 0

        # Unique dst ports from this src in the sliding window
        scan_events = src_scan_events.get(src_ip, [])
        now_t = time.time()
        unique_dst_ports = len({p for t, p in scan_events
                                if now_t - t < PORTSCAN_WINDOW})

        features = [0] * 80
        features[0]  = src_port
        features[1]  = dst_port
        features[2]  = protocol_type
        features[3]  = duration_micros
        features[4]  = flow['count']
        features[5]  = unique_dst_ports          # NEW: unique scanned ports
        features[6]  = flow['total_len']
        features[8]  = flow['max_len']
        features[9]  = flow['min_len']
        features[10] = mean_len
        features[11] = std_len
        features[16] = bytes_per_sec
        features[17] = pkts_per_sec
        features[36] = header_len * flow['count']
        features[41] = flow['max_len']
        features[42] = mean_len
        features[43] = std_len
        features[44] = var_len
        # TCP flags
        features[45] = tcp_flags_F
        features[46] = tcp_flags_S
        features[47] = tcp_flags_R
        features[48] = tcp_flags_P
        features[49] = tcp_flags_A
        features[50] = tcp_flags_U
        features[54] = mean_len
        features[68] = window

        _maybe_expire_flows()

        return features, src_ip, dst_ip, protocol_name

    return None

def analyze_packet(packet):
    if not running:
        return
    
    result = extract_features(packet)
    if result:
        packet_queue.put(result)

def process_packet_batch():
    global total_packets, intrusion_count, normal_count, last_notification_time
    
    while True:
        if not running:
            time.sleep(0.1)
            continue
            
        batch_features = []
        batch_meta = []
        try:
            while len(batch_features) < 100:     
                features, src_ip, dst_ip, protocol_name = packet_queue.get(block=True, timeout=0.1)
                batch_features.append(features)
                batch_meta.append((src_ip, dst_ip, protocol_name))
        except queue.Empty:
            pass
            
        if batch_features:
            total_packets += len(batch_features)
            
            predictions = model.predict(batch_features)
            
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            messages = []
            
            for i, (pred, meta) in enumerate(zip(predictions, batch_meta)):
                src_ip, dst_ip, protocol_name = meta
                features = batch_features[i]
                
                is_intrusion = False
                attack_type = "Unknown Anomaly"
                
                if pred != 0:
                    is_intrusion = True
                    attack_type = f"ML_Predicted_Class_{pred}"

                # UDP Flood: high packet-rate OR high byte-rate, and enough samples
                elif protocol_name == "UDP" and features[4] > 50 and (
                        features[17] > 100 or features[16] > 100_000):
                    is_intrusion = True
                    attack_type = "UDP Flood Signature"

                # Port Scan: >=THRESHOLD unique dst ports in sliding window
                # (only fires for external src IPs — see extract_features)
                elif protocol_name == "TCP" and features[46] == 1 and features[5] >= PORTSCAN_THRESHOLD:
                    is_intrusion = True
                    attack_type = "TCP Port Scan (SYN)"

                # Anomalous flags: FIN+PSH+URG together (XMAS / Slowloris probe)
                elif protocol_name == "TCP" and (
                        features[45] == 1 and features[48] == 1 and features[50] == 1):
                    is_intrusion = True
                    attack_type = "TCP Anomalous Flags (XMAS/Slowloris)"

                # SYN Flood: very high SYN rate AND no ACK (not a normal handshake reply)
                elif (protocol_name == "TCP" and features[46] == 1
                      and features[49] == 0 and features[17] > SYNFLOOD_PPS):
                    is_intrusion = True
                    attack_type = "DoS SYN Flood Signature"
                    
                
                if is_intrusion:
                    intrusion_count += 1
                    messages.append((f"[{timestamp}] ⚠ {attack_type} Detected! Src: {src_ip}, Dst: {dst_ip}, Proto: {protocol_name}\n", True))
                    
                    current_time = time.time()
                    if notification and (current_time - last_notification_time > 5):
                        last_notification_time = current_time
                        try:
                            def show_notification(sip, dip, proto):
                                try:
                                    notification.notify(
                                        title="⚠ Intrusion Detected!",
                                        message=f"Source: {sip}\nDest: {dip}\nProtocol: {proto}",
                                        app_name="ML_IDS",
                                        timeout=5
                                    )
                                except Exception as e:
                                    print(f"Notification error: {e}")
                            threading.Thread(target=show_notification, args=(src_ip, dst_ip, protocol_name), daemon=True).start()
                        except Exception as e:
                            print(f"Thread error: {e}")
                else:
                    normal_count += 1
                    messages.append((f"[{timestamp}] Normal Traffic | Src: {src_ip}, Dst: {dst_ip}, Proto: {protocol_name}\n", False))

            if messages:
                # Schedule each message individually so the GUI can tag them correctly
                for msg_text, msg_is_intrusion in messages:
                    root.after(0, update_gui, msg_text, msg_is_intrusion)

def start_ids():
    global running, current_log_path
    if not running:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        current_log_path = os.path.join(LOG_DIR, f"ids_traffic_{timestamp}.log")

    running = True
    threading.Thread(target=lambda: sniff(prn=analyze_packet, store=False), daemon=True).start()
    threading.Thread(target=process_packet_batch, daemon=True).start()

def stop_ids():
    global running
    running = False


# update_gui is defined below in the GUI section (uses new widgets)

def check_startup():
    key = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "ML_IDS"
    try:
        registry_key = winreg.OpenKey(key, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(registry_key, app_name)
        winreg.CloseKey(registry_key)
        return "on"
    except FileNotFoundError:
        return "off"

def toggle_startup():
    key = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "ML_IDS"
    if getattr(sys, 'frozen', False):
        # Running as compiled .exe — pass --minimized flag
        app_path = f'"{sys.executable}" --minimized'
    else:
        # Running as script
        app_path = f'"{sys.executable}" "{os.path.abspath(__file__)}" --minimized'
    
    try:
        registry_key = winreg.OpenKey(key, key_path, 0, winreg.KEY_ALL_ACCESS)
        if startup_var.get() == "on":
            winreg.SetValueEx(registry_key, app_name, 0, winreg.REG_SZ, app_path)
        else:
            try:
                winreg.DeleteValue(registry_key, app_name)
            except FileNotFoundError:
                pass
        winreg.CloseKey(registry_key)
    except Exception as e:
        print(f"Failed to modify startup registry: {e}")

# ─────────────────────────────────────────────────────────────
#  THEME & WINDOW
# ─────────────────────────────────────────────────────────────
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

BG        = "#0f1117"
SURFACE   = "#1a1d27"
SURFACE2  = "#22263a"
ACCENT    = "#4f8ef7"
ACCENT2   = "#6c63ff"
RED       = "#e05252"
GREEN     = "#3ecf82"
MUTED     = "#8892a4"
TEXT      = "#e8ecf4"
SIDEBAR_W = 200

root = customtkinter.CTk()
root.title("ML-IDS — Intrusion Detection System")
root.geometry("980x640")
root.minsize(820, 560)
root.configure(fg_color=BG)

# ─────────────────────────────────────────────────────────────
#  ROOT LAYOUT  —  sidebar | content
# ─────────────────────────────────────────────────────────────
outer = customtkinter.CTkFrame(root, fg_color=BG, corner_radius=0)
outer.pack(fill="both", expand=True)
outer.grid_columnconfigure(1, weight=1)
outer.grid_rowconfigure(0, weight=1)

# ── SIDEBAR ──────────────────────────────────────────────────
sidebar = customtkinter.CTkFrame(outer, width=SIDEBAR_W, fg_color=SURFACE,
                                 corner_radius=0)
sidebar.grid(row=0, column=0, sticky="nsew")
sidebar.grid_propagate(False)
sidebar.grid_rowconfigure(8, weight=1)   # pushes bottom items down

# Brand / logo row
brand_frame = customtkinter.CTkFrame(sidebar, fg_color=SURFACE2, corner_radius=0)
brand_frame.grid(row=0, column=0, sticky="ew", pady=(0, 2))
customtkinter.CTkLabel(
    brand_frame, text="🛡 ML-IDS",
    font=customtkinter.CTkFont(size=18, weight="bold"),
    text_color=TEXT
).pack(pady=16, padx=16, anchor="w")

customtkinter.CTkLabel(
    sidebar, text="NAVIGATION",
    font=customtkinter.CTkFont(size=10, weight="bold"),
    text_color=MUTED
).grid(row=1, column=0, sticky="w", padx=18, pady=(18, 4))

# ── content area host ────────────────────────────────────────
content_host = customtkinter.CTkFrame(outer, fg_color=BG, corner_radius=0)
content_host.grid(row=0, column=1, sticky="nsew")
content_host.grid_rowconfigure(0, weight=1)
content_host.grid_columnconfigure(0, weight=1)

# Two "pages" stacked; only one visible at a time
page_dashboard = customtkinter.CTkFrame(content_host, fg_color=BG, corner_radius=0)
page_settings  = customtkinter.CTkFrame(content_host, fg_color=BG, corner_radius=0)

def show_page(page):
    page_dashboard.grid_forget()
    page_settings.grid_forget()
    page.grid(row=0, column=0, sticky="nsew")

# ── sidebar nav buttons ──────────────────────────────────────
_NAV_BTN_COMMON = dict(
    anchor="w", width=SIDEBAR_W - 4, height=40, corner_radius=8,
    font=customtkinter.CTkFont(size=13),
    border_spacing=10
)

btn_dashboard = customtkinter.CTkButton(
    sidebar, text="  📊  Dashboard",
    command=lambda: show_page(page_dashboard),
    fg_color=ACCENT2, text_color=TEXT, hover_color=ACCENT,
    **_NAV_BTN_COMMON
)
btn_dashboard.grid(row=2, column=0, padx=8, pady=3, sticky="ew")

btn_settings = customtkinter.CTkButton(
    sidebar, text="  ⚙  Settings",
    command=lambda: show_page(page_settings),
    fg_color="transparent", text_color=MUTED, hover_color=SURFACE2,
    **_NAV_BTN_COMMON
)
btn_settings.grid(row=3, column=0, padx=8, pady=3, sticky="ew")

customtkinter.CTkLabel(
    sidebar, text="CONTROLS",
    font=customtkinter.CTkFont(size=10, weight="bold"),
    text_color=MUTED
).grid(row=6, column=0, sticky="w", padx=18, pady=(18, 4))

# ─────────────────────────────────────────────────────────────
#  START / STOP  logic (must come before sidebar buttons)
# ─────────────────────────────────────────────────────────────
def _start_ids():
    start_ids()
    status_pill.configure(text="  ●  RUNNING", fg_color="#1a3a2a", text_color=GREEN)
    btn_start_sb.configure(state="disabled", fg_color="#1a3a2a")
    btn_stop_sb.configure(state="normal",  fg_color=RED, hover_color="#c0392b")

def _stop_ids():
    stop_ids()
    status_pill.configure(text="  ●  STOPPED", fg_color="#2d1a1a", text_color=RED)
    btn_start_sb.configure(state="normal",  fg_color=GREEN, hover_color="#2ecc71")
    btn_stop_sb.configure(state="disabled", fg_color="#2d1a1a")

btn_start_sb = customtkinter.CTkButton(
    sidebar, text="▶ Start IDS", command=_start_ids,
    fg_color=GREEN, hover_color="#2ecc71", text_color="#0a1f14",
    **_NAV_BTN_COMMON
)
btn_start_sb.grid(row=7, column=0, padx=8, pady=3, sticky="ew")

btn_stop_sb = customtkinter.CTkButton(
    sidebar, text="■ Stop IDS", command=_stop_ids,
    fg_color="#2d1a1a", text_color=MUTED, hover_color="#c0392b",
    state="disabled",
    **_NAV_BTN_COMMON
)
btn_stop_sb.grid(row=8, column=0, padx=8, pady=(3, 18), sticky="ew")

# ═════════════════════════════════════════════════════════════
#  DASHBOARD PAGE
# ═════════════════════════════════════════════════════════════
page_dashboard.grid_columnconfigure(0, weight=1)
page_dashboard.grid_rowconfigure(2, weight=1)

# ── HEADER ROW ───────────────────────────────────────────────
header = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE, corner_radius=0, height=58)
header.grid(row=0, column=0, sticky="ew")
header.grid_propagate(False)
header.grid_columnconfigure(1, weight=1)

customtkinter.CTkLabel(
    header, text="Real-Time Network Monitor",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).grid(row=0, column=0, padx=20, pady=16, sticky="w")

status_pill = customtkinter.CTkLabel(
    header, text="  ●  STOPPED",
    font=customtkinter.CTkFont(size=12, weight="bold"),
    fg_color="#2d1a1a", text_color=RED,
    corner_radius=20, padx=14, pady=5
)
status_pill.grid(row=0, column=2, padx=20, pady=16, sticky="e")

# ── STAT CARDS ────────────────────────────────────────────────
cards_row = customtkinter.CTkFrame(page_dashboard, fg_color=BG)
cards_row.grid(row=1, column=0, sticky="ew", padx=18, pady=12)
cards_row.grid_columnconfigure((0, 1, 2), weight=1)

def _make_card(parent, col, label, color, attr_name):
    card = customtkinter.CTkFrame(parent, fg_color=SURFACE, corner_radius=12)
    card.grid(row=0, column=col, padx=6, pady=0, sticky="ew")
    customtkinter.CTkLabel(
        card, text=label.upper(),
        font=customtkinter.CTkFont(size=10, weight="bold"),
        text_color=MUTED
    ).pack(anchor="w", padx=16, pady=(14, 2))
    num_lbl = customtkinter.CTkLabel(
        card, text="0",
        font=customtkinter.CTkFont(size=32, weight="bold"),
        text_color=color
    )
    num_lbl.pack(anchor="w", padx=16, pady=(0, 14))
    return num_lbl

card_total     = _make_card(cards_row, 0, "Total Packets",      TEXT,  "total")
card_normal    = _make_card(cards_row, 1, "Normal Traffic",     GREEN, "normal")
card_intrusion = _make_card(cards_row, 2, "Intrusions Detected", RED,  "intrusion")

# ── LOG AREA ─────────────────────────────────────────────────
log_outer = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE, corner_radius=12)
log_outer.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 8))
log_outer.grid_rowconfigure(1, weight=1)
log_outer.grid_columnconfigure(0, weight=1)

log_header = customtkinter.CTkFrame(log_outer, fg_color=SURFACE2, corner_radius=0, height=34)
log_header.grid(row=0, column=0, sticky="ew")
log_header.grid_propagate(False)
log_header.grid_columnconfigure(1, weight=1)
customtkinter.CTkLabel(
    log_header, text="  EVENT LOG",
    font=customtkinter.CTkFont(size=11, weight="bold"),
    text_color=MUTED
).grid(row=0, column=0, sticky="w", padx=12, pady=7)

log_area = customtkinter.CTkTextbox(
    log_outer, corner_radius=0, wrap="none",
    font=customtkinter.CTkFont(family="Consolas", size=12),
    fg_color=SURFACE, text_color=TEXT,
    scrollbar_button_color=SURFACE2,
    scrollbar_button_hover_color=ACCENT
)
log_area.grid(row=1, column=0, sticky="nsew", padx=2, pady=(0, 2))

# colour tags for the underlying tk.Text widget
log_area._textbox.tag_configure("intrusion", foreground=RED)
log_area._textbox.tag_configure("normal",    foreground="#6b7a90")

# ── FOOTER ───────────────────────────────────────────────────
footer = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE2, corner_radius=0, height=26)
footer.grid(row=3, column=0, sticky="ew")
footer.grid_propagate(False)
footer_label = customtkinter.CTkLabel(
    footer, text="IDS not running",
    font=customtkinter.CTkFont(size=10), text_color=MUTED
)
footer_label.pack(side="left", padx=14, pady=4)

# ═════════════════════════════════════════════════════════════
#  SETTINGS PAGE
# ═════════════════════════════════════════════════════════════
page_settings.grid_columnconfigure(0, weight=1)

# Settings header
s_header = customtkinter.CTkFrame(page_settings, fg_color=SURFACE, corner_radius=0, height=58)
s_header.grid(row=0, column=0, sticky="ew")
s_header.grid_propagate(False)
customtkinter.CTkLabel(
    s_header, text="Settings",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).grid(row=0, column=0, padx=20, pady=16, sticky="w")

s_scroll = customtkinter.CTkScrollableFrame(page_settings, fg_color=BG, corner_radius=0)
s_scroll.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
page_settings.grid_rowconfigure(1, weight=1)
s_scroll.grid_columnconfigure(0, weight=1)

def _section_label(parent, row, text):
    customtkinter.CTkLabel(
        parent, text=text,
        font=customtkinter.CTkFont(size=10, weight="bold"),
        text_color=MUTED
    ).grid(row=row, column=0, sticky="w", padx=26, pady=(22, 6))

def _setting_card(parent, row, title, description, widget_fn):
    card = customtkinter.CTkFrame(parent, fg_color=SURFACE, corner_radius=12)
    card.grid(row=row, column=0, sticky="ew", padx=18, pady=4)
    card.grid_columnconfigure(0, weight=1)
    txt = customtkinter.CTkFrame(card, fg_color="transparent")
    txt.grid(row=0, column=0, sticky="w", padx=18, pady=14)
    customtkinter.CTkLabel(
        txt, text=title,
        font=customtkinter.CTkFont(size=13, weight="bold"), text_color=TEXT
    ).pack(anchor="w")
    customtkinter.CTkLabel(
        txt, text=description,
        font=customtkinter.CTkFont(size=11), text_color=MUTED
    ).pack(anchor="w", pady=(2, 0))
    w = widget_fn(card)
    w.grid(row=0, column=1, padx=18, pady=14, sticky="e")
    return card

# Appearance
_section_label(s_scroll, 0, "APPEARANCE")
def change_appearance_mode_event(new_appearance_mode: str):
    customtkinter.set_appearance_mode(new_appearance_mode)

theme_optionemenu = customtkinter.CTkOptionMenu(
    s_scroll, values=["Dark", "Light", "System"],
    command=change_appearance_mode_event,
    fg_color=SURFACE2, button_color=ACCENT, button_hover_color=ACCENT2,
    width=140
)
_setting_card(s_scroll, 1,
    "Appearance Mode",
    "Choose Dark, Light, or follow the system setting.",
    lambda p: customtkinter.CTkOptionMenu(p,
        values=["Dark", "Light", "System"],
        command=change_appearance_mode_event,
        fg_color=SURFACE2, button_color=ACCENT, button_hover_color=ACCENT2,
        width=140)
)
# Grab the actual widget from the last card to call .set()
# (We rebuild cleanly inside card so theme_optionemenu is the real one)
theme_optionemenu.set("Dark")

# Startup
_section_label(s_scroll, 2, "SYSTEM")
startup_var = customtkinter.StringVar(value=check_startup())
_setting_card(s_scroll, 3,
    "Run at Startup",
    "Automatically launch ML-IDS when Windows starts.",
    lambda p: customtkinter.CTkSwitch(p,
        text="", command=toggle_startup,
        variable=startup_var, onvalue="on", offvalue="off",
        progress_color=GREEN, button_color=TEXT)
)

# ─────────────────────────────────────────────────────────────
#  OVERRIDE update_gui / start_ids / stop_ids for new widgets
# ─────────────────────────────────────────────────────────────
def update_gui(message, is_intrusion=False):
    tag = "intrusion" if is_intrusion else "normal"
    log_area._textbox.insert(tk.END, message, tag)
    log_area._textbox.see(tk.END)

    card_total.configure(text=str(total_packets))
    card_normal.configure(text=str(normal_count))
    card_intrusion.configure(text=str(intrusion_count))

    start_time_str = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    path_str = f"  |  Log: {current_log_path}" if current_log_path else ""
    footer_label.configure(text=f"Last event: {start_time_str}{path_str}")

    try:
        if current_log_path:
            with open(current_log_path, "a", encoding="utf-8") as f:
                f.write(message)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
#  SYSTEM TRAY
# ─────────────────────────────────────────────────────────────
_tray_icon = None

def _build_tray_image(size=64):
    """Create a simple shield icon for the tray."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Background circle
    draw.ellipse([2, 2, size - 2, size - 2], fill=(26, 29, 39, 255))
    # Shield body
    half = size // 2
    pts = [
        (half, 6), (size - 8, 16), (size - 8, half),
        (half, size - 6), (8, half), (8, 16)
    ]
    draw.polygon(pts, fill=(79, 142, 247, 255))
    # Accent stripe
    draw.polygon([
        (half, 14), (size - 12, 22), (size - 12, half),
        (half, size - 12)
    ], fill=(108, 99, 255, 200))
    return img

def _show_window():
    root.after(0, lambda: (root.deiconify(), root.lift(), root.focus_force()))

def _hide_window():
    root.after(0, root.withdraw)

def _tray_on_show(icon, item):
    _show_window()

def _tray_on_start(icon, item):
    root.after(0, _start_ids)

def _tray_on_stop(icon, item):
    root.after(0, _stop_ids)

def _tray_on_quit(icon, item):
    icon.stop()
    root.after(0, root.destroy)

def _start_tray():
    global _tray_icon
    if not _TRAY_AVAILABLE:
        return
    menu = pystray.Menu(
        pystray.MenuItem("Show ML-IDS", _tray_on_show, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Start IDS",   _tray_on_start),
        pystray.MenuItem("Stop IDS",    _tray_on_stop),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit",        _tray_on_quit),
    )
    _tray_icon = pystray.Icon(
        "ML_IDS",
        _build_tray_image(),
        "ML-IDS — Intrusion Detection System",
        menu
    )
    threading.Thread(target=_tray_icon.run, daemon=True).start()

def _on_close():
    """Minimize to tray instead of quitting."""
    if _TRAY_AVAILABLE and _tray_icon is not None:
        root.withdraw()
    else:
        root.destroy()

root.protocol("WM_DELETE_WINDOW", _on_close)

# ─────────────────────────────────────────────────────────────
#  INITIAL PAGE & MAINLOOP
# ─────────────────────────────────────────────────────────────
show_page(page_dashboard)

# Start the tray icon (runs in background thread)
_start_tray()

if LAUNCH_MINIMIZED:
    # Launched at Windows startup — start IDS silently and hide to tray
    root.after(500, _start_ids)
    root.after(600, root.withdraw)

root.mainloop()