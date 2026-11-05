import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter
import os
import sys
import time
import threading
import datetime
import re

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.join(application_path, "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

def get_latest_log_file():
    try:
        files = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.endswith(".log")]
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    except Exception:
        return None

def export_logs():
    logs = full_log_area.get("1.0", tk.END)
    if not logs.strip():
        messagebox.showinfo("Export Logs", "No logs to export.")
        return
    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Logs As"
    )
    if filepath:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(logs)
            messagebox.showinfo("Export Successful", f"Logs exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save logs:\n{e}")

def export_security_report():
    """Generate an HTML security summary report from current session stats."""
    filepath = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML Report", "*.html"), ("All Files", "*.*")],
        title="Save Security Report As"
    )
    if not filepath:
        return

    now = datetime.datetime.now()
    logs_raw = full_log_area.get("1.0", tk.END).strip()
    log_lines = [l for l in logs_raw.splitlines() if l.strip()]

    # Collect intrusion events for the table
    intrusion_lines = [l for l in log_lines if "Detected" in l or "!" in l]
    normal_lines    = [l for l in log_lines if "Normal Traffic" in l]

    pct_intrusion = f"{(intrusion_count/total_packets*100):.1f}%" if total_packets else "N/A"
    pct_normal    = f"{(normal_count/total_packets*100):.1f}%"    if total_packets else "N/A"

    def escape(s):
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    rows_html = ""
    for i, line in enumerate(intrusion_lines[-50:], 1):   # cap at last 50
        rows_html += f"<tr><td>{i}</td><td class='alert'>{escape(line)}</td></tr>\n"
    if not rows_html:
        rows_html = "<tr><td colspan='2' style='text-align:center;color:#8892a4'>No intrusion events recorded.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ML-IDS Security Report — {now.strftime('%Y-%m-%d %H:%M:%S')}</title>
<style>
  body {{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#e8ecf4;margin:0;padding:32px}}
  h1   {{color:#4f8ef7;font-size:26px;margin-bottom:4px}}
  .sub {{color:#8892a4;font-size:13px;margin-bottom:36px}}
  .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-bottom:36px}}
  .card{{background:#1a1d27;border-radius:12px;padding:22px 24px}}
  .card .lbl{{font-size:11px;font-weight:700;color:#8892a4;text-transform:uppercase;letter-spacing:.08em}}
  .card .val{{font-size:34px;font-weight:700;margin-top:6px}}
  .red  {{color:#e05252}} .green{{color:#3ecf82}} .blue{{color:#4f8ef7}}
  table{{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:12px;overflow:hidden}}
  th   {{background:#22263a;color:#8892a4;font-size:11px;text-transform:uppercase;padding:12px 16px;text-align:left}}
  td   {{padding:10px 16px;font-size:12px;font-family:Consolas,monospace;border-bottom:1px solid #22263a}}
  .alert{{color:#e05252}}
  tr:last-child td{{border-bottom:none}}
  .footer{{margin-top:36px;color:#8892a4;font-size:11px;text-align:center}}
</style>
</head>
<body>
<h1>🔐 ML-IDS Security Report</h1>
<p class="sub">Generated: {now.strftime('%A, %d %B %Y at %H:%M:%S')} &nbsp;|&nbsp; Session summary</p>

<div class="grid">
  <div class="card">
    <div class="lbl">Total Packets</div>
    <div class="val blue">{total_packets}</div>
  </div>
  <div class="card">
    <div class="lbl">Normal Traffic</div>
    <div class="val green">{normal_count} <span style="font-size:16px">({pct_normal})</span></div>
  </div>
  <div class="card">
    <div class="lbl">Intrusions Detected</div>
    <div class="val red">{intrusion_count} <span style="font-size:16px">({pct_intrusion})</span></div>
  </div>
</div>

<table>
  <thead><tr><th>#</th><th>Intrusion Event Log (last 50)</th></tr></thead>
  <tbody>
{rows_html}  </tbody>
</table>

<div class="footer">ML Intrusion Detection System &nbsp;|&nbsp; Admin Portal Report</div>
</body>
</html>"""

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        messagebox.showinfo("Report Exported", f"Security report saved to:\n{filepath}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to save report:\n{e}")

def change_appearance_mode_event(new_appearance_mode: str):
    customtkinter.set_appearance_mode(new_appearance_mode)

def tail_log_file():
    current_tail_file = None
    f = None
    while running:
        latest_file = get_latest_log_file()
        if not latest_file:
            time.sleep(1)
            continue
        if current_tail_file != latest_file:
            if f:
                f.close()
            current_tail_file = latest_file
            try:
                f = open(current_tail_file, "r", encoding="utf-8")
            except Exception:
                f = None
            root.after(0, clear_logs_ui)
        if f:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            root.after(0, process_log_line, line)

total_packets = 0
intrusion_count = 0
normal_count = 0
running = True

# ─────────────────────────────────────────────────────────────
#  LOGIN  – shown before main window
# ─────────────────────────────────────────────────────────────
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def show_login():
    """Show a modal login window (CTkToplevel) over the hidden root.
    On success: destroys login and reveals root.
    On cancel/close: destroys root (exits app).
    """
    login_win = customtkinter.CTkToplevel(root)
    login_win.title("ML-IDS — Admin Login")
    login_win.geometry("600x600")
    login_win.resizable(True, True)
    login_win.configure(fg_color="#0f1117")
    login_win.grab_set()   # make it modal
    login_win.lift()
    login_win.focus_force()

    def on_login_close():
        root.destroy()  # close everything if user dismisses login

    login_win.protocol("WM_DELETE_WINDOW", on_login_close)

    # ── card ──────────────────────────────────────────────────
    card = customtkinter.CTkFrame(login_win, fg_color="#1a1d27", corner_radius=18)
    card.pack(expand=True, fill="both", padx=36, pady=44)

    # Logo / title area
    badge = customtkinter.CTkFrame(card, fg_color="#22263a", corner_radius=50, width=72, height=72)
    badge.pack(pady=(32, 0))
    badge.pack_propagate(False)
    customtkinter.CTkLabel(
        badge, text="🔐", font=customtkinter.CTkFont(size=32)
    ).pack(expand=True)

    customtkinter.CTkLabel(
        card, text="Admin Portal",
        font=customtkinter.CTkFont(size=22, weight="bold"), text_color="#e8ecf4"
    ).pack(pady=(14, 2))
    customtkinter.CTkLabel(
        card, text="ML Intrusion Detection System",
        font=customtkinter.CTkFont(size=12), text_color="#8892a4"
    ).pack(pady=(0, 28))

    # Username
    customtkinter.CTkLabel(
        card, text="Username",
        font=customtkinter.CTkFont(size=12, weight="bold"), text_color="#8892a4",
        anchor="w"
    ).pack(fill="x", padx=28)
    user_entry = customtkinter.CTkEntry(
        card, placeholder_text="Enter username",
        fg_color="#22263a", border_color="#2e334d", text_color="#e8ecf4",
        height=42, corner_radius=10, font=customtkinter.CTkFont(size=13)
    )
    user_entry.pack(fill="x", padx=28, pady=(4, 14))

    # Password
    customtkinter.CTkLabel(
        card, text="Password",
        font=customtkinter.CTkFont(size=12, weight="bold"), text_color="#8892a4",
        anchor="w"
    ).pack(fill="x", padx=28)
    pass_entry = customtkinter.CTkEntry(
        card, placeholder_text="Enter password", show="●",
        fg_color="#22263a", border_color="#2e334d", text_color="#e8ecf4",
        height=42, corner_radius=10, font=customtkinter.CTkFont(size=13)
    )
    pass_entry.pack(fill="x", padx=28, pady=(4, 6))

    err_label = customtkinter.CTkLabel(
        card, text="",
        font=customtkinter.CTkFont(size=11), text_color="#e05252"
    )
    err_label.pack(pady=(2, 10))

    def attempt_login(event=None):
        u = user_entry.get().strip()
        p = pass_entry.get().strip()
        if u == ADMIN_USER and p == ADMIN_PASS:
            login_win.destroy()
            root.deiconify()   # reveal main window
            show_page(page_dashboard, btn_dash)
            threading.Thread(target=tail_log_file, daemon=True).start()
        else:
            err_label.configure(text="⚠  Invalid username or password.")
            pass_entry.delete(0, tk.END)
            user_entry.focus_set()

    login_btn = customtkinter.CTkButton(
        card, text="Sign In",
        command=attempt_login,
        fg_color="#4f8ef7", hover_color="#6c63ff", text_color="#e8ecf4",
        height=44, corner_radius=10,
        font=customtkinter.CTkFont(size=14, weight="bold")
    )
    login_btn.pack(fill="x", padx=28, pady=(4, 18))

    user_entry.bind("<Return>", attempt_login)
    pass_entry.bind("<Return>", attempt_login)
    user_entry.focus_set()

# ─────────────────────────────────────────────────────────────
#  THEME & COLOUR TOKENS  (mirrors ids.py)
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

# ─────────────────────────────────────────────────────────────
#  WINDOW
# ─────────────────────────────────────────────────────────────
root = customtkinter.CTk()
root.title("ML-IDS - Admin Interface")
root.geometry("980x640")
root.minsize(820, 560)
root.configure(fg_color=BG)

def on_closing():
    global running
    running = False
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# ─────────────────────────────────────────────────────────────
#  ROOT LAYOUT  -  sidebar | content
# ─────────────────────────────────────────────────────────────
outer = customtkinter.CTkFrame(root, fg_color=BG, corner_radius=0)
outer.pack(fill="both", expand=True)
outer.grid_columnconfigure(1, weight=1)
outer.grid_rowconfigure(0, weight=1)

# Sidebar
sidebar = customtkinter.CTkFrame(outer, width=SIDEBAR_W, fg_color=SURFACE, corner_radius=0)
sidebar.grid(row=0, column=0, sticky="nsew")
sidebar.grid_propagate(False)
sidebar.grid_rowconfigure(6, weight=1)

brand_frame = customtkinter.CTkFrame(sidebar, fg_color=SURFACE2, corner_radius=0)
brand_frame.grid(row=0, column=0, sticky="ew", pady=(0, 2))
customtkinter.CTkLabel(
    brand_frame, text="ML-IDS Admin",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).pack(pady=16, padx=16, anchor="w")

customtkinter.CTkLabel(
    sidebar, text="NAVIGATION",
    font=customtkinter.CTkFont(size=10, weight="bold"), text_color=MUTED
).grid(row=1, column=0, sticky="w", padx=18, pady=(18, 4))

# Content host
content_host = customtkinter.CTkFrame(outer, fg_color=BG, corner_radius=0)
content_host.grid(row=0, column=1, sticky="nsew")
content_host.grid_rowconfigure(0, weight=1)
content_host.grid_columnconfigure(0, weight=1)

page_dashboard = customtkinter.CTkFrame(content_host, fg_color=BG, corner_radius=0)
page_logs      = customtkinter.CTkFrame(content_host, fg_color=BG, corner_radius=0)
page_settings  = customtkinter.CTkFrame(content_host, fg_color=BG, corner_radius=0)

_active_nav_btn = [None]

def show_page(page, nav_btn):
    for p in (page_dashboard, page_logs, page_settings):
        p.grid_forget()
    page.grid(row=0, column=0, sticky="nsew")
    if _active_nav_btn[0] and _active_nav_btn[0] is not nav_btn:
        _active_nav_btn[0].configure(fg_color="transparent", text_color=MUTED)
    nav_btn.configure(fg_color=ACCENT2, text_color=TEXT)
    _active_nav_btn[0] = nav_btn

_NAV = dict(
    anchor="w", width=SIDEBAR_W - 4, height=40, corner_radius=8,
    font=customtkinter.CTkFont(size=13), border_spacing=10
)

btn_dash = customtkinter.CTkButton(
    sidebar, text="  Dashboard", fg_color=ACCENT2, text_color=TEXT,
    hover_color=ACCENT, **_NAV)
btn_dash.grid(row=2, column=0, padx=8, pady=3, sticky="ew")

btn_logs = customtkinter.CTkButton(
    sidebar, text="  Logs", fg_color="transparent", text_color=MUTED,
    hover_color=SURFACE2, **_NAV)
btn_logs.grid(row=3, column=0, padx=8, pady=3, sticky="ew")

btn_settings_nav = customtkinter.CTkButton(
    sidebar, text="  Settings", fg_color="transparent", text_color=MUTED,
    hover_color=SURFACE2, **_NAV)
btn_settings_nav.grid(row=4, column=0, padx=8, pady=(3, 18), sticky="ew")

btn_dash.configure(         command=lambda: show_page(page_dashboard, btn_dash))
btn_logs.configure(         command=lambda: show_page(page_logs,      btn_logs))
btn_settings_nav.configure( command=lambda: show_page(page_settings,  btn_settings_nav))

# ─────────────────────────────────────────────────────────────
#  DASHBOARD PAGE
# ─────────────────────────────────────────────────────────────
page_dashboard.grid_columnconfigure(0, weight=1)
page_dashboard.grid_rowconfigure(2, weight=1)

_dh = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE, corner_radius=0, height=58)
_dh.grid(row=0, column=0, sticky="ew")
_dh.grid_propagate(False)
_dh.grid_columnconfigure(1, weight=1)
customtkinter.CTkLabel(
    _dh, text="Live Traffic Monitor",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).grid(row=0, column=0, padx=20, pady=16, sticky="w")

cards_row = customtkinter.CTkFrame(page_dashboard, fg_color=BG)
cards_row.grid(row=1, column=0, sticky="ew", padx=18, pady=12)
cards_row.grid_columnconfigure((0, 1, 2), weight=1)

def _card(parent, col, label, color):
    card = customtkinter.CTkFrame(parent, fg_color=SURFACE, corner_radius=12)
    card.grid(row=0, column=col, padx=6, sticky="ew")
    customtkinter.CTkLabel(card, text=label.upper(),
        font=customtkinter.CTkFont(size=10, weight="bold"), text_color=MUTED
    ).pack(anchor="w", padx=16, pady=(14, 2))
    num = customtkinter.CTkLabel(card, text="0",
        font=customtkinter.CTkFont(size=32, weight="bold"), text_color=color)
    num.pack(anchor="w", padx=16, pady=(0, 14))
    return num

card_total     = _card(cards_row, 0, "Total Packets",      TEXT)
card_normal    = _card(cards_row, 1, "Normal Traffic",     GREEN)
card_intrusion = _card(cards_row, 2, "Intrusions Detected", RED)

_log_outer = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE, corner_radius=12)
_log_outer.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 8))
_log_outer.grid_rowconfigure(1, weight=1)
_log_outer.grid_columnconfigure(0, weight=1)

_lh = customtkinter.CTkFrame(_log_outer, fg_color=SURFACE2, corner_radius=0, height=34)
_lh.grid(row=0, column=0, sticky="ew")
_lh.grid_propagate(False)
customtkinter.CTkLabel(_lh, text="  LIVE EVENT FEED",
    font=customtkinter.CTkFont(size=11, weight="bold"), text_color=MUTED
).pack(side="left", padx=12, pady=7)

dashboard_log_area = customtkinter.CTkTextbox(
    _log_outer, corner_radius=0, wrap="none",
    font=customtkinter.CTkFont(family="Consolas", size=12),
    fg_color=SURFACE, text_color=TEXT,
    scrollbar_button_color=SURFACE2, scrollbar_button_hover_color=ACCENT)
dashboard_log_area.grid(row=1, column=0, sticky="nsew", padx=2, pady=(0, 2))
dashboard_log_area._textbox.tag_configure("intrusion", foreground=RED)
dashboard_log_area._textbox.tag_configure("normal",    foreground="#6b7a90")

footer = customtkinter.CTkFrame(page_dashboard, fg_color=SURFACE2, corner_radius=0, height=26)
footer.grid(row=3, column=0, sticky="ew")
footer.grid_propagate(False)
footer_label = customtkinter.CTkLabel(footer, text="Monitoring logs...",
    font=customtkinter.CTkFont(size=10), text_color=MUTED)
footer_label.pack(side="left", padx=14, pady=4)

# ─────────────────────────────────────────────────────────────
#  LOGS PAGE
# ─────────────────────────────────────────────────────────────
page_logs.grid_columnconfigure(0, weight=1)
page_logs.grid_rowconfigure(1, weight=1)

_ph = customtkinter.CTkFrame(page_logs, fg_color=SURFACE, corner_radius=0, height=58)
_ph.grid(row=0, column=0, sticky="ew")
_ph.grid_propagate(False)
customtkinter.CTkLabel(_ph, text="Detailed Application Logs",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).grid(row=0, column=0, padx=20, pady=16, sticky="w")

_log_outer2 = customtkinter.CTkFrame(page_logs, fg_color=SURFACE, corner_radius=12)
_log_outer2.grid(row=1, column=0, sticky="nsew", padx=18, pady=(12, 4))
_log_outer2.grid_rowconfigure(1, weight=1)
_log_outer2.grid_columnconfigure(0, weight=1)

_lh2 = customtkinter.CTkFrame(_log_outer2, fg_color=SURFACE2, corner_radius=0, height=34)
_lh2.grid(row=0, column=0, sticky="ew")
_lh2.grid_propagate(False)
customtkinter.CTkLabel(_lh2, text="  FULL LOG",
    font=customtkinter.CTkFont(size=11, weight="bold"), text_color=MUTED
).pack(side="left", padx=12, pady=7)

full_log_area = customtkinter.CTkTextbox(
    _log_outer2, corner_radius=0, wrap="none",
    font=customtkinter.CTkFont(family="Consolas", size=12),
    fg_color=SURFACE, text_color=TEXT,
    scrollbar_button_color=SURFACE2, scrollbar_button_hover_color=ACCENT)
full_log_area.grid(row=1, column=0, sticky="nsew", padx=2, pady=(0, 2))
full_log_area._textbox.tag_configure("intrusion", foreground=RED)
full_log_area._textbox.tag_configure("normal",    foreground="#6b7a90")

_btn_bar = customtkinter.CTkFrame(page_logs, fg_color="transparent")
_btn_bar.grid(row=2, column=0, pady=10)

clear_logs_btn = customtkinter.CTkButton(
    _btn_bar, text="Clear Logs", command=lambda: clear_logs(),
    fg_color=SURFACE, hover_color=SURFACE2, text_color=RED,
    border_width=1, border_color=RED, corner_radius=8,
    font=customtkinter.CTkFont(size=13, weight="bold"))
clear_logs_btn.pack(side=tk.LEFT, padx=8)

export_logs_btn = customtkinter.CTkButton(
    _btn_bar, text="Export Logs", command=export_logs,
    fg_color=ACCENT2, hover_color=ACCENT, text_color=TEXT,
    corner_radius=8, font=customtkinter.CTkFont(size=13, weight="bold"))
export_logs_btn.pack(side=tk.LEFT, padx=8)

export_report_btn = customtkinter.CTkButton(
    _btn_bar, text="Export Security Report", command=export_security_report,
    fg_color=GREEN, hover_color="#2db36b", text_color="#0f1117",
    corner_radius=8, font=customtkinter.CTkFont(size=13, weight="bold"))
export_report_btn.pack(side=tk.LEFT, padx=8)

# ─────────────────────────────────────────────────────────────
#  SETTINGS PAGE
# ─────────────────────────────────────────────────────────────
page_settings.grid_columnconfigure(0, weight=1)

_sh = customtkinter.CTkFrame(page_settings, fg_color=SURFACE, corner_radius=0, height=58)
_sh.grid(row=0, column=0, sticky="ew")
_sh.grid_propagate(False)
customtkinter.CTkLabel(_sh, text="Settings",
    font=customtkinter.CTkFont(size=16, weight="bold"), text_color=TEXT
).grid(row=0, column=0, padx=20, pady=16, sticky="w")

s_scroll = customtkinter.CTkScrollableFrame(page_settings, fg_color=BG, corner_radius=0)
s_scroll.grid(row=1, column=0, sticky="nsew")
page_settings.grid_rowconfigure(1, weight=1)
s_scroll.grid_columnconfigure(0, weight=1)

def _section_label(parent, row, text):
    customtkinter.CTkLabel(parent, text=text,
        font=customtkinter.CTkFont(size=10, weight="bold"), text_color=MUTED
    ).grid(row=row, column=0, sticky="w", padx=26, pady=(22, 6))

def _setting_card(parent, row, title, desc, widget_fn):
    card = customtkinter.CTkFrame(parent, fg_color=SURFACE, corner_radius=12)
    card.grid(row=row, column=0, sticky="ew", padx=18, pady=4)
    card.grid_columnconfigure(0, weight=1)
    txt = customtkinter.CTkFrame(card, fg_color="transparent")
    txt.grid(row=0, column=0, sticky="w", padx=18, pady=14)
    customtkinter.CTkLabel(txt, text=title,
        font=customtkinter.CTkFont(size=13, weight="bold"), text_color=TEXT
    ).pack(anchor="w")
    customtkinter.CTkLabel(txt, text=desc,
        font=customtkinter.CTkFont(size=11), text_color=MUTED
    ).pack(anchor="w", pady=(2, 0))
    w = widget_fn(card)
    w.grid(row=0, column=1, padx=18, pady=14, sticky="e")

_section_label(s_scroll, 0, "APPEARANCE")
_setting_card(s_scroll, 1,
    "Appearance Mode",
    "Choose Dark, Light, or follow the system setting.",
    lambda p: customtkinter.CTkOptionMenu(p,
        values=["Dark", "Light", "System"],
        command=change_appearance_mode_event,
        fg_color=SURFACE2, button_color=ACCENT, button_hover_color=ACCENT2,
        width=140)
)

# ─────────────────────────────────────────────────────────────
#  LOG PROCESSING (uses new color-tagged widgets)
# ─────────────────────────────────────────────────────────────
def process_log_line(line):
    global total_packets, normal_count, intrusion_count
    total_packets += 1
    is_intrusion = "Detected" in line or "!" in line
    if is_intrusion:
        intrusion_count += 1
    elif "Normal Traffic" in line:
        normal_count += 1

    tag = "intrusion" if is_intrusion else "normal"
    dashboard_log_area._textbox.insert(tk.END, line, tag)
    dashboard_log_area._textbox.see(tk.END)
    full_log_area._textbox.insert(tk.END, line, tag)
    full_log_area._textbox.see(tk.END)

    card_total.configure(text=str(total_packets))
    card_normal.configure(text=str(normal_count))
    card_intrusion.configure(text=str(intrusion_count))

    import datetime
    footer_label.configure(
        text=f"Last event: {datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}"
    )

def clear_logs():
    dashboard_log_area._textbox.delete("1.0", tk.END)
    full_log_area._textbox.delete("1.0", tk.END)
    try:
        latest = get_latest_log_file()
        if latest:
            open(latest, "w").close()
    except Exception:
        pass
    global total_packets, normal_count, intrusion_count
    total_packets = normal_count = intrusion_count = 0
    card_total.configure(text="0")
    card_normal.configure(text="0")
    card_intrusion.configure(text="0")

def clear_logs_ui():
    dashboard_log_area._textbox.delete("1.0", tk.END)
    full_log_area._textbox.delete("1.0", tk.END)
    global total_packets, normal_count, intrusion_count
    total_packets = normal_count = intrusion_count = 0
    card_total.configure(text="0")
    card_normal.configure(text="0")
    card_intrusion.configure(text="0")

# ─────────────────────────────────────────────────────────────
#  START & MAINLOOP
# ─────────────────────────────────────────────────────────────
# Hide main window until login succeeds, then show_login reveals it.
root.withdraw()
show_login()
root.mainloop()
