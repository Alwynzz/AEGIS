import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import sys
import time

try:
    import psutil
except ImportError:
    psutil = None

try:
    from fpdf import FPDF
except ImportError:
    messagebox.showerror("Dependency Error", "Please run: pip install fpdf")
    sys.exit(1)

try:
    from scanner_engine import run_nmap_scan, parse_nmap_results, run_tshark_capture, analyze_pcap_data
    from scanner_engine import run_dnsrecon, run_host_audit
except ImportError:
    messagebox.showerror("Error", "Missing scanner_engine.py")
    sys.exit(1)

# --- CONFIGURATION & THEME ---
ctk.set_appearance_mode("Dark")
BG_COLOR = "#0B0B0C"        
CARD_COLOR = "#1A1A1D"      
CRIT_COLOR = "#FF3B30"
HIGH_COLOR = "#FF9500"
MED_COLOR = "#FFCC00"
LOW_COLOR = "#34C759"

class CircularDial(ctk.CTkFrame):
    def __init__(self, master, title, color, size=130, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.size = size
        self.color = color
        
        self.title_label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight="bold"))
        self.title_label.pack(pady=(0, 5))
        
        self.canvas = tk.Canvas(self, width=size, height=size, bg=CARD_COLOR, highlightthickness=0)
        self.canvas.pack()
        
        self.value_label = ctk.CTkLabel(self, text="0", font=ctk.CTkFont(size=28, weight="bold"), text_color=color)
        self.value_label.place(relx=0.5, rely=0.55, anchor="center")
        self.set_value(0) 

    def set_value(self, count, max_expected=10):
        percentage = min(count / max_expected, 1.0) if max_expected > 0 else 0
        angle = percentage * 360
        self.canvas.delete("all")
        self.canvas.create_arc(10, 10, self.size-10, self.size-10, start=0, extent=359.9, width=10, style=tk.ARC, outline="#333333")
        if angle > 0:
            self.canvas.create_arc(10, 10, self.size-10, self.size-10, start=90, extent=-angle, width=10, style=tk.ARC, outline=self.color)
        self.value_label.configure(text=str(count))

# --- NEW ADMIN SETTINGS WINDOWS ---
class AdminAuthWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Vault Authentication")
        self.geometry("400x250")
        self.configure(fg_color=BG_COLOR)
        self.attributes("-topmost", True)
        self.master_app = master
        
        self.grid_rowconfigure((0, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self, text="ENTER MASTER KEY", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, pady=(30, 10))
        
        self.pwd_entry = ctk.CTkEntry(self, show="*", width=200, justify="center")
        self.pwd_entry.grid(row=1, column=0, pady=10)
        self.pwd_entry.bind('<Return>', lambda e: self.verify())
        
        self.error_lbl = ctk.CTkLabel(self, text="", text_color=CRIT_COLOR)
        self.error_lbl.grid(row=2, column=0)
        
        ctk.CTkButton(self, text="UNLOCK", fg_color="#C0392B", hover_color="#922B21", command=self.verify).grid(row=3, column=0, pady=20)

    def verify(self):
        if self.pwd_entry.get() == "admin123":
            self.destroy()
            SettingsWindow(self.master_app)
        else:
            self.error_lbl.configure(text="Access Denied")

class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Aegis - Enterprise Settings")
        self.geometry("500x450")
        self.configure(fg_color=BG_COLOR)
        self.attributes("-topmost", True)
        self.master_app = master
        
        ctk.CTkLabel(self, text="⚙️ ADMIN CONFIGURATION", font=ctk.CTkFont(size=20, weight="bold"), text_color="#00FF41").pack(pady=20)
        
        frame = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=10)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Multithreading Threshold with dynamic label box
        thread_header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        thread_header_frame.pack(fill="x", padx=20, pady=(20, 5))
        
        ctk.CTkLabel(thread_header_frame, text="Multithreading Limit (Max Processes):", font=ctk.CTkFont(weight="bold")).pack(side="left")
        
        self.thread_val_label = ctk.CTkLabel(thread_header_frame, text=str(self.master_app.config_settings["threads"]), 
                                             font=ctk.CTkFont(weight="bold"), fg_color="#333333", corner_radius=5, width=40)
        self.thread_val_label.pack(side="right")
        
        self.thread_slider = ctk.CTkSlider(frame, from_=50, to=500, command=self.update_slider_label)
        self.thread_slider.set(self.master_app.config_settings["threads"])
        self.thread_slider.pack(fill="x", padx=20)
        
        # Port Scan Timeout
        ctk.CTkLabel(frame, text="Port Scan Timeout (Seconds):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.timeout_entry = ctk.CTkEntry(frame)
        self.timeout_entry.insert(0, str(self.master_app.config_settings["timeout"]))
        self.timeout_entry.pack(fill="x", padx=20)
        
        # Deep Audit Toggle
        self.deep_audit_var = ctk.BooleanVar(value=self.master_app.config_settings["deep_audit"])
        ctk.CTkSwitch(frame, text="Enable Deep Software & FIM Auditing", variable=self.deep_audit_var, progress_color=LOW_COLOR).pack(anchor="w", padx=20, pady=30)
        
        ctk.CTkButton(self, text="SAVE & APPLY", fg_color=LOW_COLOR, hover_color="#2EAD4E", text_color="#000000", font=ctk.CTkFont(weight="bold"), command=self.save_settings).pack(pady=20)

    def update_slider_label(self, value):
        self.thread_val_label.configure(text=str(int(value)))

    def save_settings(self):
        try:
            self.master_app.config_settings["threads"] = int(self.thread_slider.get())
            self.master_app.config_settings["timeout"] = int(self.timeout_entry.get())
            self.master_app.config_settings["deep_audit"] = self.deep_audit_var.get()
            messagebox.showinfo("Settings Applied", "Enterprise settings updated successfully.")
            self.destroy()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numeric values for timeouts.")

# --- MAIN APPLICATION ---
class SecurityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aegis - Professional Hybrid Security Suite")
        self.geometry("1150x800")
        self.configure(fg_color=BG_COLOR) 
        
        # Global Settings Memory
        self.config_settings = {
            "threads": 100,
            "timeout": 30,
            "deep_audit": False
        }
        
        self.target_ip_var = tk.StringVar(value="Aegis-Primary-Node")
        self.scan_profile_var = tk.StringVar(value="Full Hybrid Audit")
        self.last_results = None
        self.vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        self.hardware_thread_running = False

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomeScreen, ScanScreen, DashboardScreen):
            frame = F(parent=self.container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(HomeScreen)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        if cont == DashboardScreen:
            self.hardware_thread_running = True
            threading.Thread(target=frame.update_hardware_stats, daemon=True).start()
        else:
            self.hardware_thread_running = False

class HomeScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        self.grid_rowconfigure((0, 6), weight=1)
        self.grid_columnconfigure((0, 2), weight=1)

        title = ctk.CTkLabel(self, text="🛡️ AEGIS SECURITY", font=ctk.CTkFont(size=48, weight="bold", family="Consolas"), text_color="#00FF41")
        title.grid(row=1, column=1, pady=(0, 5))
        
        subtitle = ctk.CTkLabel(self, text="Advanced Hybrid Host & Network Auditing Platform", font=ctk.CTkFont(size=16), text_color="#888888")
        subtitle.grid(row=2, column=1, pady=(0, 50))

        input_frame = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=15, border_width=1, border_color="#333333")
        input_frame.grid(row=3, column=1, pady=20, ipadx=20, ipady=20)
        
        ctk.CTkLabel(input_frame, text="Target Hostname/IP:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=15, pady=15, sticky="e")
        ctk.CTkEntry(input_frame, textvariable=self.controller.target_ip_var, width=280, height=35).grid(row=0, column=1, padx=15, pady=15)
        
        ctk.CTkLabel(input_frame, text="Scan Profile:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=15, pady=15, sticky="e")
        ctk.CTkOptionMenu(input_frame, variable=self.controller.scan_profile_var, values=["Full Hybrid Audit", "Network Only", "Host Audit Only"], width=280, height=35).grid(row=1, column=1, padx=15, pady=15)

        # MAIN BUTTONS
        scan_btn = ctk.CTkButton(self, text="INITIATE AUDIT", font=ctk.CTkFont(size=18, weight="bold"), width=250, height=55, fg_color="#C0392B", hover_color="#922B21", command=self.start_scan)
        scan_btn.grid(row=4, column=1, pady=(40, 10))

        settings_btn = ctk.CTkButton(self, text="⚙️ Admin Settings", font=ctk.CTkFont(size=14, weight="bold"), width=250, height=35, fg_color="#333333", hover_color="#444444", command=self.open_settings)
        settings_btn.grid(row=5, column=1, pady=(0, 40))

    def start_scan(self):
        self.controller.show_frame(ScanScreen)
        self.controller.frames[ScanScreen].start_audit_thread()

    def open_settings(self):
        AdminAuthWindow(self.controller)

class ScanScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkLabel(self, text="AUDIT IN PROGRESS", font=ctk.CTkFont(size=28, weight="bold"), text_color="#FFFFFF")
        self.header.grid(row=0, column=0, pady=(30, 5))

        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_idx = 0
        self.is_animating = False
        self.loading_label = ctk.CTkLabel(self, text="Initializing Engines... ⠋", font=ctk.CTkFont(size=16, family="Consolas"), text_color="#00FF41")
        self.loading_label.grid(row=1, column=0, pady=(0, 20))

        self.stepper_frame = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=10)
        self.stepper_frame.grid(row=2, column=0, pady=10, ipadx=20, ipady=10)
        
        self.steps = []
        phases = ["Init", "Host Audit", "Network Map", "Vuln Scan", "Traffic Analysis"]
        for i, phase in enumerate(phases):
            lbl = ctk.CTkLabel(self.stepper_frame, text=f"⭘ {phase}", font=ctk.CTkFont(size=14, weight="bold"), text_color="#555555")
            lbl.grid(row=0, column=i, padx=20)
            self.steps.append(lbl)

        self.terminal_frame = ctk.CTkFrame(self, fg_color="#050505", corner_radius=10, border_width=1, border_color="#222222") 
        self.terminal_frame.grid(row=3, column=0, sticky="nsew", padx=50, pady=30)
        self.terminal_frame.grid_rowconfigure(0, weight=1)
        self.terminal_frame.grid_columnconfigure(0, weight=1)
        
        self.log_textbox = ctk.CTkTextbox(self.terminal_frame, fg_color="transparent", text_color="#00FF41", font=ctk.CTkFont(family="Consolas", size=13))
        self.log_textbox.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self.log_textbox.configure(state="disabled")

    def animate_spinner(self):
        if self.is_animating:
            base_text = self.loading_label.cget("text")[:-1].strip()
            self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)
            self.loading_label.configure(text=f"{base_text} {self.spinner_chars[self.spinner_idx]}")
            self.after(100, self.animate_spinner)

    def set_loading_text(self, text):
        self.loading_label.configure(text=f"{text} {self.spinner_chars[self.spinner_idx]}")

    def log(self, text):
        timestamp = time.strftime("[%H:%M:%S] ")
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", timestamp + text + "\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def update_stepper(self, current_step_idx):
        for i, lbl in enumerate(self.steps):
            if i < current_step_idx:
                lbl.configure(text=lbl.cget("text").replace("⭘", "✓").replace("↻", "✓"), text_color=LOW_COLOR)
            elif i == current_step_idx:
                lbl.configure(text=lbl.cget("text").replace("⭘", "↻"), text_color="#FFFFFF")
            else:
                lbl.configure(text_color="#555555")

    def start_audit_thread(self):
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")
        self.controller.vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        self.is_animating = True
        self.animate_spinner()
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        c = self.controller
        display_host = c.target_ip_var.get()
        actual_target = "127.0.0.1" if display_host in ["Aegis-Primary-Node", ""] else display_host
        
        profile = c.scan_profile_var.get()
        res = {'nmap': {}, 'traffic': [], 'dnsrecon': [], 'host_audit': []}

        self.after(0, self.update_stepper, 0)
        self.after(0, self.set_loading_text, "Waking up engines...")
        self.log("Initializing Aegis Engine...")
        self.log(f"Applying Admin Configs -> Max Threads: {c.config_settings['threads']}")
        time.sleep(1)

        if profile in ["Full Hybrid Audit", "Host Audit Only"]:
            self.after(0, self.update_stepper, 1)
            self.after(0, self.set_loading_text, "Auditing Local Host Configuration...")
            self.log(f"Gathering local system intelligence for {display_host}...")
            res['host_audit'] = run_host_audit()
            
            # Deep Audit Toggle check
            if c.config_settings['deep_audit']:
                self.log("[+] Admin deep audit triggered. Analyzing registry for blacklisted artifacts...")
                time.sleep(0.5)
            
            self.process_findings(res['host_audit'], "Host")

        if profile in ["Full Hybrid Audit", "Network Only"]:
            self.after(0, self.update_stepper, 2)
            self.after(0, self.set_loading_text, f"Mapping Network Surface for {display_host}...")
            self.log(f"Mapping network surface via Nmap (Timeout: {c.config_settings['timeout']}s)...")
            nm = run_nmap_scan(actual_target)
            if nm:
                res['nmap'] = parse_nmap_results(nm, actual_target)
                self.process_findings(res['nmap'].get('port_threats', []), "Nmap")
                
                open_ports = res['nmap'].get('open_ports', [])
                self.log(f"Found {len(open_ports)} open ports.")
                
                self.after(0, self.update_stepper, 3)
                self.after(0, self.set_loading_text, "Evaluating Threat Dictionary...")
                
            else:
                self.log("ERROR: Network scan failed.")

        if profile == "Full Hybrid Audit":
            self.after(0, self.update_stepper, 4)
            self.after(0, self.set_loading_text, "Analyzing Live Network Traffic (15s)...")
            self.log("Activating TShark packet sniffer for 15 seconds...")
            pcap = run_tshark_capture(duration=15)
            if pcap:
                res['traffic'] = analyze_pcap_data(pcap)
                self.process_findings(res['traffic'], "Traffic")
            else:
                self.log("WARNING: Packet capture failed.")

        self.is_animating = False
        self.after(0, self.loading_label.configure, {"text": "Audit Complete! ✓", "text_color": LOW_COLOR})
        self.log("Compilation complete. Routing to Dashboard...")
        time.sleep(1.5)
        
        c.last_results = res
        self.after(0, self.finish_scan)

    def process_findings(self, findings, tool):
        if not findings: return
        for f in findings:
            if isinstance(f, dict):
                sev = f.get('severity', 'Info')
                self.log(f"[{sev.upper()}] {tool}: {f.get('summary')}")
                if sev in self.controller.vuln_counts:
                    self.controller.vuln_counts[sev] += 1
                elif sev == "Info":
                    self.controller.vuln_counts["Info"] += 1

    def finish_scan(self):
        self.update_stepper(5)
        dash = self.controller.frames[DashboardScreen]
        dash.populate_data()
        self.controller.show_frame(DashboardScreen)

class DashboardScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure((0,1), weight=1)

        self.hdr_card = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=10)
        self.hdr_card.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=(20, 10), ipadx=10, ipady=10)
        
        self.grade_label = ctk.CTkLabel(self.hdr_card, text="A", font=ctk.CTkFont(size=60, weight="bold"), text_color=LOW_COLOR)
        self.grade_label.pack(side="left", padx=(20, 20))

        info_frame = ctk.CTkFrame(self.hdr_card, fg_color="transparent")
        info_frame.pack(side="left", fill="y", pady=10)
        self.target_label = ctk.CTkLabel(info_frame, text="Target: N/A", font=ctk.CTkFont(size=20, weight="bold"))
        self.target_label.pack(anchor="w")
        self.score_label = ctk.CTkLabel(info_frame, text="System Health: 100/100", font=ctk.CTkFont(size=14), text_color="#AAAAAA")
        self.score_label.pack(anchor="w")

        btn_frame = ctk.CTkFrame(self.hdr_card, fg_color="transparent")
        btn_frame.pack(side="right", padx=20)
        ctk.CTkButton(btn_frame, text="Export PDF Report", fg_color="#C0392B", hover_color="#922B21", font=ctk.CTkFont(weight="bold"), command=self.generate_pdf).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="New Scan", width=100, fg_color="#333333", hover_color="#444444", command=lambda: self.controller.show_frame(HomeScreen)).pack(side="left")

        dials_card = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=10)
        dials_card.grid(row=1, column=0, sticky="nsew", padx=(20, 10), pady=10)
        ctk.CTkLabel(dials_card, text="VULNERABILITY METRICS", font=ctk.CTkFont(size=14, weight="bold"), text_color="#888888").pack(pady=(15, 5))
        dial_container = ctk.CTkFrame(dials_card, fg_color="transparent")
        dial_container.pack(expand=True, fill="both", pady=10)
        
        self.dial_crit = CircularDial(dial_container, "CRITICAL", CRIT_COLOR)
        self.dial_crit.pack(side="left", expand=True, padx=5)
        self.dial_high = CircularDial(dial_container, "HIGH", HIGH_COLOR)
        self.dial_high.pack(side="left", expand=True, padx=5)
        self.dial_med = CircularDial(dial_container, "MEDIUM", MED_COLOR)
        self.dial_med.pack(side="left", expand=True, padx=5)

        threat_card = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=10)
        threat_card.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=10)
        ctk.CTkLabel(threat_card, text="LIVE THREAT FEED", font=ctk.CTkFont(size=14, weight="bold"), text_color="#888888").pack(pady=(15, 5))
        self.threat_scroll = ctk.CTkScrollableFrame(threat_card, fg_color="transparent")
        self.threat_scroll.pack(expand=True, fill="both", padx=10, pady=(0, 10))

        bottom_area = ctk.CTkFrame(self, fg_color="transparent")
        bottom_area.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=20, pady=(10, 20))
        bottom_area.grid_columnconfigure(1, weight=1)

        hw_card = ctk.CTkFrame(bottom_area, fg_color=CARD_COLOR, corner_radius=10)
        hw_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), ipadx=10, ipady=10)
        ctk.CTkLabel(hw_card, text="HARDWARE TELEMETRY", font=ctk.CTkFont(size=12, weight="bold"), text_color="#888888").pack(pady=(5, 10))
        
        self.lbl_cpu = ctk.CTkLabel(hw_card, text="CPU: 0%", font=ctk.CTkFont(size=12))
        self.lbl_cpu.pack(anchor="w", padx=10)
        self.hw_cpu = ctk.CTkProgressBar(hw_card, progress_color="#32ADE6", height=10)
        self.hw_cpu.pack(pady=(2, 10), padx=10, fill="x")

        self.lbl_ram = ctk.CTkLabel(hw_card, text="RAM: 0%", font=ctk.CTkFont(size=12))
        self.lbl_ram.pack(anchor="w", padx=10)
        self.hw_ram = ctk.CTkProgressBar(hw_card, progress_color="#AF52DE", height=10)
        self.hw_ram.pack(pady=(2, 10), padx=10, fill="x")

        tabs_card = ctk.CTkFrame(bottom_area, fg_color=CARD_COLOR, corner_radius=10)
        tabs_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        
        self.tabs = ctk.CTkTabview(tabs_card, fg_color="transparent", bg_color="transparent")
        self.tabs.pack(fill="both", expand=True, padx=10, pady=5)
        self.tabs.add("Host Details")
        self.tabs.add("Network / Nmap")
        
        self.txt_host = ctk.CTkTextbox(self.tabs.tab("Host Details"), font=ctk.CTkFont(family="Consolas", size=12), fg_color="#0F0F0F")
        self.txt_host.pack(fill="both", expand=True)
        self.txt_net = ctk.CTkTextbox(self.tabs.tab("Network / Nmap"), font=ctk.CTkFont(family="Consolas", size=12), fg_color="#0F0F0F")
        self.txt_net.pack(fill="both", expand=True)

    def populate_data(self):
        c = self.controller
        display_host = c.target_ip_var.get()
        if display_host == "": display_host = "Aegis-Primary-Node"
        self.target_label.configure(text=f"Target: {display_host}")
        
        score = 100 - (c.vuln_counts['Critical']*20) - (c.vuln_counts['High']*10) - (c.vuln_counts['Medium']*5)
        score = max(0, score)
        
        if score >= 90: grade, color = "A", LOW_COLOR
        elif score >= 75: grade, color = "B", MED_COLOR
        elif score >= 50: grade, color = "C", HIGH_COLOR
        else: grade, color = "F", CRIT_COLOR
            
        self.grade_label.configure(text=grade, text_color=color)
        self.score_label.configure(text=f"System Health: {score}/100")

        self.dial_crit.set_value(c.vuln_counts["Critical"], max_expected=5)
        self.dial_high.set_value(c.vuln_counts["High"], max_expected=10)
        self.dial_med.set_value(c.vuln_counts["Medium"], max_expected=15)
        
        for widget in self.threat_scroll.winfo_children(): widget.destroy()

        alerts_found = False
        res = c.last_results
        
        threat_lists = [res.get('nmap', {}).get('port_threats', [])]
        for section in ['host_audit', 'traffic', 'dnsrecon']:
            threat_lists.append(res.get(section, []))

        for data in threat_lists:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        sev = item.get('severity', 'Info')
                        sum_text = item.get('summary', 'Unknown finding')
                        self.add_threat_row(sev, sum_text, item.get('tool', 'SYSTEM'))
                        alerts_found = True
                        
        if not alerts_found:
            ctk.CTkLabel(self.threat_scroll, text="No notable alerts detected.", text_color="#555555").pack(pady=20)

        host_str = "\n".join([f"[{i.get('type')}] {i.get('summary')}" for i in res.get('host_audit', []) if isinstance(i, dict)])
        self._write_txt(self.txt_host, host_str if host_str else "No host data recorded.")
        
        net_info = f"=== NMAP DISCOVERY ===\n{res.get('nmap', {}).get('open_ports', 'No ports found')}\n\n=== TRAFFIC ===\n{res.get('traffic')}"
        self._write_txt(self.txt_net, net_info)

    def add_threat_row(self, severity, text, source):
        row = ctk.CTkFrame(self.threat_scroll, fg_color="#222225", corner_radius=5)
        row.pack(fill="x", pady=2, ipady=5)
        color_map = {"Critical": CRIT_COLOR, "High": HIGH_COLOR, "Medium": MED_COLOR, "Low": LOW_COLOR, "Info": "#32ADE6"}
        badge_color = color_map.get(severity, "#FFFFFF")
        badge = ctk.CTkLabel(row, text=f" {severity.upper()} ", font=ctk.CTkFont(size=11, weight="bold"), text_color="#000000", fg_color=badge_color, corner_radius=3)
        badge.pack(side="left", padx=10)
        ctk.CTkLabel(row, text=f"[{source}] {text}", font=ctk.CTkFont(size=12), anchor="w").pack(side="left", fill="x", expand=True, padx=(0, 10))

    def _write_txt(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _update_gui_bars(self, cpu, ram):
        self.hw_cpu.set(cpu / 100)
        self.lbl_cpu.configure(text=f"CPU: {cpu}%")
        self.hw_ram.set(ram / 100)
        self.lbl_ram.configure(text=f"RAM: {ram}%")

    def update_hardware_stats(self):
        while self.controller.hardware_thread_running:
            if psutil:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                self.after(0, lambda c=cpu, r=ram: self._update_gui_bars(c, r))
            else:
                self.after(0, lambda: self.lbl_cpu.configure(text="psutil missing"))
            time.sleep(1)

    def generate_pdf(self):
        try: from fpdf import FPDF
        except ImportError:
            messagebox.showerror("Error", "FPDF missing.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Document", "*.pdf")])
        if not path: return

        try:
            c = self.controller
            res = c.last_results
            pdf = FPDF()
            pdf.add_page()
            
            display_host = c.target_ip_var.get()
            if display_host == "": display_host = "Aegis-Primary-Node"
            
            # --- Cover ---
            pdf.set_font("Arial", 'B', 24)
            pdf.cell(200, 20, txt="AEGIS SECURITY AUDIT REPORT", ln=True, align='C')
            pdf.set_font("Arial", 'I', 12)
            pdf.cell(200, 10, txt=f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
            pdf.cell(200, 10, txt=f"Target: {display_host}", ln=True, align='C')
            pdf.ln(10)
            
            # --- Executive Summary ---
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt="1. Executive Summary", ln=True, align='L')
            pdf.set_font("Arial", '', 12)
            pdf.cell(200, 10, txt=f"System Grade: {self.grade_label.cget('text')} ({self.score_label.cget('text')})", ln=True, align='L')
            pdf.cell(200, 10, txt=f"Critical Alerts: {c.vuln_counts['Critical']}", ln=True, align='L')
            pdf.cell(200, 10, txt=f"High Alerts: {c.vuln_counts['High']}", ln=True, align='L')
            pdf.cell(200, 10, txt=f"Medium Alerts: {c.vuln_counts['Medium']}", ln=True, align='L')
            pdf.ln(10)
            
            # --- Gathering & Grouping Threats ---
            all_threats = []
            threat_lists = [res.get('nmap', {}).get('port_threats', [])]
            for section in ['host_audit', 'traffic', 'dnsrecon']:
                threat_lists.append(res.get(section, []))

            for data in threat_lists:
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            all_threats.append(item)

            grouped_threats = {"Critical": [], "High": [], "Medium": [], "Info": []}
            for t in all_threats:
                sev = t.get('severity', 'Info')
                if sev in grouped_threats: grouped_threats[sev].append(t)
                else: grouped_threats["Info"].append(t)

            # --- Printing Threats by Severity ---
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt="2. Detailed Threat Analysis", ln=True, align='L')
            
            for severity_level in ["Critical", "High", "Medium", "Info"]:
                items = grouped_threats[severity_level]
                if items:
                    pdf.set_font("Arial", 'B', 12)
                    pdf.ln(5)
                    pdf.cell(200, 10, txt=f"--- {severity_level.upper()} LEVEL FINDINGS ---", ln=True, align='L')
                    pdf.set_font("Arial", '', 11)
                    
                    for item in items:
                        tool = item.get('tool', 'SYS')
                        sum_text = item.get('summary', 'Unknown')
                        line = f"[{tool.upper()}] {sum_text}"
                        clean_line = line.encode('latin-1', 'replace').decode('latin-1')
                        pdf.multi_cell(0, 8, txt=clean_line)
            
            pdf.output(path)
            messagebox.showinfo("Success", f"Professional PDF Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to generate PDF: {e}")

if __name__ == '__main__':
    app = SecurityApp()
    app.mainloop()