import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import platform
import time
import os
from usb_scanner import USBDefender


class USBDefenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USBDefender GUI")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")
        self.monitoring = False
        self.monitor_thread = None

        self.defender = USBDefender()
        self.create_widgets()
        self.refresh_drives()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TButton", background="#2d2d2d", foreground="white", font=("Segoe UI", 10))
        style.configure("TCombobox", fieldbackground="#2d2d2d", background="#2d2d2d", foreground="white")

        title = ttk.Label(self.root, text="USBDefender - Advanced USB Malware Scanner", font=("Segoe UI", 16, "bold"))
        title.pack(pady=15)

        self.drive_combo = ttk.Combobox(self.root, state="readonly", font=("Segoe UI", 10))
        self.drive_combo.pack(pady=10, ipadx=5, ipady=5)

        btn_frame = tk.Frame(self.root, bg="#1e1e1e")
        btn_frame.pack(pady=10)

        scan_btn = ttk.Button(btn_frame, text="Scan Drive", command=self.scan_selected_drive)
        scan_btn.grid(row=0, column=0, padx=10)

        self.monitor_btn = ttk.Button(btn_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_btn.grid(row=0, column=1, padx=10)

        refresh_btn = ttk.Button(btn_frame, text="Refresh Drives", command=self.refresh_drives)
        refresh_btn.grid(row=0, column=2, padx=10)

        self.export_btn = ttk.Button(btn_frame, text="Export Report", command=self.export_report, state="disabled")
        self.export_btn.grid(row=0, column=3, padx=10)

        self.log_output = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, bg="#121212", fg="#33ff33",
                                                    font=("Consolas", 10), insertbackground="white")
        self.log_output.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.status_label = ttk.Label(self.root, text="Ready", anchor="center", font=("Segoe UI", 10))
        self.status_label.pack(fill=tk.X, pady=5)

    def refresh_drives(self):
        drives = list(self.defender.get_current_drives())
        self.drive_combo['values'] = drives
        if drives:
            self.drive_combo.current(0)
        else:
            self.drive_combo.set('No USB drives detected')

    def scan_selected_drive(self):
        selected = self.drive_combo.get()
        if not selected or 'No USB' in selected:
            messagebox.showwarning("No Drive", "Please select a drive to scan.")
            return

        self.log_output.insert(tk.END, f"\n[+] Scanning drive: {selected}\n")
        self.log_output.see(tk.END)
        self.status_label.config(text=f"Scanning {selected}...")
        self.export_btn.config(state="disabled")

        threading.Thread(target=self.run_scan, args=(selected,), daemon=True).start()

    def run_scan(self, path):
        has_threats = self.defender.scan_drive(path)
        self.log_output.insert(tk.END, f"\n[+] Scan completed. Threats found: {'Yes' if has_threats else 'No'}\n")
        self.log_output.insert(tk.END, f"[+] Drives Scanned: {self.defender.total_drives_scanned}, Files Scanned: {self.defender.total_files_scanned}, Threats: {self.defender.total_threats_found}\n")
        self.log_output.see(tk.END)
        self.status_label.config(text="Scan finished")
        self.export_btn.config(state="normal")

    def toggle_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.status_label.config(text="Monitoring stopped")
            self.monitor_btn.config(text="Start Monitoring")
            self.log_output.insert(tk.END, "\n[+] Monitoring stopped.\n")
            self.log_output.see(tk.END)
        else:
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitoring")
            self.status_label.config(text="Monitoring for USB drives...")
            self.log_output.insert(tk.END, "\n[+] Started monitoring USB drives...\n")
            self.log_output.see(tk.END)
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()

    def monitor_loop(self):
        self.defender.previous_drives = self.defender.get_current_drives()
        while self.monitoring:
            current_drives = self.defender.get_current_drives()
            new_drives = current_drives - self.defender.previous_drives
            if new_drives:
                for drive in new_drives:
                    self.log_output.insert(tk.END, f"\n[+] New drive detected: {drive}\n")
                    self.log_output.see(tk.END)
                    self.status_label.config(text=f"Scanning {drive}...")
                    self.defender.scan_drive(drive)
            self.defender.previous_drives = current_drives
            time.sleep(2)

    def export_report(self):
        report_dir = os.path.expanduser("~/USBDefender_Reports")
        os.makedirs(report_dir, exist_ok=True)
        suspicious_files = []  # Placeholder; would need to pass actual data from scan
        all_files = []         # Placeholder; would need to pass actual data from scan
        fake_drive = self.drive_combo.get() or "Unknown"
        report_path = self.defender.export_report(fake_drive, suspicious_files, all_files, 0)
        if report_path:
            self.log_output.insert(tk.END, f"\n[+] Report exported to: {report_path}\n")
            self.status_label.config(text="Report saved")
        else:
            messagebox.showerror("Export Failed", "Could not save the report.")


if __name__ == "__main__":
    root = tk.Tk()
    icon_path = os.path.join(os.path.dirname(__file__), "usbdefender.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    app = USBDefenderGUI(root)
    root.mainloop()
