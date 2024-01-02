import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from ddos_detection_tool.detection.ddos_detector import (
    start_sniffing, stop_sniffing, set_sinkhole_ip, set_new_route_ip,
    set_reputation_service_url, set_threshold_values, set_traffic_shaping_params,
    set_internal_ip_ranges, block_ip
)

class DDoSDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Detection Tool by shutdow_n (Discord)")

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(pady=10)
        self.stop_button.config(state=tk.DISABLED)

        self.detected_attacks_label = tk.Label(root, text="Detected Attacks:")
        self.detected_attacks_label.pack(pady=5)

        self.detected_attacks_text = tk.Text(root, height=10, width=50, state=tk.DISABLED)
        self.detected_attacks_text.pack(pady=5)

        self.sinkhole_label = tk.Label(root, text="Sinkhole IP:")
        self.sinkhole_label.pack(pady=5)
        self.sinkhole_entry = tk.Entry(root)
        self.sinkhole_entry.pack(pady=5)

        self.new_route_label = tk.Label(root, text="New Route IP:")
        self.new_route_label.pack(pady=5)
        self.new_route_entry = tk.Entry(root)
        self.new_route_entry.pack(pady=5)

        self.reputation_service_label = tk.Label(root, text="Reputation Service URL:")
        self.reputation_service_label.pack(pady=5)
        self.reputation_service_entry = tk.Entry(root)
        self.reputation_service_entry.pack(pady=5)

        self.threshold_packets_label = tk.Label(root, text="Threshold Packets per Second:")
        self.threshold_packets_label.pack(pady=5)
        self.threshold_packets_entry = tk.Entry(root)
        self.threshold_packets_entry.pack(pady=5)

        self.threshold_time_label = tk.Label(root, text="Threshold Time Interval (seconds):")
        self.threshold_time_label.pack(pady=5)
        self.threshold_time_entry = tk.Entry(root)
        self.threshold_time_entry.pack(pady=5)

        self.max_packets_label = tk.Label(root, text="Maximum Allowed Packets:")
        self.max_packets_label.pack(pady=5)
        self.max_packets_entry = tk.Entry(root)
        self.max_packets_entry.pack(pady=5)

        self.latency_label = tk.Label(root, text="Latency for Traffic Shaping (ms):")
        self.latency_label.pack(pady=5)
        self.latency_entry = tk.Entry(root)
        self.latency_entry.pack(pady=5)

        self.bandwidth_limit_label = tk.Label(root, text="Bandwidth Limit for Traffic Shaping (e.g., 1Mbit):")
        self.bandwidth_limit_label.pack(pady=5)
        self.bandwidth_limit_entry = tk.Entry(root)
        self.bandwidth_limit_entry.pack(pady=5)

        # internal ranges
        self.internal_ip_ranges_label = tk.Label(root, text="Internal IP Ranges (CIDR notation, comma-separated):")
        self.internal_ip_ranges_label.pack(pady=5)
        self.internal_ip_ranges_entry = tk.Entry(root)
        self.internal_ip_ranges_entry.pack(pady=5)

        self.set_ip_button = tk.Button(root, text="Set IP Configuration", command=self.set_ip_configuration)
        self.set_ip_button.pack(pady=10)

        self.set_threshold_button = tk.Button(root, text="Set Custom Thresholds", command=self.set_custom_thresholds)
        self.set_threshold_button.pack(pady=10)

        self.set_traffic_shaping_button = tk.Button(root, text="Set Traffic Shaping Params", command=self.set_traffic_shaping_params)
        self.set_traffic_shaping_button.pack(pady=10)

        self.block_ip_button = tk.Button(root, text="Block IP", command=self.block_ip)
        self.block_ip_button.pack(pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def start_sniffing(self):
        print("DDoS Detection Tool - Press Stop Sniffing to stop")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.detected_attacks_text.config(state=tk.NORMAL)
        self.detected_attacks_text.delete("1.0", tk.END)

        start_sniffing(self.update_detected_attacks)

    def stop_sniffing(self):
        print("Sniffing stopped.")
        stop_sniffing()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_detected_attacks(self, attack_info):
        self.detected_attacks_text.insert(tk.END, f"{datetime.now()}: {attack_info}\n")
        self.detected_attacks_text.see(tk.END)

    def on_close(self):
        self.root.destroy()

    def set_ip_configuration(self):
        sinkhole_ip = self.sinkhole_entry.get()
        new_route_ip = self.new_route_entry.get()
        reputation_service_url = self.reputation_service_entry.get()
        internal_ip_ranges = self.internal_ip_ranges_entry.get()

        set_sinkhole_ip(sinkhole_ip)
        set_new_route_ip(new_route_ip)
        set_reputation_service_url(reputation_service_url)
        set_internal_ip_ranges(internal_ip_ranges)

    def set_custom_thresholds(self):
        threshold_packets = int(self.threshold_packets_entry.get())
        threshold_time = int(self.threshold_time_entry.get())
        max_packets = int(self.max_packets_entry.get())

        set_threshold_values(threshold_packets, threshold_time, max_packets)

    def set_traffic_shaping_params(self):
        latency = self.latency_entry.get()
        bandwidth_limit = self.bandwidth_limit_entry.get()

        set_traffic_shaping_params(latency, bandwidth_limit)

    def block_ip(self):
        ip_to_block = self.sinkhole_entry.get()
        block_ip(ip_to_block)
        messagebox.showinfo("Block IP", f"IP {ip_to_block} blocked successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSDetectionApp(root)
    root.mainloop()