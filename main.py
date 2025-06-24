import sys, time, queue, webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import pyshark
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import folium
from folium.plugins import MarkerCluster
import geoip2.database

from reputation import check_ip_reputation


class ReputationThread(QThread):
    result_ready = pyqtSignal(int, str)

    def __init__(self, ip_queue, row_ip_map):
        super().__init__()
        self.ip_queue = ip_queue
        self.row_ip_map = row_ip_map
        self.cache = {}

    def run(self):
        while not self.ip_queue.empty():
            row = self.ip_queue.get()
            ip = self.row_ip_map[row]
            if ip in self.cache:
                rep = self.cache[ip]
            else:
                rep = check_ip_reputation(ip)
                self.cache[ip] = rep
                time.sleep(1)  # Hindari rate-limit
            self.result_ready.emit(row, rep)


class MalwareTrafficAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MalTraf - IP Reputation & GeoIP Visualization")
        self.resize(1000, 600)

        layout = QVBoxLayout(self)
        label = QLabel("📡 Load PCAP - Analyze IPs - Realtime Reputation - GeoIP + Protocol Map")
        layout.addWidget(label)

        btns = QHBoxLayout()
        self.btn_open = QPushButton("Open PCAP")
        self.btn_open.clicked.connect(self.load_pcap)
        btns.addWidget(self.btn_open)

        self.btn_viz = QPushButton("Visualize GeoIP & Protocols")
        self.btn_viz.clicked.connect(self.show_visualization)
        btns.addWidget(self.btn_viz)

        layout.addLayout(btns)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Src IP", "Dst IP", "Protocol", "Reputation"])
        layout.addWidget(self.table)

        self.row_ip_map = {}
        self.reputation_queue = queue.Queue()
        self.reputation_thread = None
        self.seen_ip_pairs = set()
        self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')  # 🗺 Pastikan file ini tersedia
        self.country_counts = defaultdict(int)
        self.protocol_counts = Counter()

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if path:
            self.analyze_pcap(path)

    def analyze_pcap(self, path):
        self.table.setRowCount(0)
        self.row_ip_map.clear()
        self.seen_ip_pairs.clear()
        self.country_counts.clear()
        self.protocol_counts.clear()

        try:
            cap = pyshark.FileCapture(path, use_json=True, include_raw=False)
            row = 0
            for pkt in cap:
                if not hasattr(pkt, 'ip'):
                    continue

                src = pkt.ip.src
                dst = pkt.ip.dst
                proto = pkt.highest_layer or pkt.transport_layer
                time_str = pkt.sniff_time.strftime('%H:%M:%S')

                # Hindari IP lokal & duplikat
                if src.startswith(("127.", "192.168", "10.", "0.", "172.")) and dst.startswith(("127.", "192.168", "10.", "0.", "172.")):
                    continue

                for ip in [src, dst]:
                    if (src, dst, ip) in self.seen_ip_pairs:
                        continue
                    self.seen_ip_pairs.add((src, dst, ip))

                    self.table.insertRow(row)
                    self.table.setItem(row, 0, QTableWidgetItem(time_str))
                    self.table.setItem(row, 1, QTableWidgetItem(src))
                    self.table.setItem(row, 2, QTableWidgetItem(dst))
                    self.table.setItem(row, 3, QTableWidgetItem(proto))
                    self.table.setItem(row, 4, QTableWidgetItem("Checking..."))

                    self.row_ip_map[row] = ip
                    self.reputation_queue.put(row)
                    self.update_country_count(ip)
                    self.protocol_counts[proto] += 1
                    row += 1

                    if row >= 300:
                        break

            cap.close()
            self.start_reputation_thread()

        except Exception as e:
            print(f"[!] Failed to analyze PCAP: {e}")

    def update_country_count(self, ip):
        if not self.geoip_reader:
            return
        try:
            response = self.geoip_reader.city(ip)
            country = response.country.name or "Unknown"
            self.country_counts[ip] += 1  # Simpan per-IP, bukan hanya negara
        except:
            pass

    def start_reputation_thread(self):
        self.reputation_thread = ReputationThread(self.reputation_queue, self.row_ip_map)
        self.reputation_thread.result_ready.connect(self.update_reputation)
        self.reputation_thread.start()

    def update_reputation(self, row, rep):
        self.table.setItem(row, 4, QTableWidgetItem(rep))

    def show_visualization(self):
        if not self.country_counts and not self.protocol_counts:
            print("[!] No data to visualize.")
            return

        # --- GeoIP map ---
        m = folium.Map(location=[0, 0], zoom_start=2)
        marker_cluster = MarkerCluster().add_to(m)

        for ip in self.country_counts:
            try:
                response = self.geoip_reader.city(ip)
                lat = response.location.latitude
                lon = response.location.longitude
                country = response.country.name or "Unknown"
                folium.Marker(
                    location=[lat, lon],
                    popup=f"{country}\nIP: {ip}",
                    icon=folium.Icon(color="red", icon="info-sign")
                ).add_to(marker_cluster)
            except:
                continue

        map_path = "geoip_map.html"
        m.save(map_path)
        webbrowser.open(map_path)

        # --- Protocol chart ---
        if self.protocol_counts:
            plt.figure(figsize=(6, 4))
            plt.bar(list(self.protocol_counts.keys()), list(self.protocol_counts.values()), color='skyblue')
            plt.title("Protocol Usage")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MalwareTrafficAnalyzer()
    window.show()
    sys.exit(app.exec_())
