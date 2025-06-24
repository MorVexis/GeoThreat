# GeoThreat 🛰️ - Malicious IP Detection & GeoIP Visualizer

**GeoThreat** adalah GUI-based PCAP analyzer yang dirancang untuk memudahkan investigasi trafik mencurigakan. Tools ini secara otomatis:
- Mengekstrak semua IP dari file PCAP
- Mengecek reputasi IP via **VirusTotal** dan **AbuseIPDB**
- Menampilkan peta lokasi IP (GeoIP)
- Menunjukkan statistik penggunaan protokol (HTTP, DNS, TLS, dll)

> 🎯 Cocok digunakan untuk analyst SOC, DFIR, penetration tester, dan network forensic investigator.

---

## ✨ Fitur

- ✅ Deteksi IP **malicious/suspicious** via VirusTotal + AbuseIPDB
- 🌍 Visualisasi lokasi IP dari file PCAP (berbasis GeoIP)
- 📊 Statistik protokol (HTTP, DNS, TCP, TLS, dsb)
- 🚫 IP lokal otomatis diabaikan
- 🧠 Reputasi disimpan sementara (cache) agar tidak duplikat query

---

## 🧪 Screenshot

![GeoThreat Screenshot](assets/screenshot.png) ![GeoThreat Screenshot](assets/screenshot.png) ![GeoThreat Screenshot](assets/screenshot.png)

---

## 🚀 Cara Jalankan

1. **Install library yang dibutuhkan**:
   ```bash
   pip install -r requirements.txt
