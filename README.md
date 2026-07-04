# TheJules ESP32 Rule-Based IDS

Prototype sistem deteksi serangan berbasis rule untuk penelitian tugas akhir.
Arsitektur terbaru menempatkan collector pada server target, sedangkan ESP32
berperan sebagai rule engine, Web UI, alert dashboard, dan CSV logger.

## Scope Deteksi

- TCP SYN Flood melalui telemetry `syn_count`.
- HTTP request flood sebagai representasi DDoS layer aplikasi melalui telemetry
  `http_requests`.

## Struktur Project

- `firmware/telemetry_ids_esp32/` firmware ESP32 rule engine dan Web UI.
- `collector/` packet collector, HTTP target collector, dan relay telemetry.
- `tools/` CLI/helper untuk menjalankan mode deployment dan pengujian.
- `config/` template konfigurasi deployment.
- `docs/` dokumentasi teknis arsitektur, setup, schema, dan rencana pengujian.
- `systemd/` contoh service untuk collector dan relay.

Folder skripsi, referensi, hasil uji, virtualenv, dan prototype lama tidak
diikutkan ke Git.

## Setup Firmware ESP32

```bash
cd firmware/telemetry_ids_esp32
cp config.example.h config.h
```

Isi `config.h` sesuai Wi-Fi dan kredensial lokal, lalu upload
`telemetry_ids_esp32.ino` ke ESP32 melalui Arduino IDE atau toolchain yang
digunakan.

## Setup Collector

Collector menggunakan Python standard library. Untuk packet collector pada Linux,
jalankan dengan privilege root karena memakai raw socket.

```bash
cp config/direct-server.example.json config/my-direct-server.json
python3 tools/thejules_cli.py
```

Atau jalankan collector langsung:

```bash
sudo python3 collector/collector.py \
  --interface eth0 \
  --esp32-url http://ESP32_IP \
  --target-ip SERVER_TARGET_IP \
  --target-ports 80,443,8080 \
  --test-id TEST_DIRECT_SERVER_TCP_SYN_01
```

## Healthcheck ESP32

```bash
python3 tools/healthcheck.py --esp32-url http://ESP32_IP
```

## Catatan Keamanan

Jangan commit `config.h`, `config/current-*.json`, password Wi-Fi, password Web
UI, IP pengujian privat, atau hasil eksperimen mentah. Gunakan file `.example`
sebagai template publik.
