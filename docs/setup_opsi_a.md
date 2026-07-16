# Setup Opsi 1

Opsi 1 menempatkan collector langsung pada server target. ESP32 menerima telemetry dan menjalankan rule-based detection.

## 1. Flash Firmware ESP32

Salin konfigurasi:

```bash
cd firmware/telemetry_ids_esp32
cp config.example.h config.h
```

Isi:

- SSID Wi-Fi
- Password Wi-Fi
- Username Web UI
- Password Web UI

Upload firmware ke ESP32 menggunakan Arduino IDE atau toolchain yang digunakan.

## 2. Cek ESP32

```bash
python3 tools/healthcheck.py --esp32-url http://ESP32_IP
```

Jika berhasil, ESP32 siap menerima telemetry di:

```text
POST http://ESP32_IP/telemetry
```

## 3. Direct Server

Salin config:

```bash
cp config/direct-server.example.json config/my-direct-server.json
```

Edit:

- `collector.interface`
- `collector.esp32_url`
- `collector.target_ip`
- `collector.target_ports`
- `collector.test_id`

Jalankan:

```bash
sudo python3 tools/start_collector_mode.py config/my-direct-server.json --component collector
```

## 4. Local Lab

Salin config:

```bash
cp config/local-lab.example.json config/my-local-lab.json
```

Edit sesuai interface dan IP PC target.

Jalankan di PC target:

```bash
sudo python3 tools/start_collector_mode.py config/my-local-lab.json --component collector
```

## 5. HTTP Request Counter

HTTP request counter sudah berjalan di dalam hybrid collector. Setelah collector aktif, uji endpoint HTTP:

```bash
curl http://SERVER_TARGET_IP:8080
```

Kirim request flood terkontrol:

```bash
URL=http://SERVER_TARGET_IP:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

## 6. Ambil Log

```bash
curl -u admin:CHANGE_ME http://ESP32_IP/telemetry.csv
curl -u admin:CHANGE_ME http://ESP32_IP/alerts.csv
curl -u admin:CHANGE_ME http://ESP32_IP/stats.csv
```
