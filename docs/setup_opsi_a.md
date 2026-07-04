# Setup Opsi 1 - Collector di Server Target

Opsi 1 menempatkan collector langsung pada server target. Pada implementasi riil, server target dapat berupa server Universitas Mataram. Pada pengujian saat ini, server target dapat direpresentasikan oleh VPS publik atau PC lokal.

## 1. Konfigurasi Wi-Fi ESP32

Edit file:

```text
firmware/telemetry_ids_esp32/config.h
```

Untuk jaringan open:

```cpp
#define WIFI_SSID "nama_ssid"
#define WIFI_PASSWORD ""
#define WIFI_OPEN_NETWORK 1
```

Untuk jaringan WPA/WPA2:

```cpp
#define WIFI_SSID "nama_ssid"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define WIFI_OPEN_NETWORK 0
```

Jika ESP32 gagal masuk ke SSID tersebut, firmware akan membuat AP fallback:

```text
SSID: ESP32-IDS
Password: CHANGE_ME45
Web UI: http://192.168.4.1
Login: admin / CHANGE_ME
```

AP fallback hanya cocok untuk validasi awal. Untuk pengujian Opsi 1 yang benar, collector harus bisa mengirim HTTP POST ke ESP32 atau ke relay jika ESP32 berada di jaringan lokal/NAT.

## 2. Compile dan upload firmware

```bash
arduino-cli compile --fqbn esp32:esp32:esp32doit-devkit-v1 firmware/telemetry_ids_esp32
arduino-cli upload -p /dev/ttyUSB0 --fqbn esp32:esp32:esp32doit-devkit-v1 firmware/telemetry_ids_esp32
```

## 3. Validasi ESP32

Buka Web UI:

```text
http://IP_ESP32
```

Login:

```text
username: admin
password: CHANGE_ME
```

Cek endpoint:

```bash
curl -u admin:CHANGE_ME http://IP_ESP32/stats.csv
```

## 4. Jalankan service target

Untuk pengujian lokal:

```bash
python3 -m http.server 8080
```

## 5. Jalankan collector pada server target

Cek nama interface:

```bash
ip -brief addr
```

Jalankan collector:

```bash
sudo python3 collector/collector.py \
  --interface NAMA_INTERFACE_SERVER \
  --esp32-url http://IP_ESP32 \
  --target-ip IP_SERVER_TARGET \
  --target-ports 8080 \
  --test-id TEST_TCP_SYN_LAB_01
```

Untuk pengujian VPS publik, gunakan config:

```bash
tools/start_packet_collector.sh config/current-vps-relay.json
```

## 6. Jalankan traffic dari PC attacker/tester

Normal HTTP:

```bash
TARGET=IP_SERVER_TARGET; curl -s http://$TARGET:8080 >/dev/null
```

TCP SYN flood:

```bash
TARGET=IP_SERVER_TARGET; hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

Untuk pengujian publik yang sudah dipakai:

```bash
TARGET=SERVER_PUBLIC_IP
sudo hping3 -S -c 500 -i u1000 -p 35122 $TARGET
```

## 7. Ambil hasil

```bash
curl -u admin:CHANGE_ME http://IP_ESP32/stats.csv
curl -u admin:CHANGE_ME http://IP_ESP32/alerts.csv
curl -u admin:CHANGE_ME http://IP_ESP32/telemetry.csv
```
