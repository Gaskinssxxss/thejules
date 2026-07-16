# Deployment Modes

Sistem dibuat dengan satu collector utama yang berjalan pada server target. Collector ini bersifat hybrid: membaca fitur TCP SYN dari packet pada interface jaringan dan sekaligus menjalankan HTTP request counter pada port layanan uji.

Mode aktif yang dipertahankan:

1. `direct-server`
2. `local-lab`

## Mode 1: Direct Server

Mode ini adalah arsitektur ideal untuk implementasi pada server target sebenarnya.

```text
Server target + hybrid collector -> ESP32
```

Server target dapat berupa server layanan Universitas Mataram atau server uji resmi yang diberi izin untuk menjalankan collector. Collector membaca traffic masuk pada interface server, menghitung fitur per window waktu, lalu mengirim telemetry langsung ke ESP32.

Gunakan config:

```text
config/direct-server.example.json
```

Jalankan:

```bash
sudo python3 tools/start_collector_mode.py config/direct-server.example.json --component collector
```

Yang perlu diubah saat deployment:

- `collector.interface`
- `collector.target_ip`
- `collector.target_ports`
- `collector.http_host`
- `collector.http_port`
- `collector.esp32_url`
- `collector.test_id`
- `collector.window_ms`

## Mode 2: Local Lab

Mode ini dipakai untuk demo dan pengujian lokal terkontrol.

```text
PC A attacker/tester -> PC B target + hybrid collector -> ESP32
```

Mode ini merepresentasikan prinsip direct-server, tetapi server target diganti dengan PC/laptop lokal. Mode ini berguna saat belum ada akses ke server kampus.

Gunakan config:

```text
config/local-lab.example.json
```

Jalankan di PC target:

```bash
sudo python3 tools/start_collector_mode.py config/local-lab.example.json --component collector
```

## Healthcheck

Cek ESP32:

```bash
python3 tools/healthcheck.py --esp32-url http://ESP32_IP
```

Kirim probe telemetry:

```bash
python3 tools/healthcheck.py --esp32-url http://ESP32_IP --send-probe
```

## Interactive CLI

Untuk membuat config tanpa edit JSON manual:

```bash
tools/thejules
```

CLI akan memandu:

- memilih mode deployment,
- mengisi interface, target IP, target port, HTTP bind host/port, dan endpoint ESP32,
- menyimpan file config baru,
- menampilkan command run,
- menjalankan healthcheck ESP32 jika URL ESP32 bisa dijangkau.

## Prinsip Implementasi

- Hanya ada satu collector utama.
- Jika sistem diterapkan pada server target kampus, gunakan `direct-server`.
- Jika hanya melakukan demo lokal, gunakan `local-lab`.
- Collector mengirim telemetry `TCP` dan `HTTP` ke ESP32.
- Rule-based detection tetap dilakukan pada ESP32.
