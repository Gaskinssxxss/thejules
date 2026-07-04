# Deployment Modes

Sistem dibuat agar kode yang sama bisa dipakai di beberapa environment. Perbedaan environment hanya berada pada file konfigurasi dan endpoint telemetry.

## Mode 1: Direct Server

Mode ini adalah arsitektur ideal untuk implementasi pada server target sebenarnya.

```text
Server target + collector -> ESP32
```

Gunakan config:

```text
config/direct-server.example.json
```

Jalankan:

```bash
tools/start_packet_collector.sh config/direct-server.example.json
```

Yang perlu diubah saat deployment:

- `collector.interface`
- `collector.target_ip`
- `collector.target_ports`
- `collector.esp32_url`
- `collector.test_id`

## Mode 2: VPS Relay

Mode ini dipakai untuk pengujian jika collector berada di VPS publik tetapi ESP32 berada di jaringan lokal/NAT.

```text
VPS + collector -> relay PC B -> ESP32
```

Collector tidak perlu tahu apakah endpoint adalah ESP32 langsung atau relay. Collector hanya POST ke `collector.esp32_url`.

Gunakan config:

```text
config/vps-relay.example.json
```

Di PC B:

```bash
tools/start_relay_tunnel.sh config/vps-relay.example.json
tools/run_cloudflare_tunnel_opsi_a.sh 18080
```

Di VPS:

```bash
tools/start_packet_collector.sh config/vps-relay.example.json
```

Untuk VPS NAT, `collector.target_ip` biasanya memakai IP internal VPS yang terlihat pada interface, misalnya `SERVER_INTERNAL_IP`.

## Mode 3: Local Lab

Mode ini dipakai untuk pengujian lokal terkontrol.

```text
PC A attacker -> PC B target + collector -> ESP32
```

Gunakan config:

```text
config/local-lab.example.json
```

Jalankan di PC B:

```bash
tools/start_packet_collector.sh config/local-lab.example.json
```

## Mode 4: VPS Public HTTP DDoS

Mode ini dipakai untuk pengujian DDoS application layer pada endpoint HTTP publik VPS.

```text
PC A attacker -> public IP/port VPS -> HTTP target + app collector -> ESP32/relay
```

Gunakan config:

```text
config/vps-http-ddos-public.example.json
```

Jalankan:

```bash
tools/start_http_target.sh config/vps-http-ddos-public.example.json
```

Jika ESP32 berada di jaringan lokal/NAT, jalankan relay di PC lokal dan isi `http_target.esp32_url` dengan URL relay yang aktif.

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
- mengisi interface, target IP, target port, endpoint ESP32/relay,
- menyimpan file config baru,
- menampilkan command run,
- menjalankan healthcheck ESP32 jika URL ESP32 bisa dijangkau.

## Prinsip Implementasi

- Kode collector tidak diubah antar environment.
- Jika ESP32 reachable langsung, `collector.esp32_url` diisi IP ESP32.
- Jika ESP32 tidak reachable langsung, `collector.esp32_url` diisi URL relay.
- Relay bersifat opsional dan tidak menjalankan deteksi.
- Rule-based detection tetap dilakukan pada ESP32.
