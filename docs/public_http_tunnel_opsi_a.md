# Fallback Simulasi Server Publik dengan Cloudflare Tunnel

Dokumen ini dipakai sebagai fallback ketika tidak tersedia endpoint publik seperti VPS atau public IP dengan port forwarding. Untuk KPI utama Opsi 1 saat ini, pengujian HTTP DDoS lebih diarahkan ke endpoint publik VPS.

## Tujuan

Merepresentasikan layanan web publik yang dapat diakses dari luar jaringan dan menguji DDoS pada application layer:

```text
Attacker eksternal
        |
        v
Cloudflare Tunnel URL
        |
        v
Server lokal + HTTP collector
        |
        v
ESP32 rule engine
```

Catatan batasan:

- Skema ini valid untuk pengujian DDoS berbentuk HTTP request flood.
- Skema ini tidak valid untuk TCP SYN flood mentah karena Cloudflare Tunnel bekerja sebagai reverse proxy.
- Pengujian TCP SYN flood mentah tetap dilakukan pada server target yang menerima traffic TCP langsung, misalnya VPS publik atau server target asli.

## Jalankan HTTP target server di PC B

```bash
python3 collector/http_target_server.py \
  --server-ip PC_B_PUBLIC_SIM \
  --esp32-url http://ESP32_IP \
  --port 8080 \
  --test-id TEST_DDOS_HTTP_TUNNEL_01
```

## Jalankan Cloudflare Tunnel di PC B

```bash
tools/run_cloudflare_tunnel_opsi_a.sh 8080
```

Cloudflare akan memberi URL sementara, misalnya:

```text
https://nama-random.trycloudflare.com
```

## Uji akses normal dari PC A atau jaringan luar

```bash
curl https://URL_TRYCLOUDFLARE
```

## Uji DDoS HTTP request flood ringan terkontrol

```bash
URL=https://URL_TRYCLOUDFLARE; for i in {1..300}; do curl -s "$URL/?i=$i" >/dev/null; done
```

Jika request serial terlalu lambat dan tidak melewati threshold dalam 5 detik, gunakan request paralel:

```bash
URL=https://URL_TRYCLOUDFLARE
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

## Cek hasil di ESP32

```bash
curl -u admin:CHANGE_ME http://ESP32_IP/stats.csv
curl -u admin:CHANGE_ME http://ESP32_IP/alerts.csv
curl -u admin:CHANGE_ME http://ESP32_IP/telemetry.csv
```

Rule yang diharapkan muncul:

```text
RULE_DDOS_HTTP_001
```
