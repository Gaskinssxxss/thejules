# Current Test Profiles

File ini mencatat profile yang saat ini dipakai di lab.

## ESP32

```text
URL: http://ESP32_IP
User: admin
Password: CHANGE_ME
```

## Local Lab TCP SYN

Config:

```text
config/current-local-lab.json
```

Run collector di PC B:

```bash
tools/start_packet_collector.sh config/current-local-lab.json
```

Attack dari PC A:

```bash
TARGET=SERVER_TARGET_IP
sudo hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

## VPS Public TCP SYN

Config:

```text
config/current-vps-relay.json
```

Catatan:

- VPS public SSH port `35122` dipetakan oleh provider ke internal SSH port `22`.
- Collector di VPS melihat destination port sebagai `22`.
- Ganti `collector.esp32_url` dengan URL relay Cloudflare yang aktif setiap kali tunnel dibuat ulang.

Run relay di PC B:

```bash
tools/start_relay_tunnel.sh config/current-vps-relay.json
tools/run_cloudflare_tunnel_opsi_a.sh 18080
```

Run collector di VPS setelah `collector.esp32_url` diisi URL relay:

```bash
python3 tools/set_config_value.py config/current-vps-relay.json collector.esp32_url https://URL_RELAY_TRYCLOUDFLARE
tools/start_packet_collector.sh config/current-vps-relay.json
```

Attack dari PC A:

```bash
TARGET=SERVER_PUBLIC_IP
sudo hping3 -S -c 500 -i u1000 -p 35122 $TARGET
```

## VPS Public HTTP DDoS

Config:

```text
config/current-vps-http-ddos-public.json
```

Catatan:

- HTTP target berjalan di VPS pada port publik `8080`.
- Ganti `http_target.esp32_url` dengan URL relay yang aktif jika ESP32 berada di jaringan lokal/NAT.

Run relay di PC B:

```bash
tools/start_relay_tunnel.sh config/current-vps-relay.json
tools/run_cloudflare_tunnel_opsi_a.sh 18080
```

Run HTTP target di VPS setelah `http_target.esp32_url` diisi URL relay:

```bash
python3 tools/set_config_value.py config/current-vps-http-ddos-public.json http_target.esp32_url https://URL_RELAY_TRYCLOUDFLARE
tools/start_http_target.sh config/current-vps-http-ddos-public.json
```

Attack dari PC A:

```bash
URL=http://SERVER_PUBLIC_IP:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```
