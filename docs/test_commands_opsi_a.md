# Test Commands Opsi 1

Gunakan command ini hanya pada server milik sendiri, PC lab, atau server yang diberi izin eksplisit.

## Variabel Dasar

```bash
export ESP32=http://ESP32_IP
export ESP32_USER=admin
export ESP32_PASS=CHANGE_ME
export TARGET=SERVER_TARGET_IP
```

## Cek ESP32

```bash
python3 tools/healthcheck.py --esp32-url "$ESP32" --username "$ESP32_USER" --password "$ESP32_PASS"
```

## Jalankan Hybrid Collector

```bash
sudo python3 tools/start_collector_mode.py config/local-lab.example.json --component collector
```

Atau langsung:

```bash
sudo python3 collector/collector.py \
  --interface wlan0 \
  --esp32-url "$ESP32" \
  --username "$ESP32_USER" \
  --password "$ESP32_PASS" \
  --target-ip "$TARGET" \
  --target-ports 8080 \
  --http-host 0.0.0.0 \
  --http-port 8080 \
  --test-id TEST_LOCAL_LAB_TCP_SYN_01
```

## Traffic Normal

```bash
curl -s "http://$TARGET:8080" >/dev/null
```

## HTTP Request Flood Terkontrol

```bash
URL=http://$TARGET:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

## TCP SYN Flood Terkontrol

```bash
sudo hping3 -S -c 500 -i u1000 -p 8080 "$TARGET"
```

## Ambil Log ESP32

```bash
curl -u "$ESP32_USER:$ESP32_PASS" "$ESP32/telemetry.csv"
curl -u "$ESP32_USER:$ESP32_PASS" "$ESP32/alerts.csv"
curl -u "$ESP32_USER:$ESP32_PASS" "$ESP32/stats.csv"
```
