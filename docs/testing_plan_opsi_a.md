# Rencana Pengujian Opsi 1

Tujuan pengujian adalah memastikan collector dapat mengirim telemetry ke ESP32 dan rule pada ESP32 dapat membedakan traffic normal dan traffic serangan.

Skenario minimal:

| ID | Skenario | Ekspektasi |
| --- | --- | --- |
| TEST_NORMAL_HTTP_01 | HTTP normal ke server | Tidak muncul alert |
| TEST_TCP_SYN_LOW_01 | TCP SYN rendah | Tidak muncul alert jika di bawah threshold |
| TEST_TCP_SYN_HIGH_01 | TCP SYN tinggi | Muncul alert `RULE_TCP_SYN_001` |
| TEST_DDOS_HTTP_LOW_01 | HTTP request ringan ke endpoint publik | Tidak muncul alert jika di bawah threshold |
| TEST_DDOS_HTTP_HIGH_01 | HTTP request flood ke endpoint publik | Muncul alert `RULE_DDOS_HTTP_001` |

KPI rinci tersedia di:

```text
docs/kpi_pengujian_opsi_1.md
```

Langkah validasi firmware tanpa collector:

```bash
python3 tools/send_test_telemetry.py --esp32-url http://IP_ESP32 --scenario all --target-ip 192.168.4.4
curl -u admin:CHANGE_ME http://IP_ESP32/alerts.csv
curl -u admin:CHANGE_ME http://IP_ESP32/stats.csv
```

Langkah pengujian collector lokal:

```bash
python3 -m http.server 8080
```

Pada terminal lain di PC B:

```bash
sudo python3 collector/collector.py \
  --interface NAMA_INTERFACE_SERVER \
  --esp32-url http://IP_ESP32 \
  --target-ip IP_PC_B \
  --target-ports 8080 \
  --test-id TEST_TCP_SYN_LAB_01
```

Dari PC A:

```bash
TARGET=IP_PC_B; curl -s http://$TARGET:8080 >/dev/null
TARGET=IP_PC_B; for i in {1..200}; do curl -s http://$TARGET:8080 >/dev/null; done
TARGET=IP_PC_B; hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

Langkah pengujian publik dengan VPS mengikuti KPI di `docs/kpi_pengujian_opsi_1.md`, yaitu:

```text
PC A attacker -> public IP/port VPS -> collector pada VPS -> relay opsional -> ESP32
```

Catatan:

- `collector.py` membutuhkan hak akses raw socket. Jalankan dengan `sudo` atau beri capability `cap_net_raw`.
- Jika `hping3` belum tersedia, pengujian SYN flood bisa diganti dengan tool lain yang mampu mengirim TCP SYN tanpa menyelesaikan koneksi.
- Relay bukan bagian wajib arsitektur Opsi 1. Relay hanya dipakai saat pengujian karena ESP32 berada di jaringan lokal yang tidak bisa diakses langsung dari VPS.
