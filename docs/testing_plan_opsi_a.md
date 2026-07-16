# Testing Plan Opsi 1

## Tujuan

Pengujian bertujuan memastikan collector dapat membaca traffic pada server target, mengirim telemetry ke ESP32, dan ESP32 dapat menghasilkan alert ketika rule terpenuhi.

## Tahapan

1. Pastikan ESP32 tersambung ke jaringan dan Web UI dapat diakses.
2. Jalankan hybrid collector pada server target atau PC target lab.
3. Pastikan telemetry normal masuk ke `/telemetry.csv`.
4. Jalankan baseline traffic normal.
5. Jalankan traffic rendah di bawah threshold.
6. Jalankan TCP SYN Flood terkontrol di lab yang diizinkan.
7. Jalankan HTTP request flood terkontrol.
8. Unduh `/alerts.csv`, `/telemetry.csv`, dan `/stats.csv`.
9. Hitung TP, TN, FP, FN, dan detection delay.

## Skenario Minimal

| Test ID | Skenario | Ekspektasi |
| --- | --- | --- |
| TEST_NORMAL_HTTP_01 | HTTP normal 20 request | Tidak alert |
| TEST_DDOS_HTTP_LOW_01 | HTTP 80 request | Tidak alert |
| TEST_DDOS_HTTP_HIGH_01 | HTTP 320 request | Alert HTTP DDoS |
| TEST_TCP_SYN_LOW_01 | TCP SYN rendah | Tidak alert |
| TEST_TCP_SYN_HIGH_01 | TCP SYN tinggi | Alert TCP SYN |

## Command Contoh

HTTP normal:

```bash
TARGET=http://SERVER_TARGET_IP:8080
curl -s "$TARGET" >/dev/null
```

HTTP request flood terkontrol:

```bash
URL=http://SERVER_TARGET_IP:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

TCP SYN Flood terkontrol:

```bash
TARGET=SERVER_TARGET_IP
sudo hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

## Catatan Etis

Pengujian flood hanya boleh dilakukan pada server milik sendiri, lab tertutup, atau server yang diberikan izin eksplisit. Jangan menjalankan command flood ke sistem publik atau jaringan produksi tanpa izin.
