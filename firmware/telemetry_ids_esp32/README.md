# ESP32 Telemetry IDS Firmware

Firmware ini menjadikan ESP32 sebagai rule engine untuk Opsi 1.

Fitur:

- Web UI dengan basic authentication.
- Endpoint `POST /telemetry`.
- Rule `RULE_TCP_SYN_001`.
- Rule `RULE_DDOS_HTTP_001`.
- Export `alerts.csv`, `telemetry.csv`, dan `stats.csv`.
- AP fallback `ESP32-IDS` jika gagal join Wi-Fi.

Konfigurasi utama dibuat dari template:

```bash
cp config.example.h config.h
```

Setelah itu isi SSID, password Wi-Fi, dan kredensial Web UI pada `config.h`.
File `config.h` sengaja tidak dimasukkan ke Git karena berisi konfigurasi lokal.
