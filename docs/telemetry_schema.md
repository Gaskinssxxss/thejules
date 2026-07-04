# Telemetry Schema Opsi 1

ESP32 menerima ringkasan traffic dari collector melalui `POST /telemetry`.

Endpoint:

```text
POST http://IP_ESP32/telemetry
Authorization: Basic admin:CHANGE_ME
Content-Type: application/json
```

Payload:

```json
{
  "test_id": "TEST_TCP_SYN_01",
  "proto": "TCP",
  "src_ip": "110.136.217.94",
  "dst_ip": "SERVER_INTERNAL_IP",
  "dst_port": 8080,
  "packet_count": 120,
  "syn_count": 120,
  "payload_bytes": 0,
  "window_ms": 5000,
  "first_seen_ms": 1000,
  "last_seen_ms": 6000
}
```

Makna field:

- `test_id`: identitas skenario uji.
- `proto`: `TCP`, `HTTP`, atau protocol lain yang dikirim collector sebagai telemetry.
- `src_ip`: alamat sumber traffic.
- `dst_ip`: alamat server target.
- `dst_port`: port layanan server target.
- `packet_count`: jumlah paket pada flow dan window waktu.
- `syn_count`: jumlah paket TCP dengan flag SYN.
- `payload_bytes`: total byte payload pada window waktu.
- `window_ms`: panjang window pengamatan.
- `first_seen_ms`: waktu awal flow teramati oleh collector.
- `last_seen_ms`: waktu akhir flow teramati oleh collector.

Rule utama:

- `RULE_TCP_SYN_001`: alert jika `proto=TCP`, `syn_count >= 100`, dan `window_ms <= 5000`.
- `RULE_DDOS_HTTP_001`: alert jika `proto=HTTP`, `packet_count >= 200`, dan `window_ms <= 5000`.

Output ESP32:

- `/`: dashboard.
- `/alerts.csv`: log alert.
- `/telemetry.csv`: log telemetry.
- `/stats.csv`: statistik global.

Catatan:

- DDoS pada versi ini diuji sebagai TCP SYN Flood pada layer 4 dan HTTP request flood pada layer 7.
- UDP dapat tetap dicatat sebagai telemetry jika dikirim collector, tetapi bukan rule utama pada scope versi ini.
