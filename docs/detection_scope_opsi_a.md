# Scope Deteksi Opsi 1

Versi pengembangan ini difokuskan pada dua jenis serangan yang sesuai dengan konsep collector di server target. Pada implementasi riil di lingkungan Universitas Mataram, collector ditempatkan pada server target yang menjalankan layanan kampus atau server uji resmi.

## 1. TCP SYN Flood

Layer:

```text
Layer 4 / Transport
```

Parameter utama:

- `proto = TCP`
- `syn_count`
- `packet_count`
- `dst_port`
- `window_ms`

Rule:

```text
RULE_TCP_SYN_001
Alert jika proto = TCP, syn_count >= 100, payload_bytes = 0, dan window <= 5000 ms.
```

Alur:

```text
Attacker/tester -> server target + hybrid collector -> ESP32
```

## 2. HTTP Request Flood

Layer:

```text
Layer 7 / Application
```

Parameter utama:

- `proto = HTTP`
- `packet_count` atau request count
- `src_ip`
- `dst_ip`
- `dst_port`
- `window_ms`

Rule:

```text
RULE_DDOS_HTTP_001
Alert jika proto = HTTP dan packet_count >= 200 dalam window <= 5000 ms.
```

Alur:

```text
Client/tester -> server target + hybrid collector -> ESP32
```

## Batasan

- Sistem melakukan deteksi dan alerting, bukan mitigasi otomatis.
- ESP32 memproses telemetry summary, bukan raw packet penuh.
- Threshold awal berasal dari pengujian lab dan harus dikalibrasi ulang pada traffic produksi.
- Sistem tidak melakukan dekripsi payload HTTPS.
- Sistem tidak diklaim memantau seluruh jaringan Universitas Mataram; cakupannya mengikuti lokasi collector.
