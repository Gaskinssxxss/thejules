# KPI Pengujian Opsi 1

Dokumen ini menjadi indikator keberhasilan sistem Opsi 1, yaitu collector ditempatkan pada server target dan ESP32 berperan sebagai rule-based detection engine.

## 1. Validasi Arsitektur

| No | KPI | Cara Cek | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | Server target tersedia | Akses service dari client/tester | Client dapat mengakses service target |
| 2 | Collector berjalan pada server target | Cek proses collector di server target | Collector aktif dan membaca interface target |
| 3 | ESP32 aktif sebagai rule engine | Buka `/stats.csv` atau Web UI ESP32 | ESP32 merespons HTTP 200 |
| 4 | Telemetry endpoint terjangkau | Collector POST ke ESP32 | Response `{"ok":true}` diterima |
| 5 | Log tersedia | Buka `/telemetry.csv`, `/alerts.csv`, `/stats.csv` | CSV dapat diunduh dan berisi data |

## 2. Validasi Mode Deployment

| Mode | Tujuan | Kriteria Berhasil |
| --- | --- | --- |
| `direct-server` | Implementasi ideal di server target | Collector POST langsung ke `http://IP_ESP32/telemetry` |
| `local-lab` | Pengujian lokal terkontrol | PC target mengirim telemetry langsung ke ESP32 |
| `local-lab` | Pengujian lokal terkontrol | Hybrid collector menghasilkan telemetry `TCP` dan `HTTP` |

## 3. Validasi Telemetry

| No | Field | Kriteria Berhasil |
| --- | --- | --- |
| 1 | `test_id` | Terisi sesuai skenario uji |
| 2 | `proto` | Bernilai `TCP` atau `HTTP` sesuai skenario |
| 3 | `src_ip` | Menunjukkan IP sumber traffic |
| 4 | `dst_ip` | Menunjukkan server target |
| 5 | `dst_port` | Sesuai port target, misalnya `80`, `443`, atau `8080` |
| 6 | `packet_count` | Bertambah saat traffic masuk |
| 7 | `syn_count` | Bertambah pada skenario TCP SYN Flood |
| 8 | `window_ms` | Bernilai `5000` ms sesuai rule awal |
| 9 | `first_seen_ms` dan `last_seen_ms` | Terisi dan dapat dipakai menghitung delay |

## 4. KPI TCP SYN Flood

Rule:

```text
RULE_TCP_SYN_001
Alert jika proto = TCP, syn_count >= 100, payload_bytes = 0, dan window <= 5000 ms.
```

| No | KPI | Cara Uji | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | Target reachable | `nc -vz SERVER_TARGET_IP PORT` | Port target terbuka |
| 2 | Collector membaca TCP traffic | Jalankan hybrid collector pada server target | Telemetry `proto=TCP` masuk ke ESP32 |
| 3 | SYN counter bertambah | Jalankan traffic SYN terkontrol | `tcp_syn_packets` bertambah |
| 4 | Threshold terlampaui | Kirim SYN >= 100 dalam 5 detik | Alert `RULE_TCP_SYN_001` muncul |
| 5 | Alert berisi bukti | Cek `/alerts.csv` | Ada `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `threshold_count`, `window_ms` |
| 6 | Detection delay tercatat | Cek kolom `detection_delay_ms` | Nilai delay tercatat dalam CSV |

Contoh command uji pada lab yang diizinkan:

```bash
TARGET=SERVER_TARGET_IP
sudo hping3 -S -c 500 -i u1000 -p 8080 $TARGET
```

## 5. KPI HTTP Request Flood

Rule:

```text
RULE_DDOS_HTTP_001
Alert jika proto = HTTP dan packet_count >= 200 dalam window <= 5000 ms.
```

| No | KPI | Cara Uji | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | HTTP target reachable | `curl http://SERVER_TARGET_IP:8080` | Response HTTP muncul dari hybrid collector |
| 2 | HTTP counter berjalan | Jalankan hybrid collector di server target | Request HTTP tercatat sebagai telemetry |
| 3 | Request counter bertambah | Kirim request normal | `http_requests` bertambah |
| 4 | Threshold terlampaui | Kirim >= 200 request dalam 5 detik | Alert `RULE_DDOS_HTTP_001` muncul |
| 5 | Alert berisi bukti | Cek `/alerts.csv` | Ada `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `threshold_count`, `window_ms` |
| 6 | Detection delay tercatat | Cek kolom `detection_delay_ms` | Nilai delay tercatat dalam CSV |

Contoh command uji:

```bash
URL=http://SERVER_TARGET_IP:8080
seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s "$URL/?p={}" >/dev/null
```

## 6. KPI Logging dan Dashboard ESP32

| No | KPI | Endpoint | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | Dashboard aktif | `/` | Web UI dapat diakses dengan login admin |
| 2 | Statistik global | `/stats.csv` | Menampilkan `tcp_syn_packets`, `http_requests`, `alerts_count` |
| 3 | Log telemetry | `/telemetry.csv` | Berisi semua telemetry yang diterima ESP32 |
| 4 | Log alert | `/alerts.csv` | Berisi alert yang melewati threshold |
| 5 | Reset log | `POST /reset` | Counter dan log kembali nol |

## 7. Metrik Evaluasi

| Metrik | Definisi | Cara Mengukur |
| --- | --- | --- |
| True Positive | Serangan terjadi dan alert muncul | Bandingkan skenario serangan dengan `/alerts.csv` |
| False Positive | Traffic normal tetapi alert muncul | Jalankan baseline normal dan cek alert |
| False Negative | Serangan terjadi tetapi alert tidak muncul | Jalankan serangan terkontrol dan cek alert |
| True Negative | Traffic normal dan tidak muncul alert | Jalankan baseline normal |
| Detection delay | Waktu dari traffic awal sampai alert tercatat | Kolom `detection_delay_ms` |
| Telemetry delivery | Collector berhasil mengirim telemetry ke ESP32 | Response POST `ok=true`, data ada di `/telemetry.csv` |

## 8. Baseline Minimal

Sebelum serangan, lakukan baseline:

| Skenario | Durasi | Ekspektasi |
| --- | --- | --- |
| Akses HTTP normal | 5 window | Tidak muncul alert |
| Koneksi TCP normal | 5 window | Tidak muncul alert TCP SYN Flood |
| Request HTTP rendah | < 200 request/5 detik | Tidak muncul alert DDoS |

## 9. Batasan Pengujian

- Pengujian harus dilakukan hanya pada server milik sendiri atau server yang diberi izin.
- Sistem tidak melakukan pemblokiran otomatis.
- Sistem tidak melakukan dekripsi HTTPS.
- Threshold awal perlu dikalibrasi ulang pada traffic nyata.
- Cakupan deteksi mengikuti lokasi collector.
