# KPI Pengujian Opsi 1

Dokumen ini menjadi indikator keberhasilan sistem Opsi 1, yaitu collector ditempatkan pada server target dan ESP32 berperan sebagai rule-based detection engine.

## 1. Validasi Arsitektur

| No | KPI | Cara Cek | Kriteria Berhasil | Status |
| --- | --- | --- | --- | --- |
| 1 | Server target publik tersedia | Akses service dari PC A | PC A dapat mengakses public endpoint server target | OK pada VPS |
| 2 | Collector berjalan pada server target | Cek proses collector di server target/VPS | Collector aktif dan membaca interface target | OK pada uji awal |
| 3 | ESP32 aktif sebagai rule engine | Buka `/stats.csv` atau Web UI ESP32 | ESP32 merespons HTTP 200 | OK pada uji awal |
| 4 | Telemetry endpoint terjangkau | Collector POST ke ESP32 atau relay | Response `{"ok":true}` diterima | OK pada uji awal |
| 5 | Relay hanya opsional | Cek mode deployment | Relay hanya digunakan jika ESP32 tidak reachable langsung | OK, hanya untuk lab/VPS |

## 2. Validasi Mode Deployment

| Mode | Tujuan | Kriteria Berhasil |
| --- | --- | --- |
| `direct-server` | Implementasi ideal di server target yang bisa menjangkau ESP32 langsung | Collector POST langsung ke `http://IP_ESP32/telemetry` |
| `vps-relay` | Pengujian server publik VPS saat ESP32 berada di jaringan lokal/NAT | Collector VPS POST ke relay, relay meneruskan ke ESP32 |
| `local-lab` | Pengujian lokal terkontrol | Collector lokal mengirim telemetry langsung ke ESP32 |
| `http-ddos-public` | Pengujian HTTP DDoS pada endpoint publik | HTTP collector menghasilkan telemetry `proto=HTTP` |

## 3. Validasi Telemetry

| No | Field | Kriteria Berhasil |
| --- | --- | --- |
| 1 | `test_id` | Terisi sesuai skenario uji |
| 2 | `proto` | Bernilai `TCP` atau `HTTP` sesuai skenario |
| 3 | `src_ip` | Menunjukkan IP sumber serangan/request |
| 4 | `dst_ip` | Menunjukkan server target atau nama representasi server |
| 5 | `dst_port` | Sesuai port target, misalnya `22`, `8080`, atau `80` |
| 6 | `packet_count` | Bertambah saat traffic masuk |
| 7 | `syn_count` | Bertambah pada skenario TCP SYN Flood |
| 8 | `window_ms` | Bernilai `5000` ms sesuai rule awal |
| 9 | `first_seen_ms` dan `last_seen_ms` | Terisi dan dapat dipakai menghitung delay |

## 4. KPI TCP SYN Flood

Rule:

```text
RULE_TCP_SYN_001
Alert jika proto = TCP dan syn_count >= 100 dalam window <= 5000 ms.
```

| No | KPI | Cara Uji | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | Target publik reachable | `nc -vz SERVER_PUBLIC_IP 35122` | Port publik target terbuka |
| 2 | Collector membaca TCP traffic | Jalankan collector packet-level pada VPS/server target | Telemetry `proto=TCP` masuk ke ESP32 |
| 3 | SYN counter bertambah | Jalankan `hping3 -S` ke target | `tcp_syn_packets` bertambah |
| 4 | Threshold terlampaui | Kirim SYN >= 100 dalam 5 detik | Alert `RULE_TCP_SYN_001` muncul |
| 5 | Alert berisi bukti | Cek `/alerts.csv` | Ada `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `threshold_count`, `window_ms` |
| 6 | Detection delay tercatat | Cek kolom `detection_delay_ms` | Nilai delay tercatat dalam CSV |

Contoh command uji:

```bash
TARGET=SERVER_PUBLIC_IP
sudo hping3 -S -c 500 -i u1000 -p 35122 $TARGET
```

## 5. KPI HTTP DDoS

Rule:

```text
RULE_DDOS_HTTP_001
Alert jika proto = HTTP dan packet_count >= 200 dalam window <= 5000 ms.
```

| No | KPI | Cara Uji | Kriteria Berhasil |
| --- | --- | --- | --- |
| 1 | HTTP target publik reachable | `curl http://SERVER_PUBLIC_IP:8080` | Response HTTP muncul |
| 2 | HTTP collector berjalan | Jalankan `http_target_server.py` di server target | Request HTTP tercatat sebagai telemetry |
| 3 | Request counter bertambah | Kirim request normal | `http_requests` bertambah |
| 4 | Threshold terlampaui | Kirim >= 200 request dalam 5 detik | Alert `RULE_DDOS_HTTP_001` muncul |
| 5 | Alert berisi bukti | Cek `/alerts.csv` | Ada `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `threshold_count`, `window_ms` |
| 6 | Detection delay tercatat | Cek kolom `detection_delay_ms` | Nilai delay tercatat dalam CSV |

Contoh command uji:

```bash
URL=http://SERVER_PUBLIC_IP:8080
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

## 7. Hasil Uji Awal yang Sudah Terbukti

Bagian ini mencatat bukti awal bahwa KPI utama sudah pernah terpenuhi pada lingkungan pengujian. VPS digunakan sebagai representasi server publik, sedangkan ESP32 tetap berada di jaringan lokal.

### TCP SYN Flood

| Field | Nilai Uji Awal |
| --- | --- |
| Skenario | `TEST_TCP_SYN_VPS_PUBLIC_SSH_01` |
| Target publik | `SERVER_PUBLIC_IP:35122` |
| Target internal yang terlihat collector | `SERVER_INTERNAL_IP:22` |
| Rule trigger | `RULE_TCP_SYN_001` |
| Alert type | `TCP_SYN_FLOOD` |
| Packet/SYN count | `380` |
| Threshold | `100` |
| Detection delay | `417 ms` |
| Kesimpulan | True Positive, karena traffic SYN tinggi menghasilkan alert |

### HTTP DDoS Request Flood

| Field | Nilai Uji Awal |
| --- | --- |
| Skenario | `TEST_DDOS_HTTP_VPS_PUBLIC_01` |
| Target publik | `SERVER_PUBLIC_IP:8080` |
| Rule trigger | `RULE_DDOS_HTTP_001` |
| Alert type | `HTTP_DDOS_FLOOD` |
| Request count | `321` |
| Threshold | `200` |
| Detection delay | `1657 ms` |
| Kesimpulan | True Positive, karena request flood menghasilkan alert |

## 8. Metrik Evaluasi

| Metrik | Definisi | Cara Mengukur |
| --- | --- | --- |
| True Positive | Serangan terjadi dan alert muncul | Bandingkan skenario serangan dengan `/alerts.csv` |
| False Positive | Traffic normal tetapi alert muncul | Jalankan baseline normal dan cek alert |
| False Negative | Serangan terjadi tetapi alert tidak muncul | Jalankan serangan terkontrol dan cek alert |
| True Negative | Traffic normal dan tidak muncul alert | Jalankan baseline normal |
| Detection delay | Waktu dari traffic awal sampai alert tercatat | Kolom `detection_delay_ms` |
| Telemetry delivery | Collector berhasil mengirim telemetry ke ESP32 | Response POST `ok=true`, data ada di `/telemetry.csv` |

## 9. Baseline Minimal

Sebelum serangan, lakukan baseline:

| Skenario | Durasi | Ekspektasi |
| --- | --- | --- |
| Akses HTTP normal | 5 window | Tidak muncul alert |
| Koneksi SSH normal | 5 window | Tidak muncul alert TCP SYN Flood |
| Request HTTP rendah | < 200 request/5 detik | Tidak muncul alert DDoS |

## 10. Batasan Pengujian

- VPS digunakan sebagai representasi server publik, bukan server produksi Universitas Mataram.
- Relay PC B digunakan karena ESP32 berada di jaringan lokal/NAT.
- Relay tidak melakukan deteksi, hanya meneruskan telemetry.
- Jika ESP32 berada satu jaringan dengan server target, mode `direct-server` dapat digunakan tanpa relay.
- Pengujian TCP SYN Flood public sementara dapat memakai port publik yang sudah dipetakan provider ke VPS.
- Pengujian HTTP DDoS menggunakan public HTTP endpoint VPS yang sudah terbuka.
