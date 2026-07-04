# Scope Deteksi Opsi 1

Versi pengembangan ini difokuskan pada dua jenis serangan yang masih sesuai dengan konsep collector di server target. Pada implementasi riil di lingkungan Universitas Mataram, collector ditempatkan pada server target yang menjalankan layanan kampus. Pada pengujian saat ini, server target direpresentasikan dengan VPS publik karena akses langsung ke server kampus belum tersedia.

## 1. TCP SYN Flood

TCP SYN Flood merepresentasikan serangan pada transport layer. Collector packet-level membaca paket TCP yang masuk ke server target dan menghitung jumlah flag SYN pada window waktu tertentu.

Rule:

```text
RULE_TCP_SYN_001
Jika proto = TCP dan syn_count >= 100 dalam window <= 5000 ms,
maka alert TCP_SYN_FLOOD.
```

Pengujian dilakukan pada server target yang dapat menerima traffic dari luar. Collector membaca paket TCP yang masuk ke interface server, lalu mengirim ringkasan `syn_count` ke ESP32.

Contoh pengujian publik dengan VPS:

```text
PC A attacker -> public IP/port VPS -> server target VPS + collector -> ESP32
```

## 2. DDoS HTTP Request Flood

DDoS direpresentasikan sebagai HTTP request flood pada layanan web publik. Collector HTTP menghitung jumlah request yang masuk ke server target pada window waktu tertentu, lalu mengirim telemetry `proto=HTTP` ke ESP32.

Rule:

```text
RULE_DDOS_HTTP_001
Jika proto = HTTP dan packet_count/request_count >= 200 dalam window <= 5000 ms,
maka alert HTTP_DDOS_FLOOD.
```

Pengujian dilakukan ke endpoint publik server target:

```text
PC A attacker/tester -> public IP/port VPS -> HTTP target server + HTTP collector -> ESP32
```

Catatan batasan:

- Sistem mendeteksi indikasi serangan dan menghasilkan alert, bukan melakukan mitigasi otomatis.
- DDoS yang diuji pada versi ini mencakup TCP SYN Flood pada layer 4 dan HTTP request flood pada layer 7.
- UDP flood tidak menjadi rule utama pada scope versi ini.
- Relay hanya digunakan pada kondisi pengujian ketika ESP32 berada di jaringan lokal/NAT dan tidak bisa diakses langsung dari server target publik.
