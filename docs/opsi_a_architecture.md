# Arsitektur Opsi 1 - Collector di Server Target

Pada Opsi 1, collector dijalankan langsung pada server target. Server target adalah host yang menjalankan layanan kampus, misalnya layanan web publik. Pada implementasi riil, server target dapat berupa server Universitas Mataram. Pada pengujian saat ini, server target direpresentasikan dengan VPS publik karena akses langsung ke server kampus belum tersedia.

Alur kerja:

1. PC A berperan sebagai tester atau attacker.
2. Server target menjalankan layanan yang diuji, misalnya HTTP publik atau SSH.
3. Collector berjalan di server target dan membaca traffic yang masuk ke interface jaringan server.
4. Collector menghitung fitur traffic per window waktu, seperti jumlah TCP SYN, jumlah HTTP request, IP sumber, IP tujuan, port tujuan, dan window waktu.
5. Collector mengirim telemetry ringkas ke ESP32 melalui HTTP. Jika ESP32 tidak dapat dijangkau langsung karena berada di jaringan lokal/NAT, telemetry dapat melewati relay.
6. ESP32 menjalankan rule-based detection, menampilkan dashboard, menghasilkan alert, dan menyimpan log CSV.

Konsekuensi teknis:

- ESP32 tidak lagi harus melakukan sniffing Wi-Fi secara langsung.
- Data yang diterima ESP32 sudah berupa ringkasan traffic, sehingga beban pemrosesan sesuai dengan keterbatasan perangkat.
- Cakupan deteksi terbatas pada server tempat collector dipasang.
- Pendekatan ini cocok untuk validasi awal karena tidak membutuhkan switch managed atau port mirroring.
- VPS publik hanya berperan sebagai representasi server target untuk pengujian. Pada lingkungan valid, collector yang sama dapat dijalankan langsung pada server target Universitas Mataram.

Komponen:

- `firmware/telemetry_ids_esp32`: firmware rule engine ESP32.
- `collector/collector.py`: collector traffic di server target.
- `collector/http_target_server.py`: HTTP target server sekaligus collector request untuk pengujian HTTP DDoS.
- `collector/telemetry_relay.py`: relay opsional dari server publik menuju ESP32 lokal.
- `tools/send_test_telemetry.py`: simulator telemetry untuk validasi awal firmware.
