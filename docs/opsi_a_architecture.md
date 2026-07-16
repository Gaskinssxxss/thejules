# Arsitektur Opsi 1 - Collector di Server Target

Pada Opsi 1, collector dijalankan langsung pada server target. Server target adalah host yang menjalankan layanan yang ingin dipantau, misalnya layanan web kampus atau server uji resmi Universitas Mataram.

Alur kerja:

1. Client/tester mengirim traffic normal atau traffic uji ke server target.
2. Server target menjalankan hybrid collector.
3. Submodul packet feature extractor membaca traffic masuk dari interface jaringan server.
4. Submodul HTTP request counter menghitung request HTTP yang masuk ke layanan uji.
5. Collector menghitung fitur traffic per window waktu, seperti jumlah TCP SYN, jumlah HTTP request, IP sumber, IP tujuan, port tujuan, jumlah paket, dan window waktu.
6. Collector mengirim telemetry ringkas langsung ke ESP32 melalui HTTP.
7. ESP32 menjalankan rule-based detection, menampilkan dashboard, menghasilkan alert, dan menyimpan log CSV.

Konsekuensi teknis:

- ESP32 tidak lagi melakukan sniffing Wi-Fi secara langsung.
- Data yang diterima ESP32 sudah berupa ringkasan traffic, sehingga beban pemrosesan sesuai dengan keterbatasan perangkat.
- Cakupan deteksi terbatas pada server tempat collector dipasang.
- Pendekatan ini cocok untuk implementasi awal karena tidak membutuhkan switch managed atau port mirroring.
- Pada lingkungan valid, collector dijalankan langsung pada server target Universitas Mataram atau server uji yang disediakan administrator jaringan.

Komponen:

- `firmware/telemetry_ids_esp32`: firmware rule engine ESP32.
- `collector/collector.py`: hybrid collector untuk fitur TCP SYN dan HTTP request.
- `tools/send_test_telemetry.py`: simulator telemetry untuk validasi awal firmware.
