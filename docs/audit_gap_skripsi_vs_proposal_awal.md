# Audit Gap Skripsi Review Dosen vs Proposal Awal

Sumber pembanding:

- Proposal awal: `F1D022009-berkas-1772964538-2026_03_08-implementasi_sistem_rule_based_pada_esp32_untuk_deteksi_serangan_pada_lalu_lintas_data_di_jaringan_universitas_mataram_v1__1_.pdf`
- Skripsi saat ini: `proposal_baru/skripsi_opsi_1_collector_server_REVIEW_DOSEN.docx`

## Kesimpulan Audit

Skripsi versi `REVIEW_DOSEN` sudah lebih lengkap daripada draft sebelumnya secara struktur Bab I sampai Bab V, tetapi memang masih ada beberapa substansi proposal awal yang belum terbawa atau belum diterjemahkan dengan cukup kuat ke konsep baru collector di server target.

Kekurangan utama bukan pada Bab IV dan Bab V saja, melainkan pada kedalaman Bab II, detail rancangan Bab III, dan komponen administratif/pendukung dari proposal awal.

## 1. Bagian Proposal Awal yang Belum Masuk atau Masih Lemah

| Bagian Proposal Awal | Status di Skripsi Saat Ini | Tindak Lanjut |
| --- | --- | --- |
| Ringkasan proposal | Sudah ada abstrak, tetapi belum ada versi ringkasan yang menekankan perubahan konsep dari sniffer ke collector | Perkuat abstrak dan latar belakang dengan narasi evaluasi perubahan arsitektur |
| Teori Internet of Things | Masih terlalu sedikit | Tambahkan subbab IoT dan sistem tertanam karena ESP32 tetap perangkat embedded/IoT |
| Teori sistem tertanam | Masih kurang | Tambahkan subbab sistem tertanam dan keterbatasan resource |
| Teori keamanan jaringan dan CIA | Belum kuat | Tambahkan subbab keamanan jaringan, availability, DoS/DDoS |
| Kajian pustaka minimal 8 penelitian | Saat ini baru ringkasan rujukan, belum menjadi kajian pustaka penelitian terdahulu yang kuat | Tambahkan tabel kajian pustaka 8-10 penelitian dan gap penelitian |
| Rancangan perangkat keras | Masih minim | Tambahkan rancangan hardware: ESP32, server target, PC penguji, jaringan, relay opsional |
| Rancangan perangkat lunak modular | Sudah ada sebagian | Perkuat dengan modul collector, telemetry endpoint, rule engine, CSV logger, Web UI |
| Use case diagram | Belum ada | Tambahkan narasi/tabel use case admin: login, lihat dashboard, download CSV, reset log |
| Rancangan interface | Belum detail | Tambahkan halaman Web UI, endpoint CSV, alert table |
| Jadwal penelitian | Belum ada | Tambahkan jadwal penelitian sebagai lampiran atau subbab pendukung |
| RAB | Belum ada | Tambahkan RAB dengan penyesuaian konsep baru: ESP32, VPS opsional, internet, printing |
| Similarity index dan AI detection | Belum ada | Tambahkan placeholder jika memang format prodi masih meminta |
| Narasi alternatif firewall utama | Ada singkat, belum sekuat proposal awal | Perkuat narasi bahwa sistem adalah alat monitoring/IDS pendukung, bukan pengganti firewall inline |

## 2. Bagian yang Harus Diubah dari Proposal Awal Karena Konsep Sudah Berubah

Beberapa bagian proposal awal tidak boleh disalin apa adanya karena konsep sistem sudah berubah dari ESP32 Wi-Fi sniffer menjadi ESP32 rule engine berbasis telemetry collector.

| Bagian Lama | Tidak Dipakai Apa Adanya | Versi Baru yang Tepat |
| --- | --- | --- |
| ESP32 sebagai sniffer Wi-Fi utama | Tidak cocok untuk konsep final | ESP32 sebagai rule engine, Web UI, alert dashboard, CSV logger |
| Open Wi-Fi sebagai target utama | Tidak menjadi arsitektur utama | Server target sebagai titik collector |
| ESP32 parsing raw IP/TCP/UDP langsung dari Wi-Fi | Tidak menjadi proses utama | Collector server membaca traffic dan mengirim summary |
| UDP Flood sebagai rule utama | Tidak lagi dipakai di scope final | TCP SYN Flood dan HTTP DDoS request flood |
| MQTT communication | Tidak dipakai pada implementasi sekarang | HTTP POST telemetry ke `/telemetry` |
| Access point sebagai komponen wajib | Tidak wajib | Jaringan hanya media komunikasi; VPS/server target lebih penting |

## 3. Kekurangan Substansi pada Skripsi Saat Ini

### Bab I

Bab I sudah sesuai arah baru, tetapi masih bisa diperkuat dengan:

- alasan objektif perubahan dari Wi-Fi sniffing ke collector,
- narasi keterbatasan WPA/WPA2 dan traffic server publik,
- posisi sistem sebagai IDS/monitoring pendukung jika firewall utama tidak tersedia atau tidak berfungsi optimal,
- ruang lingkup Universitas Mataram yang lebih eksplisit.

### Bab II

Bab II masih kurang akademik jika dibanding proposal awal. Perlu ditambah:

- Internet of Things,
- sistem tertanam,
- ESP32 sebagai edge/embedded device,
- keamanan jaringan dan CIA,
- DoS/DDoS,
- NIDS/HIDS,
- rule-based IDS,
- traffic collector dan telemetry,
- kajian pustaka penelitian terdahulu minimal 8 penelitian.

### Bab III

Bab III sudah punya metode, tetapi perlu diperkuat dengan:

- rancangan perangkat keras,
- rancangan perangkat lunak,
- use case administrator,
- rancangan Web UI,
- flow data collector ke ESP32,
- mode deployment: direct-server, VPS-relay, local-lab,
- alasan penggunaan VPS sebagai representasi server publik,
- rumus/perumusan threshold: baseline + eksperimen.

### Bab IV

Bab IV sudah berdasarkan data nyata, tetapi masih bisa diperkuat dengan:

- tabel raw stats per skenario,
- tabel raw alert per skenario,
- penjelasan tiap file CSV,
- pembahasan mengapa TCP SYN terkadang terbagi ke lebih dari satu telemetry window,
- evaluasi threshold dari baseline.

### Bab V

Bab V sudah cukup, tetapi bisa dibuat lebih akademik dengan menjawab rumusan masalah satu per satu.

## 4. Rekomendasi Perbaikan Berikutnya

Prioritas perbaikan naskah:

1. Perkuat Bab II dengan teori dan kajian pustaka dari proposal awal yang masih relevan.
2. Perkuat Bab III dengan rancangan hardware/software/use case/interface.
3. Tambahkan jadwal penelitian dan RAB sebagai lampiran atau bagian pendukung.
4. Tambahkan bagian similarity index dan AI detection placeholder jika format kampus masih meminta.
5. Perkuat Bab IV dengan tabel raw CSV dan analisis threshold.
6. Revisi kesimpulan agar menjawab rumusan masalah satu per satu.

## 5. Status

Skripsi `REVIEW_DOSEN` layak sebagai draft teknis awal untuk dibaca dosen, tetapi belum ideal sebagai naskah final. Versi berikutnya sebaiknya dibuat sebagai:

`skripsi_opsi_1_collector_server_REVIEW_DOSEN_V2.docx`

Fokus V2 adalah menggabungkan kekuatan proposal awal dengan konsep baru collector di server target.
