// include/AuthStore.h
#pragma once
#include <Arduino.h>

// Inisialisasi NVS namespace "auth"
void authInit();

// Cek apakah kredensial sudah pernah dibuat
bool authIsConfigured();

// Simpan username + salt + hash(pass)
bool authSetCredentials(const String& user, const String& pass);

// Verifikasi login (user + pass) terhadap data di NVS
bool authVerify(const String& user, const String& pass);

// (opsional) ambil username yang tersimpan
String authGetUser();

// Hapus kredensial dari NVS (reset setup)
bool authClear();


// // include/AuthStore.h
// #pragma once
// #include <Arduino.h>

// // Inisialisasi NVS namespace "auth"
// void authInit();

// // Cek apakah kredensial sudah pernah dibuat
// bool authIsConfigured();

// // Simpan username + salt + hash(pass)
// bool authSetCredentials(const String& user, const String& pass);

// // Verifikasi login (user + pass) terhadap data di NVS
// bool authVerify(const String& user, const String& pass);

// // (opsional) ambil username yang tersimpan
// String authGetUser();

// // (opsional) hapus kredensial dari NVS
// bool authClear();
