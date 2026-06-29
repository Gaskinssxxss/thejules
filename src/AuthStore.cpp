// src/AuthStore.cpp
#include "AuthStore.h"

#include <Preferences.h>
#include "mbedtls/md.h"   // SHA-256
#include <string.h>

static Preferences prefs;

static String toHex(const uint8_t* buf, size_t len) {
  static const char* hex = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out += hex[(buf[i] >> 4) & 0xF];
    out += hex[buf[i] & 0xF];
  }
  return out;
}

static bool fromHex(const String& hexStr, uint8_t* out, size_t outLen) {
  if (hexStr.length() != (int)(outLen * 2)) return false;

  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };

  for (size_t i = 0; i < outLen; i++) {
    int hi = nibble(hexStr[2 * i]);
    int lo = nibble(hexStr[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, data, len);
  mbedtls_md_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// hash = SHA256( salt || password )  (salt 16 bytes)
static String hashWithSaltHex(const uint8_t salt[16], const String& pass) {
  size_t passLen = pass.length();
  if (passLen > 128) passLen = 128;

  uint8_t buf[16 + 128];
  memcpy(buf, salt, 16);
  memcpy(buf + 16, pass.c_str(), passLen);

  uint8_t digest[32];
  sha256(buf, 16 + passLen, digest);
  return toHex(digest, 32);
}

void authInit() {
  // namespace "auth" di NVS (flash)
  prefs.begin("auth", false);
}

bool authIsConfigured() {
  return prefs.getBool("configured", false);
}

String authGetUser() {
  return prefs.getString("user", "");
}

bool authSetCredentials(const String& user, const String& pass) {
  if (user.length() < 3) return false;
  if (pass.length() < 6) return false;

  uint8_t salt[16];
  for (int i = 0; i < 16; i++) {
    salt[i] = (uint8_t)esp_random();
  }

  String saltHex = toHex(salt, 16);
  String hashHex = hashWithSaltHex(salt, pass);

  prefs.putString("user", user);
  prefs.putString("salt", saltHex);
  prefs.putString("hash", hashHex);
  prefs.putBool("configured", true);
  return true;
}

bool authVerify(const String& user, const String& pass) {
  if (!authIsConfigured()) return false;

  String savedUser = prefs.getString("user", "");
  if (user != savedUser) return false;

  String saltHex   = prefs.getString("salt", "");
  String savedHash = prefs.getString("hash", "");
  if (saltHex.length() == 0 || savedHash.length() == 0) return false;

  uint8_t salt[16];
  if (!fromHex(saltHex, salt, 16)) return false;

  String candidate = hashWithSaltHex(salt, pass);
  return candidate == savedHash;
}

bool authClear() {
  // clear semua key di namespace "auth"
  bool ok = prefs.clear();
  // pastikan state "configured" jadi false
  prefs.putBool("configured", false);
  return ok;
}


// // src/AuthStore.cpp
// #include "AuthStore.h"

// #include <Preferences.h>
// #include "mbedtls/md.h"   // SHA-256
// #include <string.h>

// static Preferences prefs;

// static String toHex(const uint8_t* buf, size_t len) {
//   static const char* hex = "0123456789abcdef";
//   String out;
//   out.reserve(len * 2);
//   for (size_t i = 0; i < len; i++) {
//     out += hex[(buf[i] >> 4) & 0xF];
//     out += hex[buf[i] & 0xF];
//   }
//   return out;
// }

// static bool fromHex(const String& hexStr, uint8_t* out, size_t outLen) {
//   if (hexStr.length() != (int)(outLen * 2)) return false;

//   auto nibble = [](char c) -> int {
//     if (c >= '0' && c <= '9') return c - '0';
//     if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
//     if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
//     return -1;
//   };

//   for (size_t i = 0; i < outLen; i++) {
//     int hi = nibble(hexStr[2 * i]);
//     int lo = nibble(hexStr[2 * i + 1]);
//     if (hi < 0 || lo < 0) return false;
//     out[i] = (uint8_t)((hi << 4) | lo);
//   }
//   return true;
// }

// static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
//   mbedtls_md_context_t ctx;
//   const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

//   mbedtls_md_init(&ctx);
//   mbedtls_md_setup(&ctx, info, 0);
//   mbedtls_md_starts(&ctx);
//   mbedtls_md_update(&ctx, data, len);
//   mbedtls_md_finish(&ctx, out);
//   mbedtls_md_free(&ctx);
// }

// // hash = SHA256( salt || password )  (salt 16 bytes)
// static String hashWithSaltHex(const uint8_t salt[16], const String& pass) {
//   // batasi panjang password yang di-hash agar buffer aman
//   size_t passLen = pass.length();
//   if (passLen > 128) passLen = 128;

//   uint8_t buf[16 + 128];
//   memcpy(buf, salt, 16);
//   memcpy(buf + 16, pass.c_str(), passLen);

//   uint8_t digest[32];
//   sha256(buf, 16 + passLen, digest);
//   return toHex(digest, 32);
// }

// void authInit() {
//   // namespace "auth" di NVS (flash)
//   prefs.begin("auth", false);
// }

// bool authIsConfigured() {
//   return prefs.getBool("configured", false);
// }

// String authGetUser() {
//   return prefs.getString("user", "");
// }

// bool authSetCredentials(const String& user, const String& pass) {
//   if (user.length() < 3) return false;
//   if (pass.length() < 6) return false;

//   uint8_t salt[16];
//   for (int i = 0; i < 16; i++) {
//     salt[i] = (uint8_t)esp_random();
//   }

//   String saltHex = toHex(salt, 16);
//   String hashHex = hashWithSaltHex(salt, pass);

//   prefs.putString("user", user);
//   prefs.putString("salt", saltHex);
//   prefs.putString("hash", hashHex);
//   prefs.putBool("configured", true);
//   return true;
// }

// bool authVerify(const String& user, const String& pass) {
//   if (!authIsConfigured()) return false;

//   String savedUser = prefs.getString("user", "");
//   if (user != savedUser) return false;

//   String saltHex   = prefs.getString("salt", "");
//   String savedHash = prefs.getString("hash", "");
//   if (saltHex.length() == 0 || savedHash.length() == 0) return false;

//   uint8_t salt[16];
//   if (!fromHex(saltHex, salt, 16)) return false;

//   String candidate = hashWithSaltHex(salt, pass);
//   return candidate == savedHash;
// }

// bool authClear() {
//   // Hapus namespace "auth"
//   bool ok = prefs.clear();
//   prefs.putBool("configured", false);
//   return ok;
// }
