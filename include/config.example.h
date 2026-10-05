#ifndef CONFIG_EXAMPLE_H
#define CONFIG_EXAMPLE_H

#include <Arduino.h>

// ==============================================================================
// GÜVENLİ VE DAĞITIK WAKE-ON-LAN (WoL) MİKRO-AJAN YAPILANDIRMASI
// ==============================================================================
// BU BİR ŞABLONDUR - GERÇEK DEĞERLER İÇERMEZ.
//
// Kullanım:
//   1. Bu dosyayı 'include/secrets.h' olarak kopyalayın.
//   2. Aşağıdaki değerleri kendi cihazınıza göre doldurun.
//   3. secrets.h .gitignore ile korunuyor; ASLA commit etmeyin.
//
// ÜRETİM GÜVENLİK KURALLARI:
//   - WAKE_AUTH_TOKEN boş bırakılırsa veya yer tutucu kalırsa cihaz TÜM WoL
//     komutlarını reddeder (fail-closed). Bu koruma main.cpp içinde zorunlu kılınır.
//   - Token, gateway'deki WOL_AUTH_TOKEN ile BİREBİR AYNI olmalıdır.
//   - MQTT_USER/MQTT_PASSWORD boşsa kanal halka açık broker'da dinlenebilir.
// ==============================================================================

// --- 1. HEDEF İŞ İSTASYONU (PC) DONANIM BİLGİSİ ---
// Uyandırılacak yerel ağdaki hedef ağ kartının (NIC) MAC adresi.
// Örnek: 00:e0:4c:5e:27:38
static const byte TARGET_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Hedef yerel ağ WoL broadcast portu (genellikle UDP 9 veya 7)
static const uint16_t WOL_PORT = 9;

// --- 2. GÜVENLİ MQTT BROKER YAPILANDIRMASI ---
// Üretimde KİMLİK DOĞRULAMALI ve TLS'LI (port 8883) kendi broker'ınızı kullanın.
// Not: Bu firmware düz metin WiFiClient ile çalışır; TLS desteği eklemek için
// PubSubClient + BearSSL ve kök sertifika yüklenmelidir. Bu yapılmadan
// broker'a giden token düz metin görünür.
static const char* MQTT_BROKER_HOST = "";
static const uint16_t MQTT_BROKER_PORT = 8883;

static const char* MQTT_USER = "";
static const char* MQTT_PASSWORD = "";

// --- 3. YETKİLENDİRME ANAHTARI (TOKEN) ---
// Halka açık broker üzerinde yetkisiz uyandırma isteklerini engelleyen anahtar.
// Üretin: python3 -c "import secrets; print(secrets.token_hex(32))"
// Bu değer main.cpp'deki yer tutucu kontrolüne takılır: yer tutucu kalırsa
// cihaz hiçbir WoL komutunu kabul etmez (bilinçli olarak çalışmaz).
static const char* WAKE_AUTH_TOKEN = "CHANGE_ME_generate_with_secrets_token_hex_32";

// --- 4. TOPIC (KANAL) ŞABLONLARI ---
// Cihaza özel ve tahmin edilemez kanal adı tercih edin.
// Topic adı, broker'ı dinleyen herkese açıktır; sır tutmayın, tahmin edilemez olsun.
#define TOPIC_PREFIX "edge/wol/device"
static const char* WAKE_TOPIC   = TOPIC_PREFIX "/wake";
static const char* STATUS_TOPIC = TOPIC_PREFIX "/status";

// --- 5. WIFIMANAGER (PROVİZYON) PARAMETRELERİ ---
// Cihaz ilk açılışta veya kayıtlı ağa bağlanamadığında şifreli bir AP açar.
// Böylece kaynak kodda hiçbir Wi-Fi parolası açık metin tutulmaz.
static const char* AP_PORTAL_SSID = "WoL-Bridge-Setup";
static const char* AP_PORTAL_PASS = "CHANGE_ME_at_least_8_chars"; // >= 8 karakter
static const unsigned long AP_TIMEOUT_SECONDS = 180; // 3 dakika sonra kapanır

#endif // CONFIG_EXAMPLE_H
