#ifndef CONFIG_EXAMPLE_H
#define CONFIG_EXAMPLE_H

#include <Arduino.h>

// ==============================================================================
// GÜVENLİ VE DAĞITIK WAKE-ON-LAN (WoL) MİKRO-AJAN YAPILANDIRMASI
// ==============================================================================
// Bu dosya bir yapılandırma şablonudur. Gerçek hassas değerleri (parolalar, özel
// token'lar) içeren dosyanızı 'include/secrets.h' olarak oluşturup derleme
// sürecine dahil edebilirsiniz. 'secrets.h' dosyası .gitignore ile korunmalıdır.
// ==============================================================================

// --- 1. HEDEF İŞ İSTASYONU (PC) DONANIM BİLGİSİ ---
// Uyandırılacak olan yerel ağdaki hedef ağ kartının (NIC) MAC adresi.
// Örnek: 00:11:22:33:44:55 (Kendi hedef cihazınızın MAC adresini giriniz)
static const byte TARGET_MAC[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

// Hedef yerel ağ WoL broadcast portu (Genellikle UDP 9 veya 7 kullanılır)
static const uint16_t WOL_PORT = 9;

// --- 2. GÜVENLİ MQTT BROKER YAPILANDIRMASI ---
// Broker sunucu adresi ve portu. 
// Üretim ortamında TLS (Port 8883) veya kimlik doğrulamalı özel broker önerilir.
static const char* MQTT_BROKER_HOST = "broker.hivemq.com";
static const uint16_t MQTT_BROKER_PORT = 1883;

// Broker kimlik doğrulama bilgileri (Anonim broker kullanılıyorsa boş bırakılabilir)
static const char* MQTT_USER = "";
static const char* MQTT_PASSWORD = "";

// --- 3. YETKİLENDİRME VE GÜVENLİK ANAHTARI (TOKEN) ---
// Halka açık veya paylaşımlı broker üzerinde yetkisiz uyandırma isteklerini
// engellemek için kullanılan yüksek entropili cihaz gizli anahtarı.
// Gelen WAKE komutu bu token ile doğrulanmadan işlem yapılmaz.
static const char* WAKE_AUTH_TOKEN = "GENERATE_HIGH_ENTROPY_SECRET_TOKEN_HERE";

// --- 4. TOPIC (KANAL) ŞABLONLARI ---
// Cihaza özel tekil konu adresi. Cihaz Chip ID'si ile dinamik birleştirilebilir.
// Örnek format: "enterprises/edge/wol/<DEVICE_ID>/wake"
#define TOPIC_PREFIX "edge/wol/device"
static const char* WAKE_TOPIC   = TOPIC_PREFIX "/wake";
static const char* STATUS_TOPIC = TOPIC_PREFIX "/status";

// --- 5. WIFIMANAGER (PROVISIONING) PARAMETRELERİ ---
// Cihaz ilk açıldığında veya kayıtlı Wi-Fi ağına bağlanamadığında bir Access Point (AP)
// açar. Kullanıcı telefon veya bilgisayarından bağlanıp web arayüzünden ağı seçer.
// Böylece kaynak kodda hiçbir Wi-Fi parolası açık metin olarak tutulmaz!
static const char* AP_PORTAL_SSID = "WoL-Bridge-Setup";
static const char* AP_PORTAL_PASS = "SetupSecure2026!"; // En az 8 karakterli AP şifresi
static const unsigned long AP_TIMEOUT_SECONDS = 180;    // 3 dakika sonra otomatik zaman aşımı

#endif // CONFIG_EXAMPLE_H
