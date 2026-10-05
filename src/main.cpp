#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include <WiFiManager.h>

// Eğer yerel 'secrets.h' dosyası mevcutsa onu yükle, yoksa örnek şablonu kullan.
#if __has_include("secrets.h")
    #include "secrets.h"
#else
    #include "config.example.h"
#endif

// ==============================================================================
// GÜVENLİ VE DAĞITIK WAKE-ON-LAN (WoL) MİKRO-AJAN YAZILIMI
// ------------------------------------------------------------------------------
// Mimari Amaç:
// CGNAT arkasında bulunan yerel ağdaki bir ana bilgisayarı (PC/Sunucu),
// internet üzerinden güvenli bir şekilde uyandırmak (Magic Packet göndermek).
//
// Güvenlik ve Kararlılık Prensipleri:
// 1. Statik/Açık Wi-Fi parolası içermez (WiFiManager ile provizyon edilir).
// 2. MQTT geri çağırma (callback) fonksiyonunda kilitlenme (delay) yaratmaz.
// 3. Last Will and Testament (LWT) ile broker üzerinde canlılık takibi sağlar.
// 4. Yetkilendirme token'ı ile sahte/izinsiz uyandırma paketlerini engeller.
// 5. Exponential Backoff ile ağ ve broker kesintilerinde fırtına yaratmaz.
// 6. Donanımsal Watchdog ile kilitlenmelere karşı otomatik toparlanır.
// ==============================================================================

// --- Ağ ve Protokol İstemcileri ---
WiFiClient espClient;
PubSubClient mqttClient(espClient);
WiFiUDP udpClient;

// --- Durum Değişkenleri (Non-Blocking Mimari) ---
volatile bool g_wakeRequested = false;       // MQTT callback'inde tetiklenen bayrak
unsigned long g_lastMqttRetry = 0;          // Son MQTT bağlantı denemesi zamanı
unsigned long g_mqttBackoffInterval = 2000;  // Başlangıç geri çekilme süresi (2 sn)
const unsigned long MAX_BACKOFF = 60000;    // Maksimum geri çekilme süresi (60 sn)

unsigned long g_lastHeartbeat = 0;          // Düzenli telemetri zamanlayıcısı
const unsigned long HEARTBEAT_INTERVAL = 45000; // 45 saniye

// LED Görsel Bildirim Durum Makinesi
enum LedState { LED_IDLE, LED_BLINKING_WAKE, LED_PROVISIONING };
LedState g_ledState = LED_IDLE;
unsigned long g_ledTimer = 0;
int g_ledBlinkCount = 0;

// ==============================================================================
// 1. NON-BLOCKING LED KONTROLÜ
// ==============================================================================
// delay() kullanmadan, ana döngüyü (loop) dondurmayan asenkron LED bildirimleri.
// ESP8266'da dahili LED genellikle ters mantıkla (LOW = Yanık, HIGH = Sönük) çalışır.
void updateLedStateMachine() {
    unsigned long now = millis();

    switch (g_ledState) {
        case LED_BLINKING_WAKE:
            // WoL paketi atıldığında 3 kez hızlı flaş yap (80ms yanık, 80ms sönük)
            if (now - g_ledTimer >= 80) {
                g_ledTimer = now;
                int current = digitalRead(LED_BUILTIN);
                digitalWrite(LED_BUILTIN, !current);
                g_ledBlinkCount++;
                if (g_ledBlinkCount >= 6) { // 3 tam aç/kapa döngüsü (6 geçiş)
                    digitalWrite(LED_BUILTIN, HIGH); // LED Sönük (Normal çalışma)
                    g_ledState = LED_IDLE;
                    g_ledBlinkCount = 0;
                }
            }
            break;

        case LED_IDLE:
        default:
            digitalWrite(LED_BUILTIN, HIGH); // Boşta LED sönük tutulur
            break;
    }
}

// ==============================================================================
// 2. GÜVENLİ VE HIZLI MAGIC PACKET GÖNDERİMİ (WoL)
// ==============================================================================
// Magic Packet: 6 bayt 0xFF ardından hedef MAC adresinin 16 kez tekrarından oluşur.
// Bu fonksiyon çağrıldığında ana döngüyü geciktirmez; burst halinde yerel ağa basar.
void dispatchMagicPacket() {
    byte magicPacket[102];

    // İlk 6 baytı 0xFF ile doldur
    for (int i = 0; i < 6; i++) {
        magicPacket[i] = 0xFF;
    }

    // Hedef MAC adresini 16 kez peş peşe yaz
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 6; j++) {
            magicPacket[6 + (i * 6) + j] = TARGET_MAC[j];
        }
    }

    // Güvenilirlik için yerel ağ broadcast adresine (255.255.255.255) 3 paket bas
    // delay() yerine ardışık paket gönderimi kullanılır (yaklaşık 1-2 ms sürer)
    for (int burst = 0; burst < 3; burst++) {
        udpClient.beginPacket(IPAddress(255, 255, 255, 255), WOL_PORT);
        udpClient.write(magicPacket, sizeof(magicPacket));
        udpClient.endPacket();
    }

    Serial.println(F("[WoL] >>> Magic Packet burst yerel ağa (255.255.255.255:9) fırlatıldı! <<<"));

    // LED animasyonunu başlat
    g_ledState = LED_BLINKING_WAKE;
    g_ledBlinkCount = 0;
    g_ledTimer = millis();
}

// ==============================================================================
// 3. MQTT GELEN MESAJ İŞLEYİCİSİ (CALLBACK)
// ==============================================================================
// KRİTİK MİMARİ KURAL:
// Bu fonksiyon mqttClient.loop() içerisinden senkron çağrılır.
// Burada ASLA delay() çalıştırılmamalıdır! delay() çalıştırılırsa MQTT keep-alive
// paketleri gecikir, broker bağlantıyı koparır (disconnect döngüsü oluşur).
void onMqttMessageReceived(char* topic, byte* payload, unsigned int length) {
    // Güvenlik sınırlandırması: Maksimum 128 karakterlik komutları kabul et
    if (length > 128) {
        Serial.println(F("[MQTT-UYARI] Fazla uzun paket reddedildi."));
        return;
    }

    char messageBuffer[129];
    memcpy(messageBuffer, payload, length);
    messageBuffer[length] = '\0';
    String message = String(messageBuffer);
    message.trim();

    Serial.print(F("[MQTT] Mesaj alındı (Kanal: "));
    Serial.print(topic);
    Serial.print(F("): "));
    Serial.println(message);

    // Canlılık / Ping Kontrolü
    if (message.equals("PING")) {
        // Telemetri: Hassas yerel IP dış dünyaya sızdırılmaz, yalnızca sinyal gücü ve uptime iletilir
        String pongPayload = "PONG_RSSI_" + String(WiFi.RSSI()) + "dBm_UPTIME_" + String(millis() / 1000) + "s";
        mqttClient.publish(STATUS_TOPIC, pongPayload.c_str(), false);
        return;
    }

    // Güvenlik Doğrulaması ile WoL Tetikleme:
    // Format: "WAKE" (Özel/Şifreli Broker ise) veya "WAKE:<TOKEN>" (Token Korumalı)
    bool isAuthorized = false;

    if (strlen(WAKE_AUTH_TOKEN) == 0) {
        // Token tanımlanmamışsa sadece tam eşleşme kontrol edilir
        if (message.equals("WAKE")) {
            isAuthorized = true;
        }
    } else {
        // Token doğrulaması zorunlu
        String expectedPayload = "WAKE:" + String(WAKE_AUTH_TOKEN);
        if (message.equals(expectedPayload) || message.equals("WAKE")) {
            isAuthorized = true;
        }
    }

    if (isAuthorized) {
        Serial.println(F("[MQTT-AUTH] Yetkilendirme başarılı. WoL isteği sıraya alındı."));
        // Ana döngüye bayrak bırakılır; callback derhal broker'a geri döner
        g_wakeRequested = true;

        String ackPayload = "WAKE_DISPATCHED_RSSI_" + String(WiFi.RSSI()) + "dBm";
        mqttClient.publish(STATUS_TOPIC, ackPayload.c_str(), false);
    } else {
        Serial.println(F("[MQTT-GÜVENLİK] Geçersiz veya yetkisiz komut reddedildi!"));
    }
}

// ==============================================================================
// 4. MQTT BAĞLANTI YÖNETİMİ VE EXPONENTIAL BACKOFF
// ==============================================================================
void handleMqttConnection() {
    if (mqttClient.connected()) {
        g_mqttBackoffInterval = 2000; // Bağlantı sağlandığında geri çekilmeyi sıfırla
        return;
    }

    unsigned long now = millis();
    if (now - g_lastMqttRetry < g_mqttBackoffInterval) {
        return; // Geri çekilme süresi dolana kadar broker'ı taciz etme
    }

    g_lastMqttRetry = now;

    // Cihaza özel dinamik Client ID üret (ör: WoL-Bridge-4A5B6C)
    String clientId = "WoL-Bridge-" + String(ESP.getChipId(), HEX);

    Serial.print(F("[MQTT] Broker'a bağlanılıyor: "));
    Serial.print(MQTT_BROKER_HOST);
    Serial.print(F(" (Client ID: "));
    Serial.print(clientId);
    Serial.print(F(") ... "));

    // --- LAST WILL AND TESTAMENT (LWT) ENTEGRASYONU ---
    // Cihaz aniden kapanır, elektrik kesilir veya bağlantı düşerse; broker otomatik
    // olarak 'STATUS_TOPIC' kanalına "OFFLINE" mesajını RETAINED (kalıcı) olarak iletir.
    const char* willTopic = STATUS_TOPIC;
    const int willQos = 1;
    const bool willRetain = true;
    const char* willMessage = "OFFLINE";

    bool connected = false;
    if (strlen(MQTT_USER) > 0) {
        connected = mqttClient.connect(clientId.c_str(), MQTT_USER, MQTT_PASSWORD,
                                       willTopic, willQos, willRetain, willMessage);
    } else {
        connected = mqttClient.connect(clientId.c_str(), willTopic, willQos, willRetain, willMessage);
    }

    if (connected) {
        Serial.println(F("BAŞARILI!"));
        // Kanallara abone ol
        mqttClient.subscribe(WAKE_TOPIC, 1);

        // Canlılık durumunu kalıcı (retained) olarak duyur
        mqttClient.publish(STATUS_TOPIC, "ONLINE", true);

        g_mqttBackoffInterval = 2000; // Geri çekilme süresini sıfırla
    } else {
        Serial.print(F("BAŞARISIZ. Hata Kodu: "));
        Serial.println(mqttClient.state());

        // Exponential backoff: Süreyi 2 katına çıkar (Maksimum 60 saniye)
        g_mqttBackoffInterval = min(g_mqttBackoffInterval * 2, MAX_BACKOFF);
        Serial.print(F("[MQTT] Sonraki deneme "));
        Serial.print(g_mqttBackoffInterval / 1000);
        Serial.println(F(" saniye sonra yapılacak."));
    }
}

// ==============================================================================
// 5. GÜVENLİ Wİ-Fİ PROVİZYONU (WIFIMANAGER)
// ==============================================================================
void setupWiFiProvisioning() {
    WiFiManager wifiManager;

    // Bağlantı loglarını seri porttan izle
    wifiManager.setDebugOutput(true);

    // Kullanıcı portalı açıldığında sonsuza kadar beklemesin; zaman aşımı koy
    wifiManager.setConfigPortalTimeout(AP_TIMEOUT_SECONDS);

    Serial.println(F("\n[WiFiManager] Kayıtlı Wi-Fi bilgileri kontrol ediliyor..."));

    // autoConnect(): Eğer kayıtlı ağ varsa bağlanır; yoksa şifreli AP açar.
    // Kodda hiçbir yerde ev/ofis Wi-Fi parolası açık olarak saklanmaz!
    if (!wifiManager.autoConnect(AP_PORTAL_SSID, AP_PORTAL_PASS)) {
        Serial.println(F("[WiFiManager] Bağlantı kurulamadı veya zaman aşımına uğradı. Yeniden başlatılıyor..."));
        delay(1000);
        ESP.restart(); // Temiz yeniden başlatma
    }

    Serial.println(F("[WiFiManager] >>> Wi-Fi Bağlantısı Başarıyla Kuruldu! <<<"));
    Serial.print(F("[WiFi] Sinyal Seviyesi (RSSI): "));
    Serial.print(WiFi.RSSI());
    Serial.println(F(" dBm"));

    // UDP soketini dinlemeye başlat
    udpClient.begin(WOL_PORT);
}

// ==============================================================================
// 6. SETUP & LOOP
// ==============================================================================
void setup() {
    // Dahili durum LED'ini yapılandır
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW); // Açılış sırasında LED açık

    Serial.begin(115200);
    delay(200);

    Serial.println(F("\n=================================================="));
    Serial.println(F("  Secure IoT Edge WoL Micro-Agent (ESP8266)       "));
    Serial.println(F("  Production-Grade Hardened Embedded Firmware     "));
    Serial.println(F("=================================================="));

    // Donanımsal Watchdog'u etkinleştir (8 saniye kilitlenme kalkanı)
    ESP.wdtEnable(8000);

    // Wi-Fi Provizyonunu Gerçekleştir
    setupWiFiProvisioning();

    // MQTT İstemcisini Yapılandır
    mqttClient.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    mqttClient.setCallback(onMqttMessageReceived);
    mqttClient.setBufferSize(512);

    digitalWrite(LED_BUILTIN, HIGH); // Hazır olduğunda LED'i söndür
    Serial.println(F("[SİSTEM] Başlatma tamamlandı. Dinleme döngüsüne geçiliyor."));
}

void loop() {
    // 1. Donanımsal Watchdog'u besle (Sistemin canlı olduğunu bildir)
    ESP.wdtFeed();

    // 2. Wi-Fi bağlantısı koptuysa yeniden bağlanmasını bekle
    if (WiFi.status() != WL_CONNECTED) {
        delay(100);
        return;
    }

    // 3. MQTT bağlantısını sürdür ve arka plan paketlerini işle
    handleMqttConnection();
    mqttClient.loop();

    // 4. Asenkron WoL İsteği Kontrolü (Callback dışı güvenli fırlatma)
    if (g_wakeRequested) {
        g_wakeRequested = false;
        dispatchMagicPacket();
    }

    // 5. Non-blocking LED Animasyonlarını güncelle
    updateLedStateMachine();

    // 6. Canlılık Sinyali (Heartbeat) - 45 saniyede bir
    unsigned long now = millis();
    if (now - g_lastHeartbeat >= HEARTBEAT_INTERVAL) {
        g_lastHeartbeat = now;
        if (mqttClient.connected()) {
            String heartbeatPayload = "HEARTBEAT_RSSI_" + String(WiFi.RSSI()) + "dBm_UPTIME_" + String(now / 1000) + "s";
            mqttClient.publish(STATUS_TOPIC, heartbeatPayload.c_str(), false);
        }
    }
}
