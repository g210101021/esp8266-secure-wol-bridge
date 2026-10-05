"""
Yapılandırma Modülü - Güvenli WoL Gateway ve Dağıtık Tetikleyici
==============================================================================
Bu modül, ortam değişkenlerini (.env) güvenli bir şekilde ayrıştırır ve sistem
ayarlarını tek bir kaynaktan yönetir.

Güvenlik İlkeleri:
- 'Fail-closed': Kritik yetkilendirme anahtarları (WOL_AUTH_TOKEN) eksikse
  sunucu güvenli moda geçer ve istekleri reddeder.
- Mükerrer IP ve MAC adresleri hardcode edilmez; konfigürasyondan okunur.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("WoLConfig")

# Proje dizin kökü ve .env yükleme
BASE_DIR = Path(__file__).resolve().parent.parent

# dotenv kütüphanesi varsa .env dosyasını otomatik yükle
try:
    from dotenv import load_dotenv
    env_file = BASE_DIR / "gateway" / ".env"
    if not env_file.exists():
        env_file = BASE_DIR / ".env"
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass

# ==============================================================================
# 1. GÜVENLİK VE KİMLİK DOĞRULAMA (TOKEN AUTH)
# ==============================================================================
# Gateway API uç noktalarına ve MQTT komutlarına erişim için kullanılan ortak gizli anahtar.
# Boş bırakılırsa 'fail-closed' kuralı gereği yetkisiz tüm istekler reddedilir.
WOL_AUTH_TOKEN: str = os.getenv("WOL_AUTH_TOKEN", "").strip()

# ==============================================================================
# 2. HEDEF DONANIM BİLGİLERİ (PC / WORKSTATION)
# ==============================================================================
# Hedef cihazın fiziksel ağ kartı (NIC) MAC adresi
TARGET_MAC: str = os.getenv("TARGET_MAC", "00:11:22:33:44:55").strip()

# config.example.h / .env.example içinde bırakılan şablon MAC adresi. Gerçek
# cihaz bu değere sahip değilse, gateway sessizce hiçbir işe yaramayan paketler
# gönderir. Aşağıdaki doğrulama bunu başlangıçta loglar.
PLACEHOLDER_MAC: str = "00:11:22:33:44:55"

# Yerel ağ veya WAN WoL broadcast hedefi
TARGET_BROADCAST_IP: str = os.getenv("TARGET_BROADCAST_IP", "255.255.255.255").strip()
WOL_PORT: int = int(os.getenv("WOL_PORT", "9"))

# CGNAT arkasındaki ağda dış IP değişebilir. /api/heartbeat ile kaydedilen IP
# gerçekten hedef olarak kullanılsın mı?
#
# Varsayılan: False (güvenli varsayılan). Depolanan IP'nin denetimli ve doğrulanmış
# olması gerekir; istemeden açmak, tek bir hatalı kaydın tüm WoL trafiğini yanlış
# adrese yönlendirmesine yol açar. CGNAT gerçekten engelse True yapın.
PREFER_RECORDED_IP: bool = os.getenv("PREFER_RECORDED_IP", "false").lower() in ("true", "1", "yes")

# ==============================================================================
# 3. HTTP GATEWAY SUNUCU AYARLARI
# ==============================================================================
GATEWAY_HOST: str = os.getenv("GATEWAY_HOST", "0.0.0.0").strip()
GATEWAY_PORT: int = int(os.getenv("GATEWAY_PORT", "8080"))

# Tekrarlanan istekleri ve paket fırtınasını engellemek için minimum bekleme süresi (sn)
WAKE_COOLDOWN_SECONDS: float = float(os.getenv("WAKE_COOLDOWN_SECONDS", "15.0"))

# ==============================================================================
# 4. CANLILIK KONTROLÜ (NON-BLOCKING HEALTH PROBE)
# ==============================================================================
# Ping yerine hedef cihazın dinlediği bir port (SSH 22, Webhook 8088 vb.) soket ile yoklanır
HEALTH_PROBE_HOST: str = os.getenv("HEALTH_PROBE_HOST", "127.0.0.1").strip()
HEALTH_PROBE_PORT: int = int(os.getenv("HEALTH_PROBE_PORT", "22"))
HEALTH_CACHE_TTL: float = float(os.getenv("HEALTH_CACHE_TTL", "5.0"))

# ==============================================================================
# 5. MQTT KÖPRÜ AYARLARI (NodeMCU ESP8266 Tetikleyici)
# ==============================================================================
# Varsayılan olarak KAPALI. Doğrudan UDP kanalı tek başına yeterlidir; MQTT
# köprüsü yalnızca CGNAT gerçekten engelliyorsa ve EMNİYETLİ bir broker
# (kimlik doğrulamalı + TLS) üzerinden kullanılacaksa açılmalıdır.
MQTT_ENABLED: bool = os.getenv("MQTT_ENABLED", "false").lower() in ("true", "1", "yes")
MQTT_BROKER_HOST: str = os.getenv("MQTT_BROKER_HOST", "").strip()
MQTT_BROKER_PORT: int = int(os.getenv("MQTT_BROKER_PORT", "8883"))
MQTT_USER: str = os.getenv("MQTT_USER", "").strip()
MQTT_PASSWORD: str = os.getenv("MQTT_PASSWORD", "").strip()

# TLS: üretim için zorunlu tavsiye edilir (düz metin 1883 yerine 8883).
MQTT_TLS_ENABLED: bool = os.getenv("MQTT_TLS_ENABLED", "true").lower() in ("true", "1", "yes")
MQTT_CA_CERT_FILE: str = os.getenv("MQTT_CA_CERT_FILE", "").strip()

MQTT_TOPIC_PREFIX: str = os.getenv("MQTT_TOPIC_PREFIX", "edge/wol/device").strip()
MQTT_WAKE_TOPIC: str = f"{MQTT_TOPIC_PREFIX}/wake"
MQTT_STATUS_TOPIC: str = f"{MQTT_TOPIC_PREFIX}/status"

# Halka açık/anonim broker listesi - bunlara bağlanmak bilinçli bir risktir.
PUBLIC_ANONYMOUS_BROKERS = {
    "broker.hivemq.com",
    "test.mosquitto.org",
    "mqtt.eclipseprojects.io",
    "broker.emqx.io",
}


# ==============================================================================
# 6. BAŞLANGIÇ DOĞRULAMASI (FAIL-FAST GÖRÜNÜRLÜĞÜ)
# ==============================================================================
def validate_config() -> list:
    """Yapılandırmadaki riskli durumları tespit eder ve loglar.

    Kritik bir hata bulunursa hata seviyesinde loglanır; çağıran taraf
    gerekirse servisi başlatmayı reddedebilir.
    """
    errors: list = []
    warnings: list = []

    if not WOL_AUTH_TOKEN:
        errors.append(
            "WOL_AUTH_TOKEN tanımsız. Tüm /api/* uç noktaları 401 dönecek "
            "(fail-closed). API üzerinden uyandırma çalışmayacak."
        )
    elif len(WOL_AUTH_TOKEN) < 16:
        warnings.append(
            f"WOL_AUTH_TOKEN yalnızca {len(WOL_AUTH_TOKEN)} karakter; en az 16 "
            "karakterlik yüksek entropili bir değer kullanın."
        )

    if TARGET_MAC.lower() == PLACEHOLDER_MAC:
        errors.append(
            f"TARGET_MAC hâlâ şablon değeri ({PLACEHOLDER_MAC}). Gerçek hedef "
            "cihazın MAC adresi girilmeden gateway çalıştırılmamalı."
        )
    elif len(TARGET_MAC.replace(":", "").replace("-", "").replace(".", "")) != 12:
        errors.append(f"TARGET_MAC geçersiz uzunlukta: {TARGET_MAC!r}")

    if MQTT_ENABLED:
        if not MQTT_BROKER_HOST:
            errors.append("MQTT_ENABLED=true ancak MQTT_BROKER_HOST boş.")
        elif MQTT_BROKER_HOST.lower() in PUBLIC_ANONYMOUS_BROKERS:
            warnings.append(
                f"MQTT_BROKER_HOST={MQTT_BROKER_HOST} halka açık ve anonim bir "
                "broker'dır. WAKE_TOPIC kanalı internete açıktır: kanal adı ve "
                "telemetri görünür, komutlar ise token olmadan gönderilemez. "
                "Üretimde kimlik doğrulamalı ve TLS'li kendi broker'ınızı kullanın."
            )
        if not MQTT_USER and not MQTT_TLS_ENABLED:
            warnings.append(
                "MQTT kimlik doğrulaması ve TLS birlikte kapalı: trafiğiniz "
                "düz metin, komut kanalınız izlenebilir."
            )
        if MQTT_TLS_ENABLED and not MQTT_CA_CERT_FILE:
            warnings.append(
                "MQTT_TLS_ENABLED=true ancak MQTT_CA_CERT_FILE boş. Sertifika "
                "doğrulaması yapılamaz; MITM'e açık olur."
            )
        if MQTT_BROKER_PORT == 1883 and MQTT_TLS_ENABLED:
            warnings.append(
                "TLS etkin ama port 1883 (düz metin). Çoğu broker TLS için 8883 "
                "bekler; bağlantı kurulamayabilir."
            )
    else:
        warnings.append(
            "MQTT_ENABLED=false: NodeMCU köprüsü devre dışı. Hedef CGNAT "
            "arkasındaysa yalnızca doğrudan UDP kanalı denenecek ve muhtemelen "
            "başarısız olacaktır."
        )

    if HEALTH_PROBE_HOST == "127.0.0.1":
        warnings.append(
            "HEALTH_PROBE_HOST=127.0.0.1 gateway'in kendi sunucusunu yoklar, "
            "hedef PC'yi değil. Durum paneli yanıltıcı 'online' gösterebilir."
        )

    for msg in warnings:
        logger.warning(f"[CONFIG-UYARI] {msg}")
    for msg in errors:
        logger.error(f"[CONFIG-HATA] {msg}")

    return errors
