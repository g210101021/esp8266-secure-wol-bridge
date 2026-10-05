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

import os
from pathlib import Path
from typing import Optional

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

# Yerel ağ veya WAN WoL broadcast hedefi
TARGET_BROADCAST_IP: str = os.getenv("TARGET_BROADCAST_IP", "255.255.255.255").strip()
WOL_PORT: int = int(os.getenv("WOL_PORT", "9"))

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
MQTT_ENABLED: bool = os.getenv("MQTT_ENABLED", "true").lower() in ("true", "1", "yes")
MQTT_BROKER_HOST: str = os.getenv("MQTT_BROKER_HOST", "broker.hivemq.com").strip()
MQTT_BROKER_PORT: int = int(os.getenv("MQTT_BROKER_PORT", "1883"))
MQTT_USER: str = os.getenv("MQTT_USER", "").strip()
MQTT_PASSWORD: str = os.getenv("MQTT_PASSWORD", "").strip()

MQTT_TOPIC_PREFIX: str = os.getenv("MQTT_TOPIC_PREFIX", "edge/wol/device").strip()
MQTT_WAKE_TOPIC: str = f"{MQTT_TOPIC_PREFIX}/wake"
MQTT_STATUS_TOPIC: str = f"{MQTT_TOPIC_PREFIX}/status"
