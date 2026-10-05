"""
WoL Dağıtıcı ve Eşzamanlılık Yöneticisi (Dispatcher & Concurrency Manager)
==============================================================================
Bu modül, Wake-on-LAN sihirli paketlerinin (Magic Packet) hem doğrudan UDP
broadcast hem de MQTT köprüsü (NodeMCU ESP8266) üzerinden güvenli ve
tekilleştirilmiş (deduplicated) olarak iletilmesini sağlar.

Mimari Özellikler:
1. In-Flight Lock (Eşzamanlılık Kilidi): Aynı anda gelen birden fazla uyandırma
   isteğinde sistemi kitlememek ve ağda paket fırtınası yaratmamak için tek
   bir işlem yürütülür.
2. Cooldown (Geri Çekilme / Hız Sınırı): Son gönderimden bu yana belirli bir süre
   (WAKE_COOLDOWN_SECONDS) geçmemişse mükerrer paket gönderimi engellenir.
3. Çoklu İletim Kanalı (Redundant Delivery): Hem doğrudan yerel ağ UDP soketi
   hem de CGNAT aşan NodeMCU MQTT kanalı asenkron olarak tetiklenir.
"""

import asyncio
import logging
import socket
import time
from typing import Dict, Any, Tuple

from . import config

logger = logging.getLogger("WoLDispatcher")


class WakeDispatcher:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._last_wake_time: float = 0.0

    @staticmethod
    def build_magic_packet(mac_address: str) -> bytes:
        """Hedef MAC adresinden standart 102 baytlık WoL Sihirli Paketi oluşturur.
        
        Format: 6 bayt 0xFF + 16 kez tekrarlanan 6 baytlık hedef MAC adresi.
        """
        clean_mac = mac_address.replace(":", "").replace("-", "").replace(".", "")
        if len(clean_mac) != 12:
            raise ValueError(f"Geçersiz MAC adresi uzunluğu ({mac_address}): 12 onaltılık karakter bekleniyor.")
        
        mac_bytes = bytes.fromhex(clean_mac)
        return b"\xff" * 6 + mac_bytes * 16

    async def _send_udp_broadcast(self, magic_packet: bytes, target_ip: str, port: int) -> bool:
        """Yerel ağ veya yönlendirilmiş WAN IP adresine UDP broadcast paketi fırlatır."""
        def _sync_send():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                for _ in range(3):
                    s.sendto(magic_packet, (target_ip, port))
                    time.sleep(0.03)

        try:
            await asyncio.to_thread(_sync_send)
            logger.info(f"[UDP] Magic Packet 3 kez {target_ip}:{port} hedefine iletildi.")
            return True
        except Exception as e:
            logger.error(f"[UDP-HATA] Magic Packet iletimi başarısız: {e}")
            return False

    async def _send_mqtt_trigger(self) -> bool:
        """NodeMCU ESP8266 köprüsüne MQTT üzerinden yetkilendirilmiş WAKE mesajı yayınlar."""
        if not config.MQTT_ENABLED:
            return False

        def _sync_publish():
            import paho.mqtt.publish as mqtt_pub
            
            # Yetkilendirme token'ı varsa 'WAKE:<TOKEN>' formatında ilet
            if config.WOL_AUTH_TOKEN:
                payload = f"WAKE:{config.WOL_AUTH_TOKEN}"
            else:
                payload = "WAKE"

            auth = None
            if config.MQTT_USER:
                auth = {"username": config.MQTT_USER, "password": config.MQTT_PASSWORD}

            mqtt_pub.single(
                config.MQTT_WAKE_TOPIC,
                payload=payload,
                hostname=config.MQTT_BROKER_HOST,
                port=config.MQTT_BROKER_PORT,
                auth=auth,
                retain=False,
                keepalive=10
            )

        try:
            await asyncio.to_thread(_sync_publish)
            logger.info(f"[MQTT] WAKE tetikleyici {config.MQTT_WAKE_TOPIC} kanalına başarıyla iletildi.")
            return True
        except Exception as e:
            logger.error(f"[MQTT-HATA] NodeMCU MQTT tetikleme başarısız: {e}")
            return False

    async def dispatch_wake(self, custom_target_ip: str = None) -> Dict[str, Any]:
        """Tüm kanallardan uyandırma sinyallerini eşzamanlılık kilidi ve hız sınırı altında fırlatır."""
        async with self._lock:
            now = time.time()
            elapsed_since_last = now - self._last_wake_time

            # 1. Hız Sınırı / Tekilleştirme Kontrolü (Rate-limiting / Cooldown)
            if elapsed_since_last < config.WAKE_COOLDOWN_SECONDS:
                remaining = round(config.WAKE_COOLDOWN_SECONDS - elapsed_since_last, 1)
                logger.info(f"[DEDUPE] Yakın zamanda paket atıldı. Kalan bekleme: {remaining} sn.")
                return {
                    "ok": True,
                    "cooldown_active": True,
                    "remaining_cooldown_seconds": remaining,
                    "message": f"Sihirli paket yakın zamanda gönderildi. Lütfen {remaining} sn bekleyin."
                }

            # 2. Paketi Hazırla
            magic_packet = self.build_magic_packet(config.TARGET_MAC)
            target_ip = custom_target_ip or config.TARGET_BROADCAST_IP

            # 3. İletişim Kanallarını Paralel Çalıştır
            udp_task = self._send_udp_broadcast(magic_packet, target_ip, config.WOL_PORT)
            mqtt_task = self._send_mqtt_trigger()

            results = await asyncio.gather(udp_task, mqtt_task, return_exceptions=True)
            udp_success = results[0] is True
            mqtt_success = results[1] is True

            self._last_wake_time = time.time()

            return {
                "ok": udp_success or mqtt_success,
                "cooldown_active": False,
                "channels": {
                    "direct_udp": udp_success,
                    "mqtt_bridge": mqtt_success
                },
                "target_mac": config.TARGET_MAC,
                "target_ip": target_ip,
                "timestamp": self._last_wake_time,
                "message": "Sihirli paketler (WoL) başarıyla tüm aktif kanallara iletildi."
            }


# Singleton Dağıtıcı Örneği
dispatcher = WakeDispatcher()
