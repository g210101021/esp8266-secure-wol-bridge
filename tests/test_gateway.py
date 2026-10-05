"""
Birim ve Entegrasyon Testleri - Secure WoL Gateway
==============================================================================
"""

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway import config
from gateway.dispatcher import WakeDispatcher, dispatcher
from gateway import iprecord
from gateway.wol_gateway import create_app, verify_auth_token


@pytest.fixture(autouse=True)
def isolate_config(tmp_path, monkeypatch):
    """Her testi temiz bir config/IP kaydı ile çalıştırır.

    Önceki sürümde testler config.* değerlerini kalıcı olarak değiştiriyor ve
    IP kaydını gerçek dosyaya yazıyordu; testler birbirini etkiliyordu.
    """
    monkeypatch.setattr(iprecord, "IP_RECORD_FILE", tmp_path / "last_reported_ip.txt")
    for attr, value in [
        ("WOL_AUTH_TOKEN", "test_secret_token_12345"),
        ("WAKE_COOLDOWN_SECONDS", 10.0),
        ("MQTT_ENABLED", False),
        ("PREFER_RECORDED_IP", False),
        ("TARGET_MAC", "00:11:22:33:44:55"),
        ("TARGET_BROADCAST_IP", "255.255.255.255"),
        ("HEALTH_CACHE_TTL", 5.0),
    ]:
        monkeypatch.setattr(config, attr, value)
    yield


class TestWakeDispatcher:
    def test_build_magic_packet_valid_mac(self):
        """Standard 102-byte Magic Packet generation test."""
        mac = "00:11:22:33:44:55"
        packet = WakeDispatcher.build_magic_packet(mac)
        
        assert len(packet) == 102
        # İlk 6 bayt 0xFF olmalıdır
        assert packet[:6] == b"\xff" * 6
        # Kalan 96 bayt, MAC adresinin 16 kez tekrardır
        mac_bytes = bytes.fromhex("001122334455")
        for i in range(16):
            start = 6 + (i * 6)
            assert packet[start:start + 6] == mac_bytes

    def test_build_magic_packet_invalid_mac(self):
        """Hatalı MAC adresi verildiğinde ValueError fırlatılmalıdır."""
        with pytest.raises(ValueError):
            WakeDispatcher.build_magic_packet("invalid-mac-string")

    @pytest.mark.asyncio
    async def test_wake_cooldown_deduplication(self):
        """Cooldown süresi içinde ardışık çağrılarda gereksiz paket gönderilmemelidir."""
        disp = WakeDispatcher()
        disp._last_wake_time = 0.0

        res1 = await disp.dispatch_wake()
        assert res1["cooldown_active"] is False
        assert res1["dispatched"] is True

        res2 = await disp.dispatch_wake()
        assert res2["cooldown_active"] is True
        assert res2["remaining_cooldown_seconds"] > 0
        # Kritik: cooldown yanıtı 'ok' dese bile paket GÖNDERİLMEMİŞ olmalı.
        assert res2["dispatched"] is False

    def test_resolve_target_ip_precedence(self, monkeypatch):
        """Hedef IP önceliği: özel hedef > kaydedilen IP > yapılandırılmış hedef."""
        disp = WakeDispatcher()

        assert disp.resolve_target_ip("1.2.3.4") == "1.2.3.4"

        iprecord.write_ip("203.0.113.9")

        # PREFER_RECORDED_IP kapalıyken kayıt yok sayılır
        assert disp.resolve_target_ip() == "255.255.255.255"

        monkeypatch.setattr(config, "PREFER_RECORDED_IP", True)
        assert disp.resolve_target_ip() == "203.0.113.9"


class TestIPRecord:
    def test_rejects_garbage(self):
        """Geçersiz IP'ler kaydedilmemeli (sahte-IP enjeksiyonu koruması)."""
        for bad in ["not-an-ip", "", "999.1.1.1", "1.2.3.4; rm -rf /", None]:
            with pytest.raises(ValueError):
                iprecord.write_ip(bad)

    def test_roundtrip_and_read_missing(self, tmp_path, monkeypatch):
        iprecord.write_ip("198.51.100.7")
        assert iprecord.read_ip() == "198.51.100.7"

        monkeypatch.setattr(iprecord, "IP_RECORD_FILE", tmp_path / "yok.txt")
        assert iprecord.read_ip() is None

    def test_read_corrupt_record_returns_none(self, tmp_path, monkeypatch):
        corrupt = tmp_path / "bozuk.txt"
        corrupt.write_text("bu bir IP degildir", encoding="utf-8")
        monkeypatch.setattr(iprecord, "IP_RECORD_FILE", corrupt)
        assert iprecord.read_ip() is None

    def test_resolve_client_ip_ignores_xff_from_public_ip(self):
        """Uzak (loopback olmayan) istemcinin XFF başlığı güvenilmezdir."""
        resolved = iprecord.resolve_client_ip("198.51.100.20", "10.0.0.1")
        assert resolved == "198.51.100.20"

    def test_resolve_client_ip_trusts_xff_behind_loopback(self):
        resolved = iprecord.resolve_client_ip("127.0.0.1", "198.51.100.55, 10.0.0.1")
        assert resolved == "198.51.100.55"


class TestConfigValidation:
    def test_placeholder_mac_is_error(self, monkeypatch):
        monkeypatch.setattr(config, "TARGET_MAC", "00:11:22:33:44:55")
        monkeypatch.setattr(config, "MQTT_ENABLED", False)
        errors = config.validate_config()
        assert any("şablon" in e for e in errors)

    def test_missing_token_is_error(self, monkeypatch):
        monkeypatch.setattr(config, "WOL_AUTH_TOKEN", "")
        errors = config.validate_config()
        assert any("WOL_AUTH_TOKEN" in e for e in errors)

    def test_public_broker_is_warned(self, monkeypatch):
        monkeypatch.setattr(config, "TARGET_MAC", "00:e0:4c:5e:27:38")
        monkeypatch.setattr(config, "MQTT_ENABLED", True)
        monkeypatch.setattr(config, "MQTT_BROKER_HOST", "broker.hivemq.com")
        errors = config.validate_config()
        assert not any("şablon" in e for e in errors)
        assert not any("WOL_AUTH_TOKEN" in e for e in errors)


@pytest.mark.asyncio
async def test_auth_and_endpoints():
    """API Uç Noktaları ve Kimlik Doğrulama Middleware Testi."""
    test_token = "test_secret_token_12345"

    app = create_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()

    try:
        # 1. Web Paneli (Dashboard) herkese açık olmalıdır
        resp_root = await client.get("/")
        assert resp_root.status == 200

        # 2. Yetkisiz API İsteği (Token Yok) -> 401 Unauthorized
        resp_unauth = await client.post("/api/wake")
        assert resp_unauth.status == 401
        data_unauth = await resp_unauth.json()
        assert data_unauth["ok"] is False

        # 3. Hatalı Token -> 401 Unauthorized
        resp_wrong = await client.post("/api/wake", headers={"X-Auth-Token": "wrong_token"})
        assert resp_wrong.status == 401

        # 4. Doğru Token (X-Auth-Token) -> 200 OK
        resp_auth = await client.post("/api/wake", headers={"X-Auth-Token": test_token})
        assert resp_auth.status == 200
        data_auth = await resp_auth.json()
        assert data_auth["ok"] is True

        # 5. Doğru Token (Authorization: Bearer <token>) -> 200 OK
        resp_bearer = await client.get("/api/status", headers={"Authorization": f"Bearer {test_token}"})
        assert resp_bearer.status == 200
        data_status = await resp_bearer.json()
        assert "online" in data_status

        # 6. Gövdede geçerli bir hedef IP verilirse o hedefe gidilmeli.
        # Önceki uyandırma singleton dispatcher'da cooldown bıraktığı için
        # bu testin anlamlı olması adına cooldown sıfırlanır.
        dispatcher._last_wake_time = 0.0
        resp_spoof = await client.post(
            "/api/wake",
            headers={"X-Auth-Token": test_token},
            json={"target_ip": "1.2.3.4"},
        )
        assert resp_spoof.status == 200
        assert (await resp_spoof.json())["target_ip"] == "1.2.3.4"

        # 7. Heartbeat: gövdedeki sahte IP gövdeden değil soketten alınmalı
        resp_hb = await client.post(
            "/api/heartbeat",
            headers={"X-Auth-Token": test_token},
            json={"ip": "6.6.6.6"},
        )
        assert resp_hb.status == 200
        assert (await resp_hb.json())["recorded_ip"] != "6.6.6.6"
    finally:
        await client.close()
