"""
Birim ve Entegrasyon Testleri - Secure WoL Gateway
==============================================================================
"""

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway import config
from gateway.dispatcher import WakeDispatcher, dispatcher
from gateway.wol_gateway import create_app, verify_auth_token


class TestWakeDispatcher:
    def test_build_magic_packet_valid_mac(self):
        """Standard 102-byte Magic Packet generation test."""
        mac = "00:11:22:33:44:55"
        packet = WakeDispatcher.build_magic_packet(mac)
        
        assert len(packet) == 102
        # İlk 6 bayt 0xFF olmalıdır
        assert packet[:6] == b"\xff" * 6
        # Kalan 96 bayt, MAC adresinin 16 kez tekrarıdır
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
        config.WAKE_COOLDOWN_SECONDS = 10.0
        config.MQTT_ENABLED = False

        # İlk çağrı (Cooldown yok)
        res1 = await disp.dispatch_wake()
        assert res1["cooldown_active"] is False

        # İkinci anlık çağrı (Cooldown aktif olmalı)
        res2 = await disp.dispatch_wake()
        assert res2["cooldown_active"] is True
        assert res2["remaining_cooldown_seconds"] > 0


@pytest.mark.asyncio
async def test_auth_and_endpoints():
    """API Uç Noktaları ve Kimlik Doğrulama Middleware Testi."""
    test_token = "test_secret_token_12345"
    config.WOL_AUTH_TOKEN = test_token
    config.MQTT_ENABLED = False

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
    finally:
        await client.close()
