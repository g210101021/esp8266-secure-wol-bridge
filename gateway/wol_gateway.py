"""
Asenkron ve Güvenli Wake-on-LAN (WoL) HTTP Gateway Sunucusu
==============================================================================
Bu modül, mikro-ajan ve uzak orkestratörler için REST API ve modern bir web
kontrol arayüzü sunar.

Güvenlik Mimarisi:
1. Sabit Zamanlı Kimlik Doğrulama (Constant-Time Token Auth): Zamanlama
   saldırılarına (timing attacks) karşı 'hmac.compare_digest' kullanılır.
2. Fail-Closed Koruması: WOL_AUTH_TOKEN yapılandırılmamışsa tüm korumalı uç
   noktalar otomatik olarak kilitlenir (401 Unauthorized).
3. Non-Blocking Canlılık Yoklaması: Bloklayıcı 'ping' alt süreci yerine
   asenkron soket bağlantısı ve TTL önbelleği (caching) kullanılır.
4. Güvenli Heartbeat: İstemcinin ilettiği gövdedeki sahte IP'ler reddedilir;
   yalnızca soket seviyesinde doğrulanan gerçek kaynak IP (request.remote) kaydedilir.
"""

import asyncio
import hmac
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

from aiohttp import web

from . import config
from .dispatcher import dispatcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("WoLGateway")

# Son bildirilen güvenli IP kaydı için dosya yolu
IP_RECORD_FILE = Path(__file__).resolve().parent / "last_reported_ip.txt"

# Canlılık Durumu Önbelleği (Sürekli soket açıp hedefi yormamak için)
_health_cache: Dict[str, Any] = {
    "online": False,
    "last_checked": 0.0
}


def verify_auth_token(request: web.Request) -> bool:
    """İstek başlıklarındaki (Header) token'ı sabit zamanlı olarak doğrular."""
    expected_token = config.WOL_AUTH_TOKEN
    if not expected_token:
        logger.error("[GÜVENLİK] Sunucuda 'WOL_AUTH_TOKEN' tanımlı değil! Fail-closed devrede.")
        return False

    # 1. 'X-Auth-Token' Başlığı
    token = request.headers.get("X-Auth-Token", "").strip()

    # 2. 'Authorization: Bearer <TOKEN>' Başlığı
    if not token:
        auth_header = request.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    # 3. Sabit zamanlı (Timing-attack resistant) karşılaştırma
    return hmac.compare_digest(token, expected_token)


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """API rotalarını yetkilendirme süzgecinden geçiren middleware."""
    # Web Dashboard kök sayfası veya statik dosyalar herkese açıktır (UI kendi içinde token sorar)
    if request.path == "/" or request.path.startswith("/static"):
        return await handler(request)

    # /api/* rotalarında kimlik doğrulama zorunludur
    if request.path.startswith("/api/"):
        if not verify_auth_token(request):
            return web.json_response(
                {
                    "ok": False,
                    "error": "Yetkisiz Erişim (401 Unauthorized)",
                    "message": "Geçerli bir 'X-Auth-Token' veya 'Authorization: Bearer <TOKEN>' başlığı sağlayınız."
                },
                status=401
            )

    return await handler(request)


async def check_target_online(host: str, port: int, timeout: float = 1.0) -> bool:
    """Hedef bilgisayarın dinlediği porta asenkron soket açarak canlılığını yoklar.
    
    Bloklayıcı 'subprocess.run(ping)' yerine asenkron soket kullanarak HTTP sunucusunun
    iş parçacığını asla dondurmaz.
    """
    global _health_cache
    now = time.time()

    # Önbellek süresi (TTL) dolmadıysa önceki sonucu dön
    if now - _health_cache["last_checked"] < config.HEALTH_CACHE_TTL:
        return _health_cache["online"]

    is_online = False
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        is_online = True
    except Exception:
        is_online = False

    _health_cache = {
        "online": is_online,
        "last_checked": now
    }
    return is_online


# ==============================================================================
# HTTP ROTA İŞLEYİCİLERİ (HANDLERS)
# ==============================================================================

async def handle_wake_post(request: web.Request) -> web.Response:
    """POST /api/wake - Bilgisayara Magic Packet fırlatır."""
    custom_ip = None
    try:
        if request.can_read_body:
            body = await request.json()
            if "target_ip" in body and body["target_ip"]:
                # IP adres formatını doğrula
                ipaddress.ip_address(body["target_ip"].strip())
                custom_ip = body["target_ip"].strip()
    except Exception:
        pass

    result = await dispatcher.dispatch_wake(custom_target_ip=custom_ip)
    status_code = 200 if result.get("ok") else 500
    return web.json_response(result, status=status_code)


async def handle_status_get(request: web.Request) -> web.Response:
    """GET /api/status - Hedef bilgisayarın çevrimiçi/çevrimdışı durumunu raporlar."""
    online = await check_target_online(config.HEALTH_PROBE_HOST, config.HEALTH_PROBE_PORT)
    
    last_reported_ip = ""
    if IP_RECORD_FILE.exists():
        try:
            last_reported_ip = IP_RECORD_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    return web.json_response({
        "online": online,
        "probe_target": f"{config.HEALTH_PROBE_HOST}:{config.HEALTH_PROBE_PORT}",
        "target_mac": config.TARGET_MAC,
        "last_reported_ip": last_reported_ip or config.TARGET_BROADCAST_IP,
        "timestamp": time.time()
    })


async def handle_heartbeat_post(request: web.Request) -> web.Response:
    """POST /api/heartbeat - İstemcinin dinamik WAN/yerel IP adresini güvenle kaydeder.
    
    GÜVENLİK: Gövdedeki rastgele IP'ler reddedilir; doğrudan soket seviyesindeki
    gerçek bağlantı adresi (request.remote) kaydedilir.
    """
    client_ip = request.remote or ""
    
    # Geçerli bir IP olup olmadığını kontrol et
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        if ip_obj.is_loopback and "X-Forwarded-For" in request.headers:
            # Reverse proxy arkasındaysa X-Forwarded-For'un ilk adresini al
            forwarded = request.headers["X-Forwarded-For"].split(",")[0].strip()
            ipaddress.ip_address(forwarded)
            client_ip = forwarded
    except ValueError:
        return web.json_response({"ok": False, "error": "Geçersiz IP adresi tespit edildi."}, status=400)

    try:
        IP_RECORD_FILE.write_text(client_ip, encoding="utf-8")
        logger.info(f"[HEARTBEAT] Yeni dinamik IP kaydedildi: {client_ip}")
        return web.json_response({"ok": True, "recorded_ip": client_ip})
    except Exception as e:
        logger.error(f"[HEARTBEAT-HATA] IP kaydı yazılamadı: {e}")
        return web.json_response({"ok": False, "error": str(e)}, status=500)


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure IoT WoL Gateway</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 20px; padding: 32px 24px; width: 100%; max-width: 440px; text-align: center; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
        h1 { font-size: 1.4rem; margin-bottom: 8px; font-weight: 700; }
        p.desc { font-size: 0.88rem; color: #94a3b8; margin-bottom: 24px; }
        .token-group { margin-bottom: 20px; text-align: left; }
        .token-group label { display: block; font-size: 0.78rem; color: #94a3b8; margin-bottom: 6px; font-weight: 600; }
        .token-group input { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 12px; color: #f8fafc; font-family: monospace; font-size: 0.9rem; }
        .status-badge { display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; margin-bottom: 24px; background: #334155; }
        .dot { width: 10px; height: 10px; border-radius: 50%; background: #64748b; }
        .btn-wake { width: 100%; background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; border: none; padding: 18px 20px; border-radius: 14px; font-size: 1.1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 14px rgba(37,99,235,0.4); }
        .btn-wake:active { transform: scale(0.97); }
        .btn-wake:disabled { opacity: 0.6; cursor: not-allowed; }
        .info-box { margin-top: 24px; padding: 14px; background: #0f172a; border-radius: 12px; font-size: 0.78rem; color: #64748b; text-align: left; border: 1px solid #1e293b; }
        .info-box div { margin-bottom: 6px; }
        .info-box span { color: #cbd5e1; font-family: monospace; }
        #toast { margin-top: 16px; font-size: 0.9rem; font-weight: 500; min-height: 24px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>⚡ Enterprise WoL Gateway</h1>
        <p class="desc">Asenkron & Yetkilendirilmiş Uyandırma İstasyonu</p>
        
        <div class="token-group">
            <label for="tokenInput">X-Auth-Token / Yetkilendirme Anahtarı</label>
            <input type="password" id="tokenInput" placeholder="Gizli Token'ınızı giriniz...">
        </div>

        <button class="btn-wake" id="wakeBtn" onclick="triggerWake()">🔌 Cihazı Uyandır</button>
        <div id="toast"></div>

        <div class="info-box">
            <div>• Güvenlik Modu: <span>Header Bearer / X-Auth-Token</span></div>
            <div>• Eşzamanlılık Kilidi: <span>Aktif (In-Flight Lock)</span></div>
            <div>• Tekilleştirme Sınırı: <span>15 saniye cooldown</span></div>
        </div>
    </div>

    <script>
        // Sayfa açıldığında yerel hafızadan kayıtlı token'ı getir
        document.getElementById('tokenInput').value = localStorage.getItem('wol_token') || '';

        async function triggerWake() {
            const token = document.getElementById('tokenInput').value.trim();
            const toast = document.getElementById('toast');
            const btn = document.getElementById('wakeBtn');

            if (!token) {
                toast.style.color = '#f87171';
                toast.innerText = 'Lütfen yetkilendirme token\'ı giriniz.';
                return;
            }
            localStorage.setItem('wol_token', token);

            btn.disabled = true;
            btn.innerText = '⏳ Sinyal İletiliyor...';
            toast.style.color = '#38bdf8';
            toast.innerText = 'Magic Packet tüm kanallara dağıtılıyor...';

            try {
                const res = await fetch('/api/wake', {
                    method: 'POST',
                    headers: { 'X-Auth-Token': token, 'Content-Type': 'application/json' }
                });
                const data = await res.json();

                if (res.status === 200 && data.ok) {
                    toast.style.color = '#4ade80';
                    toast.innerText = '✅ ' + data.message;
                } else if (res.status === 401) {
                    toast.style.color = '#f87171';
                    toast.innerText = '❌ Yetkisiz: Hatalı veya geçersiz token!';
                } else {
                    toast.style.color = '#f87171';
                    toast.innerText = '❌ ' + (data.message || data.error || 'İşlem başarısız');
                }
            } catch (err) {
                toast.style.color = '#f87171';
                toast.innerText = 'Bağlantı hatası oluştu.';
            } finally {
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerText = '🔌 Cihazı Uyandır';
                }, 3000);
            }
        }
    </script>
</body>
</html>
"""

async def handle_dashboard_get(request: web.Request) -> web.Response:
    """GET / - Modern kontrol paneli sayfasını döner."""
    return web.Response(text=HTML_DASHBOARD, content_type="text/html", charset="utf-8")


def create_app() -> web.Application:
    """Gateway web uygulamasını middleware ve rotalarıyla oluşturur."""
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get("/", handle_dashboard_get)
    app.router.add_post("/api/wake", handle_wake_post)
    app.router.add_get("/api/status", handle_status_get)
    app.router.add_post("/api/heartbeat", handle_heartbeat_post)
    return app


if __name__ == "__main__":
    app = create_app()
    logger.info(f"WoL Gateway {config.GATEWAY_HOST}:{config.GATEWAY_PORT} üzerinde başlatılıyor...")
    web.run_app(app, host=config.GATEWAY_HOST, port=config.GATEWAY_PORT)
