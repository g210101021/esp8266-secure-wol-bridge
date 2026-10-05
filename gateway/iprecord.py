"""
Güvenli Dinamik IP Kaydı (Trusted IP Record)
==============================================================================
CGNAT arkasındaki ev ağı, her yeniden bağlanmada dış IP'sini değiştirebilir.
Bu modül, istemcinin (PC / bridge) bildirdiği IP'yi *güvenilir biçimde* saklar.

Güvenlik Tasarımı:
- Gövdede (body) gelen IP'ler ASLA körlemesine kabul edilmez. (Eski sürümdeki
  sahte-IP enjeksiyonu açığının kapatılması.)
- Sadece soket seviyesinde doğrulanabilen gerçek kaynak adresi esas alınır.
- Yazılacak değer mutlaka geçerli bir IP olarak yeniden doğrulanır.
- Dosya yazımı atomiktir; yarım kalmış/bozuk kayıt okuma tarafını bozmaz.
"""

import ipaddress
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("WoLIPRecord")

# Raporlanan IP kaydının dosya yolu
IP_RECORD_FILE = Path(__file__).resolve().parent / "last_reported_ip.txt"


def normalize_ip(raw: Optional[str]) -> Optional[str]:
    """Verilen ham IP metnini doğrular ve normalize eder.

    Geçersiz/boş girdi durumunda None döner (fail-closed).
    """
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(str(raw).strip()))
    except ValueError:
        return None


def resolve_client_ip(remote: Optional[str], xff_header: Optional[str]) -> Optional[str]:
    """İstekten güvenilir kaynak IP'yi belirler.

    Yalnızca 'remote' bir loopback adresi ise ve istemci açıkça bir reverse proxy
    arkasından geliyorsa X-Forwarded-For değerlendirilir. Aksi halde soketin
    gerçek adresi esas alınır.
    """
    remote_ip = normalize_ip(remote)
    if remote_ip is None:
        return None

    try:
        is_loopback = ipaddress.ip_address(remote_ip).is_loopback
    except ValueError:
        return None

    if is_loopback and xff_header:
        first = xff_header.split(",")[0]
        forwarded = normalize_ip(first)
        if forwarded:
            return forwarded

    return remote_ip


def write_ip(raw_ip: str) -> Optional[str]:
    """IP kaydını atomik olarak diske yazar. Başarılıysa normalize IP'yi döner."""
    normalized = normalize_ip(raw_ip)
    if normalized is None:
        raise ValueError(f"Geçersiz IP adresi reddedildi: {raw_ip!r}")

    IP_RECORD_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Atomik yazım: aynı dizinde geçici dosya + rename
    fd, tmp_path = tempfile.mkstemp(dir=str(IP_RECORD_FILE.parent), prefix=".iprecord-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(normalized)
        os.replace(tmp_path, IP_RECORD_FILE)
    except Exception:
        # Yarım kalmış geçici dosyayı temizle
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return normalized


def read_ip() -> Optional[str]:
    """Kayıtlı IP'yi doğrulayarak okur. Kayıt yoksa veya bozuksa None döner."""
    try:
        if not IP_RECORD_FILE.exists():
            return None
        return normalize_ip(IP_RECORD_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"IP kaydı okunamadı, yok sayılıyor: {e}")
        return None
