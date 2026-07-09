"""Client HTTP minimal et robuste (stdlib uniquement, zéro dépendance)."""

from __future__ import annotations

import gzip
import time
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


USER_AGENT = (
    "wp-doctor/1.0 (+https://wpadminlab.com; audit WordPress à distance)"
)


@dataclass
class Response:
    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        # Recherche insensible à la casse
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return default


def _decode(raw: bytes, headers: dict) -> str:
    enc = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding":
            enc = v.lower()
    if "gzip" in enc:
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError):
            # Flux tronqué (max_bytes) : décompresser ce qui est disponible.
            try:
                import zlib
                d = zlib.decompressobj(zlib.MAX_WBITS | 16)
                raw = d.decompress(raw)
            except (OSError, EOFError, zlib.error):
                pass
    # Charset depuis le header si présent
    charset = "utf-8"
    for k, v in headers.items():
        if k.lower() == "content-type" and "charset=" in v.lower():
            charset = v.lower().split("charset=")[-1].split(";")[0].strip()
            break
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return raw.decode("utf-8", errors="replace")


def fetch(
    url: str,
    method: str = "GET",
    timeout: float = 15.0,
    max_bytes: int = 3_000_000,
    verify_tls: bool = True,
    allow_redirects: bool = True,
) -> Response:
    """Récupère une URL. Ne lève jamais : les erreurs vont dans Response.error."""
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept-Encoding", "gzip")
    req.add_header("Accept", "*/*")

    start = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            headers = dict(resp.headers.items())
            body = _decode(raw, headers) if method != "HEAD" else ""
            return Response(
                url=url,
                status=resp.status,
                headers=headers,
                body=body,
                elapsed_ms=(time.perf_counter() - start) * 1000,
            )
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(max_bytes)
        except Exception:
            pass
        headers = dict(e.headers.items()) if e.headers else {}
        return Response(
            url=url,
            status=e.code,
            headers=headers,
            body=_decode(raw, headers),
            elapsed_ms=(time.perf_counter() - start) * 1000,
        )
    except urllib.error.URLError as e:
        return Response(url=url, status=0, elapsed_ms=(time.perf_counter() - start) * 1000, error=str(e.reason))
    except (ssl.SSLError, TimeoutError, OSError) as e:
        return Response(url=url, status=0, elapsed_ms=(time.perf_counter() - start) * 1000, error=str(e))
