import json
import os
import pickle
import re
import subprocess
import sys
import urllib.parse
from collections import OrderedDict
from typing import Any, Dict, List, Optional
import requests


# (des) ofuscación
def to_signed_32(n: int) -> int:
    """Equivale a (int32) del JS original."""
    return n % ((-1 if n < 0 else 1) * 2 ** 32)


class _ByteGenerator:
    """
    PRNG idéntico al del JavaScript de xHamster.
    Cada algoritmo se identifica por el primer byte de la “parte hex”
    de la URL.  Si xHamster añade otro método sólo hay que crear _algo8().
    """

    def __init__(self, algo_id: int, seed: int):
        try:
            self._algorithm = getattr(self, f"_algo{algo_id}")
        except AttributeError:
            raise ValueError(f"Algoritmo desconocido: {algo_id}")
        self._s = to_signed_32(seed)

    # ---- 7 algoritmos portados de yt-dlp -----------------
    def _algo1(self, s: int) -> int:
        s = self._s = to_signed_32(s * 1664525 + 1013904223)
        return s

    def _algo2(self, s: int) -> int:
        s = to_signed_32(s ^ (s << 13))
        s = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 17))
        s = self._s = to_signed_32(s ^ (s << 5))
        return s

    def _algo3(self, s: int) -> int:
        s = self._s = to_signed_32(s + 0x9E3779B9)
        s = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 16))
        s = to_signed_32(s * to_signed_32(0x85EBCA77))
        s = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 13))
        s = to_signed_32(s * to_signed_32(0xC2B2AE3D))
        return to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 16))

    def _algo4(self, s: int) -> int:
        s = self._s = to_signed_32(s + 0x6D2B79F5)
        s = to_signed_32((s << 7) | ((s & 0xFFFFFFFF) >> 25))
        s = to_signed_32(s + 0x9E3779B9)
        s = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 11))
        return to_signed_32(s * 0x27D4EB2D)

    def _algo5(self, s: int) -> int:
        s = to_signed_32(s ^ (s << 7))
        s = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 9))
        s = to_signed_32(s ^ (s << 8))
        s = self._s = to_signed_32(s + 0xA5A5A5A5)
        return s

    def _algo6(self, s: int) -> int:
        s = self._s = to_signed_32(s * to_signed_32(0x2C9277B5) + to_signed_32(0xAC564B05))
        s2 = to_signed_32(s ^ ((s & 0xFFFFFFFF) >> 18))
        shift = (s & 0xFFFFFFFF) >> 27 & 31
        return to_signed_32((s2 & 0xFFFFFFFF) >> shift)

    def _algo7(self, s: int) -> int:
        s = self._s = to_signed_32(s + to_signed_32(0x9E3779B9))
        e = to_signed_32(s ^ (s << 5))
        e = to_signed_32(e * to_signed_32(0x7FEB352D))
        e = to_signed_32(e ^ ((e & 0xFFFFFFFF) >> 15))
        return to_signed_32(e * to_signed_32(0x846CA68B))

    def __next__(self) -> int:
        return self._algorithm(self._s) & 0xFF


class XHamsterScraper:
    _DOMAINS = r"(?:xhamster\.(?:com|one|desi)|xhms\.pro|xhamster\d+\.(?:com|desi)|xhday\.com|xhvid\.com)"
    _VIDEO_RE = re.compile(
        rf"""
        https?://(?:[^/]+\.)?{_DOMAINS}/
        (?:
            movies/(?P<id>[0-9A-Za-z]+)/[^/]+\.html |
            videos/[^/]+-(?P<id2>[0-9A-Za-z]+)
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    _HEX_RE = re.compile(r"^/(?P<hex>[0-9a-fA-F]{12,})(?P<rest>[/,].+)$")

    # ----------------------------- init ----------------------------- #
    def __init__(self, cookies_path: Optional[str] = None) -> None:
        self.cookies_path = cookies_path
        self.session = requests.Session()
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.proxies: Dict[str, Optional[str]] = {"http": None, "https": None}
        # cookies para saltar age-gate
        self.age_cookies = {"age_verified": "1", "accessAgeDisclaimerPH": "1", "accessPH": "1"}

        if self.cookies_path and os.path.isfile(self.cookies_path):
            self.load_cookies()

    def set_proxies(self, http_proxy: str, https_proxy: str) -> None:
        self.proxies.update({"http": http_proxy, "https": https_proxy})

    def load_cookies(self) -> bool:
        try:
            with open(self.cookies_path, "rb") as fh:
                self.session.cookies.update(pickle.load(fh))
            return True
        except Exception as e:
            print(f"[xHamster] No se pudieron cargar cookies: {e}")
            return False

    def set_age_cookies(self, host: str) -> None:
        for k, v in self.age_cookies.items():
            self.session.cookies.set(k, v, domain=host)

    # ------------------- descarga de páginas ----------------------- #
    def download_webpage(self, url: str) -> str:
        def _do() -> str:
            r = self.session.get(url, headers=self.headers, proxies=self.proxies, timeout=15)
            r.raise_for_status()
            return r.text

        html = _do()
        if any(w in html for w in ("document.cookie", "location.reload", "goAge")):
            host = re.search(r"https?://([^/]+)", url).group(1)  # type: ignore
            self.set_age_cookies(host)
            html = _do()
        return html

    # --------------- descifrado de URLs ofuscadas ------------------ #
    def _decipher_format_url(self, url: str) -> Optional[str]:
        pr = urllib.parse.urlparse(url)
        m = self._HEX_RE.match(pr.path)
        if not m:
            return url
        hex_str, rest = m.group("hex"), m.group("rest")
        data = bytes.fromhex(hex_str)
        algo_id, seed = data[0], int.from_bytes(data[1:5], "little", signed=True)
        try:
            gen = _ByteGenerator(algo_id, seed)
        except ValueError:
            return None
        plain = bytearray(b ^ next(gen) for b in data[5:]).decode("latin-1", errors="ignore")
        return pr._replace(path=f"/{plain}{rest}").geturl()

    # -------- leer master m3u8 y enumerar variantes disponibles ----- #
    def _extract_m3u8_variants(self, playlist_url: str, referer: str) -> list[dict[str, Any]]:
        """
        Devuelve una lista de variantes (2160p, 1080p, …) presentes
        en un master .m3u8.
        """
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Referer": referer,
        }
        r = self.session.get(
            playlist_url, headers=headers,
            proxies=self.proxies, timeout=10
        )
        r.raise_for_status()
        text = r.text
        base = playlist_url.rsplit("/", 1)[0] + "/"

        variants: List[Dict[str, Any]] = []
        attr_pat = re.compile(r'([A-Z0-9-]+)=("[^"]+"|[^,"]+)')
        current_inf: Dict[str, str] = {}

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-STREAM-INF:"):
                current_inf = {
                    k: v.strip('"')
                    for k, v in attr_pat.findall(line.split(":", 1)[1])
                }
            elif line and not line.startswith("#") and current_inf:
                var_url = urllib.parse.urljoin(base, line)
                res = current_inf.get("RESOLUTION")
                height = int(res.split("x")[1]) if res and "x" in res else None
                bw = current_inf.get("BANDWIDTH")
                tbr = int(bw) / 1000 if bw and bw.isdigit() else None
                variants.append(
                    {
                        "url": var_url,
                        "format_id": f"hls-{height or 'unk'}p",
                        "ext": "mp4",
                        "protocol": "m3u8",
                        "height": height,
                        "tbr": tbr,
                    }
                )
                current_inf = {}

        return variants
    # --------------------- extracción principal -------------------- #
    def extract_video_info(self, url: str) -> Dict[str, Any]:
        m = self._VIDEO_RE.match(url)
        if not m:
            raise Exception("La URL no pertenece a xHamster.")
        video_id = m.group("id") or m.group("id2")
        page = self.download_webpage(url)

        err = re.search(r'<div[^>]+id=["\']videoClosed["\'][^>]*>(.+?)</div>', page, re.DOTALL)
        if err:
            raise Exception("xHamster responde: " + re.sub(r"\s+", " ", err.group(1)).strip())

        initials_m = re.search(r"window\.initials\s*=\s*({.+?})\s*;", page)
        if not initials_m:
            raise Exception("No se encontró metadata JSON.")
        initials = json.loads(initials_m.group(1))
        video = initials["videoModel"]

        # ------------------ recolectar formatos --------------------
        formats: List[Dict[str, Any]] = []
        seen: set[str] = set()

        def _add(furl: str, fmt_id: str, quality: Optional[str] = None) -> None:
            if not furl:
                return
            furl = self._decipher_format_url(furl) or furl
            if furl in seen:
                return
            seen.add(furl)
            entry = {
                "url": furl,
                "format_id": fmt_id,
                "quality": quality,
            }
            if furl.endswith(".m3u8"):
                variants = self._extract_m3u8_variants(furl, referer=url)
                formats.extend(variants)
            else:
                m = re.search(r"(\d{3,4})p", fmt_id)
                entry["height"] = int(m.group(1)) if m else None
                formats.append(entry)

        xplayer = initials.get("xplayerSettings", {}).get("sources", {})
        # HLS
        hls = xplayer.get("hls", {})
        _add(hls.get("url"), "hls-url")
        _add(hls.get("fallback"), "hls-fallback")

        # MP4 estándar
        standard = xplayer.get("standard", {})
        for ident, lst in standard.items():
            if not isinstance(lst, list):
                continue
            for e in lst:
                label = str(e.get("label") or e.get("quality") or "")
                _add(e.get("url"), f"{ident}-{label}", label)
                _add(e.get("fallback"), f"{ident}-{label}-fb", label)

        if not formats:
            raise Exception("No se hallaron formatos (¿cambio de diseño?).")

        # ------------------- resto de metadata ---------------------
        def _i(k: str) -> Optional[int]:
            try:
                return int(video.get(k)) if video.get(k) is not None else None
            except (ValueError, TypeError):
                return None

        return {
            "id": video_id,
            "title": f"DescargarBot_xHamster_{video_id}",
            "thumbnail": video.get("thumbURL"),
            "formats": formats,
        }

    # ------------------ elegir mejor variante --------------------- #
    def get_best_format(self, formats: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not formats:
            return None

        def _score(f: Dict[str, Any]) -> int:
            if f.get("height"):
                return int(f["height"])
            if f.get("tbr"):
                return int(f["tbr"])
            m = re.search(r"(\d+)(?:p|k)?", str(f.get("quality") or f.get("format_id") or ""))
            return int(m.group(1)) if m else 0

        return max(formats, key=_score)

    # --------------- helpers para descarga con ffmpeg -------------- #
    def _ffmpeg_header_string(self, extra: Optional[Dict[str, str]] = None) -> str:
        hdr = {"User-Agent": self.headers["User-Agent"]}
        cookies = "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)
        if cookies:
            hdr["Cookie"] = cookies
        if extra:
            hdr.update(extra)
        return "".join(f"{k}: {v}\r\n" for k, v in hdr.items())

    def download_video_with_ffmpeg(self, media_url: str, output_path: str, referer_url: Optional[str] = None) -> bool:
        # cdn requiere al menos referer
        header_str = self._ffmpeg_header_string({"Referer": referer_url} if referer_url else None)
        cmd = [
            "ffmpeg",
            "-headers",
            header_str,
            "-i",
            media_url,
            "-c",
            "copy",
            "-bsf:a",
            "aac_adtstoasc",
            output_path,
        ]
        try:
            print("[xHamster] Ejecutando ffmpeg …")
            subprocess.run(cmd, check=True)
            print(f"[xHamster] Vídeo guardado en {output_path}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[xHamster] ffmpeg devolvió error:\n{e}")
            return False

##########################################################################
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python xh_scraper.py <url_video_xhamster>")
        sys.exit(1)

    video_url = sys.argv[1]
    scraper = XHamsterScraper()

    try:
        info = scraper.extract_video_info(video_url)
        print(json.dumps(info, indent=4, ensure_ascii=False))

        best = scraper.get_best_format(info["formats"])
        if best:
            print(f"\nMejor formato: {best['format_id']} -> {best['url']}")
            nombre = re.sub(r'[<>:"/\\|?*]', "_", info["title"]) + ".mp4"
            scraper.download_video_with_ffmpeg(best["url"], nombre, referer_url=video_url)
        else:
            print("No se encontraron formatos para descargar.")
    except Exception as exc:
        print("ERROR:", exc)
