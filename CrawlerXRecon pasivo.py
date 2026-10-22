"""
CrawlerX.py — Recon pasivo de versión PHP (ejemplo didáctico)

Uso:
    python CrawlerX.py https://ejemplo.com --max-pages 20
    python CrawlerX.py https://ejemplo.com --output reporte.json
    python CrawlerX.py https://ejemplo.com --ignore-robots

Requiere:
    pip install requests beautifulsoup4 packaging
"""

import argparse
import re
import sys
import time
import random
import logging
import json
import csv
from collections import deque
from urllib.parse import (
    urlparse, urljoin, urlunparse, parse_qsl, urlencode,
)
from urllib.robotparser import RobotFileParser

import requests
import urllib3
from bs4 import BeautifulSoup
from packaging import version

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
    "Gecko/20100101 Firefox/121.0",
]

SAFE_BRANCHES = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}

IGNORE_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".css", ".js",
    ".zip", ".rar", ".7z", ".mp4", ".mp3", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
)

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "yclid", "_ga", "_gl",
}

PHP_PATTERNS = [
    re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I),
    re.compile(r"PHP\s+Version\s+(\d+\.\d+\.\d+)", re.I),
    re.compile(r"\bPHP\s+(\d+\.\d+\.\d+)\b", re.I),
]

MAX_BODY_BYTES = 512 * 1024
REQUEST_TIMEOUT = 10
MAX_RETRIES = 2

# NUEVO: Firmas de WAFs conocidos
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
    "Akamai": ["akamai", "akamaighost"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "AWS WAF": ["awselb", "x-amzn-requestid"],
    "Incapsula": ["incap_ses", "visid_incap"],
    "F5 BIG-IP": ["bigip", "tsxxxx"]
}

log = logging.getLogger("spider")


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def human_delay(min_sec: float = 1.5, max_sec: float = 4.0) -> None:
    time.sleep(random.uniform(min_sec, max_sec))

def get_headers(referer: str | None = None) -> dict:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    }
    if referer:
        headers["Referer"] = referer
        headers["Sec-Fetch-Site"] = "same-origin"
    else:
        headers["Sec-Fetch-Site"] = "none"
    return headers

def clean_url(parsed) -> str:
    q = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in TRACKING_PARAMS
    ]
    return urlunparse(parsed._replace(query=urlencode(q), fragment=""))

def check_vulnerability(php_ver: str | None) -> str:
    if not php_ver:
        return "No determinada"
    try:
        v = version.parse(php_ver)
    except Exception:
        return "Error de parsing"

    branch = f"{v.major}.{v.minor}"
    if branch in SAFE_BRANCHES:
        patched = version.parse(SAFE_BRANCHES[branch])
        if v < patched:
            return f"VULNERABLE (parcheado en {SAFE_BRANCHES[branch]})"
        return "SEGURA (rama soportada)"

    if v.major < 8 or (v.major == 8 and v.minor < 2):
        return "CRÍTICA (EOL, sin soporte)"
    return "REVISAR (rama no catalogada)"

def extract_php_version(resp: requests.Response) -> str | None:
    for h in ("X-Powered-By", "Server", "Via"):
        value = resp.headers.get(h, "")
        for pat in PHP_PATTERNS:
            m = pat.search(value)
            if m:
                return m.group(1)

    body = resp.text[:MAX_BODY_BYTES]
    for pat in PHP_PATTERNS:
        m = pat.search(body)
        if m:
            return m.group(1)
    return None

def is_html(resp: requests.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "").lower()
    return ctype.startswith("text/html") or ctype.startswith("application/xhtml")

# NUEVO: Función para detectar el WAF
def detect_waf(resp: requests.Response) -> str | None:
    """Revisa las cabeceras y el cuerpo buscando firmas de WAFs conocidos."""
    headers_str = str(resp.headers).lower()
    body_str = resp.text[:2000].lower() if resp.text else ""
    
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig in headers_str or sig in body_str:
                return waf_name
    return None

def fetch(session: requests.Session, url: str, referer: str | None) -> requests.Response | None:
    for attempt in range(MAX_RETRIES + 1):
        try:
            r = session.get(url, headers=get_headers(referer), timeout=REQUEST_TIMEOUT)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                wait = 2 ** attempt + random.uniform(0, 1)
                log.warning("HTTP %s en %s, reintento en %.1fs", r.status_code, url, wait)
                time.sleep(wait)
                continue
            
            # NUEVO: Si el servidor bloquea (403 o 503), avisamos si hay un WAF
            if r.status_code in (403, 503):
                waf = detect_waf(r)
                if waf:
                    log.warning("¡ALERTA! WAF detectado: %s. El escaneo podría estar bloqueado.", waf)
                else:
                    log.warning("HTTP %s. Posible bloqueo sin WAF identificado.", r.status_code)

            return r
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
            log.error("Error de red en %s: %s", url, e)
            return None
    return None

def load_robots(session: requests.Session, base_url: str) -> RobotFileParser:
    rp = RobotFileParser()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        r = session.get(robots_url, headers=get_headers(), timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            rp.parse(r.text.splitlines())
        else:
            rp.allow_all = True
    except requests.exceptions.RequestException:
        rp.allow_all = True
    return rp


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

def spider_website(start_url: str, max_pages: int = 15, verify_tls: bool = True, ignore_robots: bool = False) -> dict:
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    base = urlparse(start_url)
    base_domain = base.netloc

    session = requests.Session()
    session.verify = verify_tls
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("Verificación TLS deshabilitada: solo para entornos controlados")

    # NUEVO: Si ignore_robots es True, creamos un objeto que permite todo
    if ignore_robots:
        log.warning("¡Atención! Ignorando robots.txt por petición del usuario (Modo Laboratorio)")
        robots = RobotFileParser()
        robots.allow_all = True
    else:
        robots = load_robots(session, start_url)

    queue = deque([(start_url, None)])
    seen = {start_url}
    results = []
    pages_scanned = 0

    log.info("Iniciando spider en %s (máx %d páginas)", start_url, max_pages)

    while queue and pages_scanned < max_pages:
        current_url, referer = queue.popleft()

        if not robots.can_fetch("*", current_url):
            log.info("robots.txt prohíbe %s, se omite", current_url)
            continue

        pages_scanned += 1
        log.info("(%d/%d) %s", pages_scanned, max_pages, current_url)

        resp = fetch(session, current_url, referer)
        if resp is None:
            continue
        if resp.status_code != 200:
            log.info("  HTTP %s, se ignora", resp.status_code)
            continue
        if not is_html(resp):
            log.info("  Content-Type no HTML, se ignora")
            continue

        php_ver = extract_php_version(resp)
        if php_ver:
            status = check_vulnerability(php_ver)
            log.info("  PHP %s -> %s", php_ver, status)
            results.append({
                "url": current_url,
                "php_version": php_ver,
                "status": status,
            })
        else:
            log.debug("  Sin rastro de PHP")

        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            full = urljoin(current_url, a["href"])
            p = urlparse(full)

            if p.scheme not in ("http", "https"):
                continue
            if p.netloc != base_domain:
                continue
            if p.path.lower().endswith(IGNORE_EXTENSIONS):
                continue

            clean = clean_url(p)
            if clean in seen:
                continue

            seen.add(clean)
            queue.append((clean, current_url))

        human_delay()

    summary = {
        "start_url": start_url,
        "pages_scanned": pages_scanned,
        "pending": len(queue),
        "findings": results,
    }
    return summary


# ---------------------------------------------------------------------------
# NUEVO: Exportación de Resultados
# ---------------------------------------------------------------------------

def export_results(summary: dict, output_file: str):
    """Guarda los hallazgos en JSON o CSV dependiendo de la extensión."""
    findings = summary["findings"]
    
    if not findings:
        print("\n[!] No hay hallazgos para exportar.")
        return

    if output_file.endswith(".json"):
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)
        print(f"\n[+] Resultados exportados a JSON: {output_file}")
        
    elif output_file.endswith(".csv"):
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "php_version", "status"])
            writer.writeheader()
            writer.writerows(findings)
        print(f"\n[+] Resultados exportados a CSV: {output_file}")
        
    else:
        print("\n[-] Error: La extensión del archivo debe ser .json o .csv")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CrawlerX: Spider pasivo para detectar versión de PHP."
    )
    parser.add_argument("url", help="URL inicial, p.ej. https://ejemplo.com/")
    parser.add_argument("--max-pages", type=int, default=15, help="Máximo de páginas (default 15)")
    parser.add_argument(
        "--insecure", action="store_true",
        help="Desactiva la verificación TLS (solo laboratorios)",
    )
    # NUEVO: Argumento para output
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Archivo de salida para los resultados (ej: reporte.json o reporte.csv)"
    )
    # NUEVO: Argumento para ignorar robots.txt
    parser.add_argument(
        "--ignore-robots", action="store_true",
        help="Ignora las reglas de robots.txt (SOLO PARA LABORATORIOS/AUDITORÍAS AUTORIZADAS)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Log detallado")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    summary = spider_website(
        args.url,
        max_pages=args.max_pages,
        verify_tls=not args.insecure,
        ignore_robots=args.ignore_robots # NUEVO
    )

    print("\n" + "=" * 60)
    print("Resumen del escaneo")
    print("=" * 60)
    print(f"URL inicial       : {summary['start_url']}")
    print(f"Páginas visitadas : {summary['pages_scanned']}")
    print(f"Pendientes        : {summary['pending']}")
    print(f"Hallazgos PHP     : {len(summary['findings'])}")
    for f in summary["findings"]:
        print(f"  - {f['url']}\n      PHP {f['php_version']} -> {f['status']}")
    print("=" * 60)

    # NUEVO: Llamada a la exportación si se solicitó
    if args.output:
        export_results(summary, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
