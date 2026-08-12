"""
ANGEL v2.0 — Улучшенный OSINT-сканер
Используйте только в законных целях и с согласия субъекта данных.

Улучшения:
  • Исправлена уязвимость command injection в ping
  • Блокировка приватных IP-диапазонов
  • Fallback-парсер (html.parser при отсутствии lxml)
  • Поддержка прокси / Tor
  • Retry с exponential backoff
  • Нормальный JSON-экспорт (структурированные данные)
  • Whois-информация для IP
  • Расширенный поиск username (20+ платформ)
  • История сканирований в SQLite
  • Вкладки: Телефон / Username / IP
  • Копирование результатов в буфер обмена
  • Rate limiting и обнаружение капчи
  • Конфигурация через INI-файл
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable
from urllib.parse import quote

import phonenumbers
import requests
from bs4 import BeautifulSoup
from phonenumbers import carrier, geocoder, timezone

# ---------------------------------------------------------------------------
# КОНФИГУРАЦИЯ
# ---------------------------------------------------------------------------

CURRENT_VERSION = "2.0.0"

C_BG = "#0d0d0d"
C_BG_PANEL = "#121212"
C_BG_INPUT = "#1a1a1a"
C_BORDER = "#2a2a2a"
C_TEXT = "#e0e0e0"
C_TEXT_DIM = "#888888"
C_TEXT_MUTED = "#555555"
C_ACCENT = "#bbbbbb"
C_HIGHLIGHT = "#ffffff"
C_SUCCESS = "#4caf50"
C_WARN = "#ff9800"
C_ERROR = "#f44336"

CONFIG_PATH = "angel_config.ini"
DB_PATH = "angel_history.db"

# ---------------------------------------------------------------------------
# УТИЛИТЫ
# ---------------------------------------------------------------------------

def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)


def ensure_icon_files() -> tuple[str, str]:
    png_path = resource_path(os.path.join("assets", "icon.png"))
    ico_path = resource_path(os.path.join("assets", "icon.ico"))
    if not os.path.isfile(png_path):
        raise FileNotFoundError(f"Иконка не найдена: {png_path}")
    if not os.path.isfile(ico_path):
        try:
            from PIL import Image
            img = Image.open(png_path).convert("RGBA")
            img.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (256, 256)])
        except ImportError:
            pass
    return png_path, ico_path


def load_header_icon(size: int = 72):
    from PIL import Image, ImageTk
    png_path, _ = ensure_icon_files()
    img = Image.open(png_path).convert("RGBA")
    img = img.resize((size, size), Image.Resampling.LANCZOS)
    return ImageTk.PhotoImage(img)


def get_soup(text: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(text, "lxml")
    except Exception:
        return BeautifulSoup(text, "html.parser")


def normalize_username(raw: str) -> str:
    value = raw.strip()
    value = re.sub(r"^https?://t\.me/", "", value, flags=re.IGNORECASE)
    return value.lstrip("@")


def detect_target_type(raw: str) -> str:
    value = raw.strip()
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value):
        return "ip"
    if value.startswith("@") or re.match(r"^[a-zA-Z][a-zA-Z0-9_]{4,31}$", normalize_username(value)):
        return "username"
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 7:
        return "phone"
    return "unknown"


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# БАЗА ДАННЫХ ИСТОРИИ
# ---------------------------------------------------------------------------

class HistoryDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    results_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def save(self, target: str, target_type: str, results: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO scans (target, target_type, timestamp, results_json) VALUES (?, ?, ?, ?)",
                (target, target_type, datetime.now().isoformat(), json.dumps(results, ensure_ascii=False))
            )
            conn.commit()

    def get_recent(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# КОНФИГУРАЦИЯ ПРИЛОЖЕНИЯ
# ---------------------------------------------------------------------------

class AppConfig:
    def __init__(self, path: str = CONFIG_PATH):
        self.path = path
        self.proxy: str = ""
        self.timeout: int = 15
        self.retries: int = 2
        self.delay_between_requests: float = 1.0
        self._load()

    def _load(self):
        import configparser
        if not os.path.exists(self.path):
            self._save_default()
            return
        cfg = configparser.ConfigParser()
        cfg.read(self.path, encoding="utf-8")
        net = cfg.get("network", "proxy", fallback="")
        self.proxy = net if net else ""
        self.timeout = cfg.getint("network", "timeout", fallback=15)
        self.retries = cfg.getint("network", "retries", fallback=2)
        self.delay_between_requests = cfg.getfloat("network", "delay", fallback=1.0)

    def _save_default(self):
        import configparser
        cfg = configparser.ConfigParser()
        cfg["network"] = {
            "proxy": "",
            "timeout": "15",
            "retries": "2",
            "delay": "1.0",
        }
        with open(self.path, "w", encoding="utf-8") as f:
            cfg.write(f)

    def get_proxies(self) -> dict | None:
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}


# ---------------------------------------------------------------------------
# СЕССИЯ С RETRY И RATE LIMITING
# ---------------------------------------------------------------------------

class SafeSession:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ]

    def __init__(self, config: AppConfig):
        self.cfg = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept": "application/json, text/plain, */*",
        })
        proxies = config.get_proxies()
        if proxies:
            self.session.proxies.update(proxies)

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.cfg.timeout)
        last_exc = None
        for attempt in range(self.cfg.retries + 1):
            try:
                time.sleep(self.cfg.delay_between_requests * attempt)
                resp = self.session.get(url, **kwargs)
                if self._is_captcha(resp):
                    raise requests.RequestException("Обнаружена капча")
                return resp
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.cfg.retries:
                    time.sleep(2 ** attempt)
        raise last_exc or requests.RequestException("Max retries exceeded")

    def head(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.cfg.timeout)
        return self.session.head(url, **kwargs)

    @staticmethod
    def _is_captcha(resp: requests.Response) -> bool:
        text = resp.text.lower()
        indicators = ["captcha", "капча", "подтвердите, что вы не робот", "recaptcha", "g-recaptcha"]
        return any(ind in text for ind in indicators) and resp.status_code in (200, 403, 429)


# ---------------------------------------------------------------------------
# СКАНЕР
# ---------------------------------------------------------------------------

@dataclass
class ScanContext:
    target: str
    is_ip: bool = False
    is_username: bool = False
    is_phone: bool = False
    username: str = ""
    parsed_phone: Any = None
    e164: str = ""
    national: str = ""
    country_code: str = ""
    valid: bool = False


class AngelScanner:
    SOCIAL_PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Instagram": "https://instagram.com/{}",
        "Twitter/X": "https://x.com/{}",
        "VK": "https://vk.com/{}",
        "TikTok": "https://tiktok.com/@{}",
        "Telegram": "https://t.me/{}",
        "Reddit": "https://reddit.com/user/{}",
        "YouTube": "https://youtube.com/@{}",
        "Pinterest": "https://pinterest.com/{}",
        "LinkedIn": "https://linkedin.com/in/{}",
        "Facebook": "https://facebook.com/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "Twitch": "https://twitch.tv/{}",
        "Snapchat": "https://snapchat.com/add/{}",
        "Spotify": "https://open.spotify.com/user/{}",
        "GitLab": "https://gitlab.com/{}",
        "Medium": "https://medium.com/@{}",
        "DeviantArt": "https://{}.deviantart.com",
        "Flickr": "https://flickr.com/people/{}",
        "Keybase": "https://keybase.io/{}",
    }

    def __init__(self, target: str, config: AppConfig | None = None):
        self.cfg = config or AppConfig()
        self.http = SafeSession(self.cfg)
        self.target = target.strip()
        self.ctx = self._build_context()
        self.results: dict = {}

    def _build_context(self) -> ScanContext:
        ctx = ScanContext(target=self.target)
        ttype = detect_target_type(self.target)

        if ttype == "ip":
            ctx.is_ip = True
        elif ttype == "username":
            ctx.is_username = True
            ctx.username = normalize_username(self.target)
        elif ttype == "phone":
            ctx.is_phone = True
            try:
                parsed = phonenumbers.parse(self.target, None)
                ctx.parsed_phone = parsed
                ctx.e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                ctx.national = str(parsed.national_number)
                ctx.country_code = str(parsed.country_code)
                ctx.valid = phonenumbers.is_valid_number(parsed)
            except phonenumbers.NumberParseException:
                ctx.e164 = self.target
                ctx.national = re.sub(r"\D", "", self.target)
        return ctx

    # ------------------------------------------------------------------
    # IP
    # ------------------------------------------------------------------
    def scan_ip(self) -> None:
        if not self.ctx.is_ip:
            return
        ip = self.target

        if is_private_ip(ip):
            self.results["IP-АДРЕС"] = {"Статус": "Приватный / Loopback IP — сканирование ограничено"}
            self._ping_ip(ip)
            return

        ip_data: dict = {}

        # ip-api
        try:
            r = self.http.get(f"http://ip-api.com/json/{ip}?lang=ru")
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    ip_data["ip-api.com"] = {
                        "IP": data.get("query"),
                        "Страна": data.get("country"),
                        "Регион": data.get("regionName"),
                        "Город": data.get("city"),
                        "Провайдер": data.get("isp"),
                        "Организация": data.get("org"),
                        "AS": data.get("as"),
                        "Координаты": f"{data.get('lat')}, {data.get('lon')}",
                        "Часовой пояс": data.get("timezone"),
                        "ZIP": data.get("zip"),
                    }
        except Exception as exc:
            ip_data["ip-api.com"] = f"Ошибка: {exc}"

        # ipinfo
        try:
            r = self.http.get(f"https://ipinfo.io/{ip}/json")
            if r.status_code == 200:
                data = r.json()
                ip_data["ipinfo.io"] = {
                    "Город": data.get("city"),
                    "Регион": data.get("region"),
                    "Страна": data.get("country"),
                    "Провайдер": data.get("org"),
                    "Почтовый индекс": data.get("postal"),
                    "Координаты": data.get("loc"),
                    "Часовой пояс": data.get("timezone"),
                }
        except Exception as exc:
            ip_data["ipinfo.io"] = f"Ошибка: {exc}"

        # Shodan InternetDB
        try:
            r = self.http.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code == 200:
                data = r.json()
                if data:
                    ip_data["Shodan InternetDB"] = {
                        "Порты": data.get("ports", [])[:15],
                        "Хосты": data.get("hostnames", [])[:5],
                        "Теги": data.get("tags", [])[:5],
                        "CPE": data.get("cpes", [])[:5],
                        "Уязвимости": data.get("vulns", [])[:5],
                    }
        except Exception as exc:
            ip_data["Shodan"] = f"Ошибка: {exc}"

        # Whois
        try:
            ip_data["Whois"] = self._whois_ip(ip)
        except Exception as exc:
            ip_data["Whois"] = f"Ошибка: {exc}"

        self.results["IP-АДРЕС"] = ip_data
        self._ping_ip(ip)

    def _whois_ip(self, ip: str) -> dict:
        result: dict = {}
        try:
            cmd = ["whois", ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            text = proc.stdout
            fields = {
                "netname": r"NetName:\s*(.+)",
                "orgname": r"OrgName:\s*(.+)",
                "country": r"Country:\s*(.+)",
                "origin": r"OriginAS:\s*(.+)",
                "inetnum": r"inetnum:\s*(.+)",
            }
            for key, pattern in fields.items():
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    result[key.capitalize()] = m.group(1).strip()
            if not result:
                result["Примечание"] = "Whois-данные не распознаны (возможно, rate limit)"
        except FileNotFoundError:
            result["Примечание"] = "Утилита whois не установлена в системе"
        except Exception as exc:
            result["Ошибка"] = str(exc)
        return result

    def _ping_ip(self, ip: str) -> None:
        try:
            param_count = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(
                ["ping", param_count, "1", ip],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            ping_data: dict = {}
            if result.returncode == 0:
                ping_match = re.search(r"time[=<](\d+\.?\d*)", result.stdout)
                ping_data["Статус"] = "Доступен"
                ping_data["Время"] = f"{ping_match.group(1)} мс" if ping_match else "—"
            else:
                ping_data["Статус"] = "Недоступен (ICMP заблокирован)"
            self.results["Пинг (ICMP)"] = ping_data
        except Exception as exc:
            self.results["Пинг (ICMP)"] = {"Ошибка": str(exc)}

    # ------------------------------------------------------------------
    # USERNAME / TELEGRAM
    # ------------------------------------------------------------------
    def search_telegram_profile(self, username: str | None = None) -> dict:
        username = normalize_username(username or self.ctx.username or self.target)
        data: dict = {"Username": f"@{username}", "Ссылка": f"https://t.me/{username}"}
        try:
            r = self.http.get(f"https://t.me/{username}")
            if r.status_code != 200 or "tgme_page_title" not in r.text:
                return {"Статус": "Профиль не найден или скрыт"}
            soup = get_soup(r.text)
            title = soup.find("div", class_="tgme_page_title")
            desc = soup.find("div", class_="tgme_page_description")
            extra = soup.find("div", class_="tgme_page_extra")
            photo = soup.find("img", class_="tgme_page_photo_image")
            counters = soup.find("div", class_="tgme_page_counter")

            if title:
                data["Имя"] = title.get_text(strip=True)
            if desc:
                data["Описание"] = desc.get_text(strip=True)
            if extra:
                data["Дополнительно"] = extra.get_text(strip=True)
            if photo and photo.get("src"):
                data["Фото"] = photo["src"]
            if counters:
                data["Статистика"] = counters.get_text(strip=True)
        except Exception as exc:
            return {"Статус": f"Ошибка: {exc}"}
        return data

    def search_username_osint(self) -> None:
        profile = self.search_telegram_profile()
        self.results["TELEGRAM"] = profile

        username = self.ctx.username
        mentions: list[dict] = []

        # Yandex mentions
        try:
            r = self.http.get(f"https://yandex.ru/search/?text={quote('@' + username)}&lr=213")
            soup = get_soup(r.text)
            for item in soup.find_all("li", class_="serp-item")[:5]:
                title_el = item.find("h2")
                desc_el = item.find("div", class_="text-container")
                if title_el and desc_el:
                    mentions.append({
                        "Заголовок": title_el.get_text(strip=True)[:120],
                        "Описание": desc_el.get_text(strip=True)[:200],
                    })
            self.results["ЯНДЕКС (упоминания)"] = mentions or "Упоминаний не найдено"
        except Exception as exc:
            self.results["ЯНДЕКС (упоминания)"] = f"Недоступен: {exc}"

        # Possible phones from Yandex
        found_phones: list[str] = []
        for query in (f"{username} телефон", f"{username} phone +7"):
            try:
                r = self.http.get(f"https://yandex.ru/search/?text={quote(query)}&lr=213")
                if r.status_code == 200:
                    phones = re.findall(r"\+?\d[\d\s\-()]{8,}\d", get_soup(r.text).get_text())
                    for phone in phones:
                        clean = re.sub(r"\s+", " ", phone.strip())
                        if len(re.sub(r"\D", "", clean)) >= 10:
                            found_phones.append(clean)
            except Exception:
                continue
        if found_phones:
            self.results["ВОЗМОЖНЫЕ НОМЕРА"] = list(dict.fromkeys(found_phones))[:5]

        # Social links
        socials = {name: url.format(username) for name, url in self.SOCIAL_PLATFORMS.items()}
        self.results["СОЦСЕТИ (ссылки для проверки)"] = socials

    # ------------------------------------------------------------------
    # PHONE
    # ------------------------------------------------------------------
    def offline_info(self) -> None:
        if not self.ctx.is_phone:
            return
        if not self.ctx.valid or self.ctx.parsed_phone is None:
            self.results["ОШИБКА"] = "Неверный формат номера телефона"
            return

        parsed = self.ctx.parsed_phone
        country = geocoder.description_for_number(parsed, "ru")
        region = geocoder.description_for_valid_number(parsed, "ru")
        oper = carrier.name_for_number(parsed, "ru")
        tz = timezone.time_zones_for_number(parsed)
        num_type = phonenumbers.number_type(parsed)
        type_map = {
            0: "Стационарный",
            1: "Мобильный",
            2: "Стационарный или мобильный",
            3: "Бесплатный (800)",
            4: "Премиум-номер",
            5: "Общий доступ",
        }

        self.results["ОФФЛАЙН-ДАННЫЕ"] = {
            "Международный": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Национальный": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "E.164": self.ctx.e164,
            "Страна": country or "—",
            "Регион": region or "—",
            "Оператор": oper or "—",
            "Тип линии": type_map.get(num_type, "Неизвестный"),
            "Часовые пояса": ", ".join(tz) if tz else "—",
            "Валидность": "Действительный" if self.ctx.valid else "Недействительный",
        }

    def search_yandex(self) -> None:
        if not self.ctx.is_phone:
            return
        try:
            r = self.http.get(f"https://yandex.ru/search/?text={quote(self.ctx.e164)}&lr=213")
            soup = get_soup(r.text)
            items = soup.find_all("li", class_="serp-item")[:7]
            res = []
            for item in items:
                h2 = item.find("h2")
                desc = item.find("div", class_="text-container")
                if h2 and desc:
                    res.append({
                        "Заголовок": h2.get_text(strip=True)[:120],
                        "Описание": desc.get_text(strip=True)[:200],
                    })
            self.results["ЯНДЕКС"] = res or "Упоминаний не найдено"
        except Exception as exc:
            self.results["ЯНДЕКС"] = f"Недоступен: {exc}"

    def search_vk(self) -> None:
        if not self.ctx.is_phone:
            return
        self.results["ВКОНТАКТЕ"] = {
            "Статус": "Публичный поиск по телефону недоступен без авторизации",
            "Рекомендация": "Используйте авторизованный API VK или поиск через Яндекс",
        }

    def search_telegram(self) -> None:
        if not self.ctx.is_phone:
            return
        self.results["TELEGRAM"] = {
            "Статус": "Поиск по номеру через t.me невозможен",
            "Примечание": "Telegram не открывает профиль по номеру через публичную ссылку. "
                          "Используйте официальный клиент или API.",
            "Ссылка на чат": f"https://t.me/{self.ctx.e164}",
        }

    def search_whatsapp(self) -> None:
        if not self.ctx.is_phone:
            return
        try:
            clean = self.ctx.e164.replace("+", "").replace(" ", "")
            r = self.http.head(f"https://wa.me/{clean}", allow_redirects=True)
            self.results["WHATSAPP"] = {
                "Ссылка": f"https://wa.me/{clean}",
                "Статус": "Ссылка активна" if r.status_code == 200 else f"HTTP {r.status_code}",
            }
        except Exception as exc:
            self.results["WHATSAPP"] = f"Недоступен: {exc}"

    def search_avito(self) -> None:
        if not self.ctx.is_phone:
            return
        try:
            r = self.http.get(f"https://www.avito.ru/all?q={quote(self.ctx.e164)}")
            soup = get_soup(r.text)
            items = soup.find_all("div", {"data-marker": "item"})[:5]
            res = []
            for item in items:
                title = item.find("h3")
                price = item.find("span", {"data-marker": "item-price"})
                link = item.find("a", {"data-marker": "item-title"})
                if title:
                    res.append({
                        "Товар": title.get_text(strip=True)[:80],
                        "Цена": price.get_text(strip=True) if price else "—",
                        "Ссылка": "https://www.avito.ru" + link.get("href", "") if link else "—",
                    })
            self.results["АВИТО"] = res or "Объявлений не найдено"
        except Exception as exc:
            self.results["АВИТО"] = f"Недоступен: {exc}"

    def search_leaks(self) -> None:
        if not self.ctx.is_phone:
            return
        try:
            r = self.http.get(f"https://psbdmp.cc/api/v3/search?q={quote(self.ctx.e164)}")
            if r.status_code != 200:
                self.results["УТЕЧКИ (psbdmp)"] = f"Сервис вернул HTTP {r.status_code}"
                return
            data = r.json()
            emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text)
            result_data: dict = {"Ответ API": data}
            if emails:
                result_data["Найденные email"] = list(dict.fromkeys(emails))[:5]
            self.results["УТЕЧКИ (psbdmp)"] = result_data
        except Exception as exc:
            self.results["УТЕЧКИ (psbdmp)"] = f"Недоступен: {exc}"

    # ------------------------------------------------------------------
    # ORCHESTRATION
    # ------------------------------------------------------------------
    def run_all(self, progress_callback: Callable[[int, str], None] | None = None) -> dict:
        if self.ctx.is_ip:
            steps = [("IP-адрес", self.scan_ip)]
        elif self.ctx.is_username:
            steps = [("Telegram / Username", self.search_username_osint)]
        else:
            steps = [
                ("Оффлайн-данные", self.offline_info),
                ("Яндекс", self.search_yandex),
                ("ВКонтакте", self.search_vk),
                ("Telegram", self.search_telegram),
                ("WhatsApp", self.search_whatsapp),
                ("Авито", self.search_avito),
                ("Утечки", self.search_leaks),
            ]

        for i, (name, func) in enumerate(steps):
            if progress_callback:
                progress_callback(int((i) / len(steps) * 100), name)
            try:
                func()
            except Exception as exc:
                self.results[f"ОШИБКА ({name})"] = str(exc)
            if progress_callback:
                progress_callback(int((i + 1) / len(steps) * 100), name)

        if progress_callback:
            progress_callback(100, "Готово")
        return self.results


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class AngelApp:
    def __init__(self):
        self.cfg = AppConfig()
        self.db = HistoryDB()
        self.win = tk.Tk()
        self.win.title("ANGEL v2.0")
        self.win.geometry("1000x760")
        self.win.configure(bg=C_BG)
        self.win.minsize(800, 600)

        try:
            _, self.icon_ico_path = ensure_icon_files()
            self.icon_img = load_header_icon(64)
            self.win.iconbitmap(self.icon_ico_path)
            self.win.iconphoto(True, self.icon_img)
        except Exception:
            self.icon_img = None

        self.status_var = tk.StringVar(value="Готов")
        self.current_results: dict = {}
        self.scanning = False
        self.found_phones: list[str] = []

        self._configure_styles()
        self._build_ui()
        self._center()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Angel.Horizontal.TProgressbar",
                        troughcolor=C_BG_INPUT, background=C_TEXT,
                        bordercolor=C_BORDER, lightcolor=C_TEXT, darkcolor=C_TEXT)
        style.configure("Angel.TNotebook", background=C_BG, borderwidth=0)
        style.configure("Angel.TNotebook.Tab", font=("Consolas", 10),
                        background=C_BG_INPUT, foreground=C_TEXT_DIM,
                        padding=(12, 6))
        style.map("Angel.TNotebook.Tab",
                  background=[("selected", C_BG_PANEL)],
                  foreground=[("selected", C_TEXT)])

    def _center(self):
        self.win.update_idletasks()
        w, h = 1000, 760
        x = (self.win.winfo_screenwidth() - w) // 2
        y = (self.win.winfo_screenheight() - h) // 2
        self.win.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        # Header
        header = tk.Frame(self.win, bg=C_BG)
        header.pack(fill="x", pady=(14, 6))
        if self.icon_img:
            tk.Label(header, image=self.icon_img, bg=C_BG).pack()
        tk.Label(header, text="ANGEL", font=("Consolas", 28, "bold"), fg=C_TEXT, bg=C_BG).pack()
        tk.Label(header, text=f"v{CURRENT_VERSION}  •  OSINT-сканер", font=("Consolas", 9),
                 fg=C_TEXT_DIM, bg=C_BG).pack(pady=(2, 0))

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.win, style="Angel.TNotebook")
        self.notebook.pack(fill="x", padx=20, pady=(10, 0))

        self.tab_phone = self._build_tab("Телефон", "+79991234567")
        self.tab_user = self._build_tab("Username", "@durov")
        self.tab_ip = self._build_tab("IP-адрес", "8.8.8.8")

        self.notebook.add(self.tab_phone["frame"], text="  📱 Телефон  ")
        self.notebook.add(self.tab_user["frame"], text="  💬 Username  ")
        self.notebook.add(self.tab_ip["frame"], text="  🌐 IP-адрес  ")

        # Buttons
        btn_frame = tk.Frame(self.win, bg=C_BG)
        btn_frame.pack(pady=8)

        tk.Button(btn_frame, text="СКАНИРОВАТЬ", command=self._start_scan,
                  font=("Consolas", 11, "bold"), bg=C_BG_INPUT, fg=C_TEXT,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=18, pady=6, cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="СОХРАНИТЬ TXT", command=self._save_txt,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_ACCENT,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=12, pady=6, cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="СОХРАНИТЬ JSON", command=self._save_json,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_SUCCESS,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=12, pady=6, cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="КОПИРОВАТЬ", command=self._copy,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_WARN,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=12, pady=6, cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="ИСТОРИЯ", command=self._show_history,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_TEXT_DIM,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=12, pady=6, cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="ОЧИСТИТЬ", command=self._clear,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_ERROR,
                  activebackground=C_BORDER, activeforeground=C_TEXT,
                  relief="solid", bd=1, padx=12, pady=6, cursor="hand2").pack(side="left", padx=4)

        # Progress
        self.progress = ttk.Progressbar(self.win, mode="determinate", length=800,
                                        style="Angel.Horizontal.TProgressbar")
        self.progress.pack(pady=(8, 2))

        self.status_label = tk.Label(self.win, textvariable=self.status_var,
                                     font=("Consolas", 9), fg=C_TEXT_DIM, bg=C_BG)
        self.status_label.pack()

        # Phone buttons frame
        self.phone_buttons = tk.Frame(self.win, bg=C_BG)

        # Output
        self.output = scrolledtext.ScrolledText(
            self.win, font=("Consolas", 10), bg=C_BG_PANEL, fg=C_ACCENT,
            insertbackground=C_TEXT, relief="solid", bd=1,
            highlightthickness=1, highlightbackground=C_BORDER,
            wrap=tk.WORD,
        )
        self.output.pack(fill="both", expand=True, padx=20, pady=(8, 16))

        # Tags
        self.output.tag_config("header", foreground=C_TEXT, font=("Consolas", 13, "bold"))
        self.output.tag_config("section", foreground=C_HIGHLIGHT, font=("Consolas", 11, "bold"))
        self.output.tag_config("key", foreground=C_TEXT_DIM)
        self.output.tag_config("value", foreground=C_ACCENT)
        self.output.tag_config("warn", foreground=C_WARN)
        self.output.tag_config("error", foreground=C_ERROR)
        self.output.tag_config("success", foreground=C_SUCCESS)

        # Context menu
        self.output.bind("<Button-3>", self._context_menu)

        self._log_welcome()

    def _build_tab(self, label: str, placeholder: str) -> dict:
        frame = tk.Frame(self.win, bg=C_BG)
        inner = tk.Frame(frame, bg=C_BG)
        inner.pack(fill="x", padx=10, pady=10)

        tk.Label(inner, text="Цель:", font=("Consolas", 12), fg=C_TEXT, bg=C_BG).pack(side="left", padx=(0, 8))
        var = tk.StringVar()
        entry = tk.Entry(inner, textvariable=var, font=("Consolas", 14),
                         bg=C_BG_INPUT, fg=C_TEXT, insertbackground=C_TEXT,
                         relief="solid", bd=1, highlightthickness=1,
                         highlightbackground=C_BORDER, highlightcolor=C_TEXT)
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        entry.bind("<Return>", lambda _e: self._start_scan())
        entry.focus_set()

        tk.Label(frame, text=f"Пример: {placeholder}", font=("Consolas", 8),
                 fg=C_TEXT_MUTED, bg=C_BG).pack(anchor="w", padx=10, pady=(0, 4))
        return {"frame": frame, "var": var, "entry": entry}

    def _get_active_target(self) -> str:
        idx = self.notebook.index("current")
        if idx == 0:
            return self.tab_phone["var"].get().strip()
        elif idx == 1:
            return self.tab_user["var"].get().strip()
        else:
            return self.tab_ip["var"].get().strip()

    def _set_active_target(self, value: str):
        idx = self.notebook.index("current")
        if idx == 0:
            self.tab_phone["var"].set(value)
        elif idx == 1:
            self.tab_user["var"].set(value)
        else:
            self.tab_ip["var"].set(value)

    def _context_menu(self, event):
        menu = tk.Menu(self.win, tearoff=0, bg=C_BG_INPUT, fg=C_TEXT,
                       activebackground=C_BORDER, activeforeground=C_TEXT)
        menu.add_command(label="Копировать", command=lambda: self.output.event_generate("<<Copy>>"))
        menu.add_command(label="Выделить всё", command=lambda: self.output.tag_add("sel", "1.0", "end"))
        menu.tk_popup(event.x_root, event.y_root)

    def _log_welcome(self):
        self._log("=" * 60 + "\n", "header")
        self._log("  ANGEL v2.0 — OSINT-поиск\n", "header")
        self._log("=" * 60 + "\n\n", "header")
        self._log("Введите номер телефона, Telegram username или IP-адрес.\n\n", "value")
        self._log("Поддерживаемые форматы:\n", "key")
        self._log("  • +79991234567, 89991234567\n", "value")
        self._log("  • @username или username\n", "value")
        self._log("  • 192.168.1.1, 8.8.8.8\n\n", "value")
        self._log("Используйте только в законных целях.\n", "warn")
        self._log("\nНовое в v2.0:\n", "success")
        self._log("  • Исправлена уязвимость command injection\n", "value")
        self._log("  • Блокировка приватных IP\n", "value")
        self._log("  • Поддержка прокси и retry\n", "value")
        self._log("  • История сканирований в SQLite\n", "value")
        self._log("  • Нормальный JSON-экспорт\n", "value")
        self._log("  • Whois для IP\n", "value")

    def _log(self, text: str, tag: str | None = None):
        self.output.insert("end", text, tag)
        self.output.see("end")
        self.win.update_idletasks()

    def _clear(self):
        self.output.delete("1.0", "end")
        self.progress["value"] = 0
        self.status_var.set("Готов")
        self.found_phones = []
        for widget in self.phone_buttons.winfo_children():
            widget.destroy()
        self.phone_buttons.pack_forget()
        self.current_results = {}
        self._log_welcome()

    def _start_scan(self):
        target = self._get_active_target()
        if not target:
            messagebox.showerror("Ошибка", "Введите номер, username или IP")
            return
        if self.scanning:
            return

        target_type = detect_target_type(target)
        if target_type == "unknown":
            messagebox.showerror("Ошибка", "Не удалось определить тип цели.\nВведите номер (+7...), @username или IP.")
            return

        self.scanning = True
        self.output.delete("1.0", "end")
        self.progress["value"] = 0
        self.status_var.set("Инициализация...")
        self.found_phones = []
        for widget in self.phone_buttons.winfo_children():
            widget.destroy()
        self.phone_buttons.pack_forget()

        def progress_cb(val: int, name: str):
            self.win.after(0, lambda: self.progress.configure(value=val))
            self.win.after(0, lambda: self.status_var.set(f"Сканирование: {name}..."))

        def worker():
            scanner = AngelScanner(target, self.cfg)
            try:
                data = scanner.run_all(progress_callback=progress_cb)
                self.win.after(0, lambda: self._display(data, scanner))
                self.win.after(0, lambda: self.status_var.set("Завершено"))
                self.win.after(0, lambda: self.progress.configure(value=100))
                try:
                    ttype = "ip" if scanner.ctx.is_ip else ("username" if scanner.ctx.is_username else "phone")
                    self.db.save(target, ttype, data)
                except Exception:
                    pass
            except Exception as exc:
                self.win.after(0, lambda: self._log(f"\nОШИБКА: {exc}\n", "error"))
                self.win.after(0, lambda: self.status_var.set("Ошибка"))
            finally:
                self.scanning = False

        threading.Thread(target=worker, daemon=True).start()

    def _display(self, data: dict, scanner: AngelScanner):
        self.current_results = data
        if scanner.ctx.is_ip:
            mode = f"IP-АДРЕС: {self.target}"
        elif scanner.ctx.is_username:
            mode = f"TELEGRAM @{scanner.ctx.username}"
        else:
            mode = f"НОМЕР: {scanner.ctx.e164 or self.target}"

        self._log("=" * 60 + "\n", "header")
        self._log(f"  РЕЗУЛЬТАТЫ — {mode}\n", "header")
        self._log("=" * 60 + "\n\n", "header")

        self.found_phones = []
        for section, content in data.items():
            self._log(f"\n▌ {section}\n", "section")
            self._log("─" * 50 + "\n", "section")
            self._render_content(content, indent=1)
            if section == "ВОЗМОЖНЫЕ НОМЕРА" and isinstance(content, list):
                self.found_phones.extend(content)

        if self.found_phones:
            self._show_phone_buttons()

        self._log("\n" + "=" * 60 + "\n", "header")
        self._log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "value")
        self._log("  ANGEL v2.0\n", "value")
        self._log("=" * 60 + "\n", "header")

    def _render_content(self, content, indent: int = 0):
        pad = "  " * indent
        if isinstance(content, dict):
            for key, value in content.items():
                if isinstance(value, (dict, list)):
                    self._log(f"{pad}{key}:\n", "key")
                    self._render_content(value, indent + 1)
                else:
                    self._log(f"{pad}{key}: {value}\n", "value")
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    for key, value in item.items():
                        self._log(f"{pad}• {key}: {value}\n", "value")
                    self._log("\n", "value")
                else:
                    self._log(f"{pad}• {item}\n", "value")
        else:
            self._log(f"{pad}{content}\n", "value")

    def _show_phone_buttons(self):
        self.phone_buttons.pack(pady=(0, 4))
        tk.Label(self.phone_buttons, text="Проверить найденный номер:",
                 font=("Consolas", 9), fg=C_TEXT_DIM, bg=C_BG).pack()
        for phone in self.found_phones[:3]:
            tk.Button(self.phone_buttons, text=f"→ {phone}",
                      command=lambda p=phone: self._scan_phone(p),
                      font=("Consolas", 10), bg=C_BG_INPUT, fg=C_TEXT,
                      activebackground=C_BORDER, activeforeground=C_TEXT,
                      relief="solid", bd=1, padx=12, pady=4, cursor="hand2").pack(pady=2)

    def _scan_phone(self, phone: str):
        self.notebook.select(0)
        self.tab_phone["var"].set(phone)
        self._start_scan()

    def _save_txt(self):
        text = self.output.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Пусто", "Нет данных для сохранения")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt")],
            initialfile=f"angel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Готово", f"Сохранено:\n{path}")

    def _save_json(self):
        if not self.current_results:
            messagebox.showwarning("Пусто", "Нет данных для сохранения")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"angel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.current_results, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Готово", f"Сохранено:\n{path}")

    def _copy(self):
        text = self.output.get("1.0", "end").strip()
        if not text:
            return
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self.status_var.set("Скопировано в буфер обмена")
        self.win.after(2000, lambda: self.status_var.set("Готов"))

    def _show_history(self):
        win = tk.Toplevel(self.win)
        win.title("История сканирований")
        win.geometry("800x500")
        win.configure(bg=C_BG)
        win.transient(self.win)

        tree = ttk.Treeview(win, columns=("id", "target", "type", "time"), show="headings")
        tree.heading("id", text="ID")
        tree.heading("target", text="Цель")
        tree.heading("type", text="Тип")
        tree.heading("time", text="Время")
        tree.column("id", width=40)
        tree.column("target", width=250)
        tree.column("type", width=100)
        tree.column("time", width=180)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        def load():
            for i in tree.get_children():
                tree.delete(i)
            for row in self.db.get_recent(50):
                tree.insert("", "end", values=(row["id"], row["target"], row["target_type"], row["timestamp"]))

        def on_double_click(event):
            item = tree.selection()[0]
            values = tree.item(item, "values")
            if not values:
                return
            target = values[1]
            ttype = values[2]
            if ttype == "phone":
                self.notebook.select(0)
                self.tab_phone["var"].set(target)
            elif ttype == "username":
                self.notebook.select(1)
                self.tab_user["var"].set(target)
            else:
                self.notebook.select(2)
                self.tab_ip["var"].set(target)
            win.destroy()
            self._start_scan()

        tree.bind("<Double-1>", on_double_click)

        tk.Button(win, text="Обновить", command=load,
                  font=("Consolas", 10), bg=C_BG_INPUT, fg=C_TEXT).pack(pady=(0, 10))
        load()

    def run(self):
        self.win.mainloop()


if __name__ == "__main__":
    AngelApp().run()
