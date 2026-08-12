"""
ANGEL — OSINT-поиск по номеру телефона или Telegram username.
Используйте только в законных целях и с согласия субъекта данных.
"""

import os
import re
import random
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.parse import quote

import phonenumbers
import requests
from bs4 import BeautifulSoup
from phonenumbers import carrier, geocoder, timezone


CURRENT_VERSION = "1.1.0"

# Чёрно-белая палитра
C_BG = "#000000"
C_BG_PANEL = "#0a0a0a"
C_BG_INPUT = "#111111"
C_BORDER = "#333333"
C_TEXT = "#ffffff"
C_TEXT_DIM = "#888888"
C_TEXT_MUTED = "#555555"
C_ACCENT = "#cccccc"
C_HIGHLIGHT = "#ffffff"


def create_icon() -> str:
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([10, 10, 54, 54], outline=(255, 255, 255, 220), width=2)
    draw.text((32, 32), "A", fill=(255, 255, 255, 255), anchor="mm")
    draw.arc([5, 20, 25, 44], start=240, end=60, fill=(255, 255, 255, 180), width=2)
    draw.arc([39, 20, 59, 44], start=120, end=300, fill=(255, 255, 255, 180), width=2)
    icon_path = os.path.join(os.environ.get("TEMP", "."), "angel_icon.png")
    img.save(icon_path)
    return icon_path


def normalize_username(raw: str) -> str:
    value = raw.strip()
    value = re.sub(r"^https?://t\.me/", "", value, flags=re.I)
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


class AngelScanner:
    def __init__(self, target: str):
        self.target = target.strip()
        self.is_ip = detect_target_type(self.target) == "ip"
        self.is_username = detect_target_type(self.target) == "username"
        self.username = normalize_username(self.target) if self.is_username else ""

        self.parsed = None
        self.e164 = ""
        self.national = ""
        self.country_code = ""
        self.valid = False

        if not self.is_ip and not self.is_username:
            try:
                self.parsed = phonenumbers.parse(self.target, None)
                self.e164 = phonenumbers.format_number(
                    self.parsed, phonenumbers.PhoneNumberFormat.E164
                )
                self.national = str(self.parsed.national_number)
                self.country_code = str(self.parsed.country_code)
                self.valid = phonenumbers.is_valid_number(self.parsed)
            except phonenumbers.NumberParseException:
                self.e164 = self.target
                self.national = self.target

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": random.choice(
                    [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                    ]
                ),
                "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.results: dict = {}

    def _phone_only(self) -> bool:
        return not self.is_ip and not self.is_username

    def scan_ip(self) -> None:
        if not self.is_ip:
            return

        ip_data: dict = {}

        try:
            r = self.session.get(
                f"http://ip-api.com/json/{self.target}?lang=ru", timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    ip_data["ip-api.com"] = {
                        "IP": data.get("query"),
                        "Страна": data.get("country"),
                        "Регион": data.get("regionName"),
                        "Город": data.get("city"),
                        "Провайдер": data.get("isp"),
                        "Координаты": f"{data.get('lat')}, {data.get('lon')}",
                        "Часовой пояс": data.get("timezone"),
                    }
        except requests.RequestException:
            pass

        try:
            r = self.session.get(f"https://ipinfo.io/{self.target}/json", timeout=10)
            if r.status_code == 200:
                data = r.json()
                ip_data["ipinfo.io"] = {
                    "Город": data.get("city"),
                    "Регион": data.get("region"),
                    "Страна": data.get("country"),
                    "Провайдер": data.get("org"),
                    "Координаты": data.get("loc"),
                    "Часовой пояс": data.get("timezone"),
                }
        except requests.RequestException:
            pass

        try:
            r = self.session.get(
                f"https://internetdb.shodan.io/{self.target}", timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                if data:
                    ip_data["Shodan"] = {
                        "Порты": data.get("ports", [])[:10],
                        "Хосты": data.get("hostnames", [])[:5],
                        "Теги": data.get("tags", [])[:5],
                    }
        except requests.RequestException:
            pass

        try:
            import platform
            import subprocess

            param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            result = subprocess.run(
                f"ping {param} {self.target}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                ping_match = re.search(r"time[=<](\d+\.?\d*)", result.stdout)
                ip_data["Пинг"] = {
                    "Статус": "Доступен",
                    "Время": f"{ping_match.group(1)} мс" if ping_match else "—",
                }
            else:
                ip_data["Пинг"] = {"Статус": "Недоступен"}
        except (OSError, subprocess.SubprocessError):
            pass

        self.results["IP-АДРЕС"] = ip_data

    def search_telegram_profile(self, username: str | None = None) -> dict:
        username = normalize_username(username or self.username or self.target)
        data: dict = {"Username": f"@{username}", "Ссылка": f"https://t.me/{username}"}

        try:
            r = self.session.get(f"https://t.me/{username}", timeout=10)
            if r.status_code != 200 or "tgme_page_title" not in r.text:
                return {"Статус": "Профиль не найден или скрыт"}

            soup = BeautifulSoup(r.text, "lxml")
            title = soup.find("div", class_="tgme_page_title")
            desc = soup.find("div", class_="tgme_page_description")
            extra = soup.find("div", class_="tgme_page_extra")
            photo = soup.find("img", class_="tgme_page_photo_image")

            if title:
                data["Имя"] = title.text.strip()
            if desc:
                data["Описание"] = desc.text.strip()
            if extra:
                data["Дополнительно"] = extra.text.strip()
            if photo and photo.get("src"):
                data["Фото"] = photo["src"]

            counters = soup.find("div", class_="tgme_page_counter")
            if counters:
                data["Статистика"] = counters.text.strip()
        except requests.RequestException:
            return {"Статус": "Telegram недоступен (возможно, нужен VPN)"}

        return data

    def search_username_osint(self) -> None:
        profile = self.search_telegram_profile()
        self.results["TELEGRAM"] = profile

        username = self.username
        mentions: list[dict] = []

        try:
            r = self.session.get(
                f"https://yandex.ru/search/?text={quote('@' + username)}&lr=213",
                timeout=15,
            )
            soup = BeautifulSoup(r.text, "lxml")
            for item in soup.find_all("li", class_="serp-item")[:5]:
                title_el = item.find("h2")
                desc_el = item.find("div", class_="text-container")
                if title_el and desc_el:
                    mentions.append(
                        {
                            "Заголовок": title_el.text.strip()[:120],
                            "Описание": desc_el.text.strip()[:200],
                        }
                    )
            self.results["ЯНДЕКС"] = mentions or "Упоминаний не найдено"
        except requests.RequestException:
            self.results["ЯНДЕКС"] = "Недоступен"

        found_phones: list[str] = []
        for query in (f"{username} телефон", f"{username} phone +7"):
            try:
                r = self.session.get(
                    f"https://yandex.ru/search/?text={quote(query)}&lr=213",
                    timeout=10,
                )
                if r.status_code == 200:
                    phones = re.findall(
                        r"\+?\d[\d\s\-()]{8,}\d", BeautifulSoup(r.text, "lxml").get_text()
                    )
                    for phone in phones:
                        clean = re.sub(r"\s+", " ", phone.strip())
                        if len(re.sub(r"\D", "", clean)) >= 10:
                            found_phones.append(clean)
            except requests.RequestException:
                continue

        if found_phones:
            self.results["ВОЗМОЖНЫЕ НОМЕРА"] = list(dict.fromkeys(found_phones))[:5]

        socials = {
            "GitHub": f"https://github.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Twitter/X": f"https://x.com/{username}",
            "VK": f"https://vk.com/{username}",
        }
        self.results["СОЦСЕТИ (ссылки для проверки)"] = socials

    def offline_info(self) -> None:
        if not self._phone_only():
            return
        if not self.valid or self.parsed is None:
            self.results["ОШИБКА"] = "Неверный формат номера телефона"
            return

        country = geocoder.description_for_number(self.parsed, "ru")
        region = geocoder.description_for_valid_number(self.parsed, "ru")
        oper = carrier.name_for_number(self.parsed, "ru")
        tz = timezone.time_zones_for_number(self.parsed)

        num_type = phonenumbers.number_type(self.parsed)
        type_map = {
            0: "Стационарный",
            1: "Мобильный",
            2: "Стационарный или мобильный",
            3: "Бесплатный (800)",
            4: "Премиум-номер",
            5: "Общий доступ",
        }

        self.results["ОФФЛАЙН-ДАННЫЕ"] = {
            "Международный": phonenumbers.format_number(
                self.parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "Национальный": phonenumbers.format_number(
                self.parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            "E.164": self.e164,
            "Страна": country or "—",
            "Регион": region or "—",
            "Оператор": oper or "—",
            "Тип линии": type_map.get(num_type, "Неизвестный"),
            "Часовые пояса": ", ".join(tz) if tz else "—",
            "Валидность": "Действительный" if self.valid else "Недействительный",
        }

    def search_yandex(self) -> None:
        if not self._phone_only():
            return
        try:
            r = self.session.get(
                f"https://yandex.ru/search/?text={quote(self.e164)}&lr=213", timeout=15
            )
            soup = BeautifulSoup(r.text, "lxml")
            items = soup.find_all("li", class_="serp-item")[:7]
            res = [
                {
                    "Заголовок": item.find("h2").text.strip()[:120],
                    "Описание": item.find("div", class_="text-container").text.strip()[:200],
                }
                for item in items
                if item.find("h2") and item.find("div", class_="text-container")
            ]
            self.results["ЯНДЕКС"] = res or "Упоминаний не найдено"
        except requests.RequestException:
            self.results["ЯНДЕКС"] = "Недоступен"

    def search_vk(self) -> None:
        if not self._phone_only():
            return
        try:
            phone = self.national if self.country_code == "7" else self.e164.replace("+", "")
            r = self.session.get(
                f"https://vk.com/search?c[section]=people&c[phone]={phone}", timeout=15
            )
            profiles = []
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for div in soup.find_all("div", class_="people_row"):
                    link = div.find("a", class_="search_item")
                    if link:
                        profiles.append(
                            {
                                "Имя": link.text.strip(),
                                "Ссылка": "https://vk.com" + link.get("href", ""),
                            }
                        )
            self.results["ВКОНТАКТЕ"] = profiles[:4] if profiles else "Не найден"
        except requests.RequestException:
            self.results["ВКОНТАКТЕ"] = "Недоступен"

    def search_telegram(self) -> None:
        if not self._phone_only():
            return
        try:
            r = self.session.get(f"https://t.me/{self.e164}", timeout=10)
            if "tgme_page_title" not in r.text:
                self.results["TELEGRAM"] = "Не найден"
                return
            soup = BeautifulSoup(r.text, "lxml")
            title = soup.find("div", class_="tgme_page_title")
            desc = soup.find("div", class_="tgme_page_description")
            data = {"Ссылка": f"https://t.me/{self.e164}"}
            if title:
                data["Имя"] = title.text.strip()
            if desc:
                data["Описание"] = desc.text.strip()
            self.results["TELEGRAM"] = data
        except requests.RequestException:
            self.results["TELEGRAM"] = "Недоступен"

    def search_whatsapp(self) -> None:
        if not self._phone_only():
            return
        try:
            clean = self.e164.replace("+", "").replace(" ", "")
            r = self.session.head(
                f"https://wa.me/{clean}", timeout=10, allow_redirects=True
            )
            self.results["WHATSAPP"] = (
                {"Ссылка": f"https://wa.me/{clean}", "Статус": "Ссылка активна"}
                if r.status_code == 200
                else "Не найден"
            )
        except requests.RequestException:
            self.results["WHATSAPP"] = "Недоступен"

    def search_avito(self) -> None:
        if not self._phone_only():
            return
        try:
            r = self.session.get(
                f"https://www.avito.ru/all?q={quote(self.e164)}", timeout=15
            )
            soup = BeautifulSoup(r.text, "lxml")
            items = soup.find_all("div", {"data-marker": "item"})[:5]
            res = []
            for item in items:
                title = item.find("h3")
                price = item.find("span", {"data-marker": "item-price"})
                link = item.find("a", {"data-marker": "item-title"})
                if title:
                    res.append(
                        {
                            "Товар": title.text.strip()[:80],
                            "Цена": price.text.strip() if price else "—",
                            "Ссылка": "https://www.avito.ru" + link.get("href", "")
                            if link
                            else "—",
                        }
                    )
            self.results["АВИТО"] = res or "Объявлений не найдено"
        except requests.RequestException:
            self.results["АВИТО"] = "Недоступен"

    def search_leaks(self) -> None:
        if not self._phone_only():
            return
        try:
            r = self.session.get(
                f"https://psbdmp.cc/api/v3/search?q={quote(self.e164)}", timeout=15
            )
            if r.status_code != 200:
                self.results["УТЕЧКИ"] = "Сервис недоступен"
                return
            emails = re.findall(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text
            )
            data = {}
            if emails:
                data["Email"] = list(dict.fromkeys(emails))[:5]
            self.results["УТЕЧКИ"] = data or "Ничего не найдено"
        except requests.RequestException:
            self.results["УТЕЧКИ"] = "Недоступен"

    def run_all(self, progress_callback=None) -> dict:
        if self.is_ip:
            self.scan_ip()
            if progress_callback:
                progress_callback(100)
            return self.results

        if self.is_username:
            steps = [
                ("Telegram", self.search_username_osint),
            ]
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

        for i, (_, func) in enumerate(steps):
            try:
                func()
            except Exception as exc:
                self.results["ОШИБКА"] = str(exc)
            if progress_callback:
                progress_callback(int((i + 1) / len(steps) * 100))

        return self.results


class AngelApp:
    def __init__(self):
        self.win = tk.Tk()
        self.win.title("ANGEL")
        self.win.geometry("920x680")
        self.win.configure(bg=C_BG)
        self.win.minsize(720, 560)

        self.icon_path = create_icon()
        self.icon_img = tk.PhotoImage(file=self.icon_path)
        self.win.iconphoto(True, self.icon_img)

        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Готов")
        self.scanning = False
        self.found_phones: list[str] = []

        self._configure_styles()
        self._build_ui()
        self._center()

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Angel.Horizontal.TProgressbar",
            troughcolor=C_BG_INPUT,
            background=C_TEXT,
            bordercolor=C_BORDER,
            lightcolor=C_TEXT,
            darkcolor=C_TEXT,
        )

    def _center(self) -> None:
        self.win.update_idletasks()
        w, h = 920, 680
        x = (self.win.winfo_screenwidth() - w) // 2
        y = (self.win.winfo_screenheight() - h) // 2
        self.win.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self) -> None:
        header = tk.Frame(self.win, bg=C_BG)
        header.pack(fill="x", pady=(18, 8))

        tk.Label(header, image=self.icon_img, bg=C_BG).pack()
        tk.Label(
            header,
            text="ANGEL",
            font=("Consolas", 30, "bold"),
            fg=C_TEXT,
            bg=C_BG,
        ).pack()
        tk.Label(
            header,
            text=f"v{CURRENT_VERSION}  •  номер телефона  •  @username Telegram  •  IP",
            font=("Consolas", 9),
            fg=C_TEXT_DIM,
            bg=C_BG,
        ).pack(pady=(2, 0))

        input_frame = tk.Frame(self.win, bg=C_BG)
        input_frame.pack(fill="x", padx=24, pady=(12, 6))

        tk.Label(
            input_frame,
            text="Цель:",
            font=("Consolas", 12),
            fg=C_TEXT,
            bg=C_BG,
        ).pack(side="left", padx=(0, 8))

        entry = tk.Entry(
            input_frame,
            textvariable=self.target_var,
            font=("Consolas", 14),
            bg=C_BG_INPUT,
            fg=C_TEXT,
            insertbackground=C_TEXT,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=C_BORDER,
            highlightcolor=C_TEXT,
        )
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        entry.focus_set()
        entry.bind("<Return>", lambda _e: self._start_scan())

        tk.Label(
            self.win,
            text="Примеры: +79991234567  •  @durov  •  durov  •  8.8.8.8",
            font=("Consolas", 8),
            fg=C_TEXT_MUTED,
            bg=C_BG,
        ).pack(pady=(0, 10))

        btn_frame = tk.Frame(self.win, bg=C_BG)
        btn_frame.pack(pady=4)

        tk.Button(
            btn_frame,
            text="СКАНИРОВАТЬ",
            command=self._start_scan,
            font=("Consolas", 11, "bold"),
            bg=C_BG_INPUT,
            fg=C_TEXT,
            activebackground=C_BORDER,
            activeforeground=C_TEXT,
            relief="solid",
            bd=1,
            padx=18,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="СОХРАНИТЬ",
            command=self._save,
            font=("Consolas", 11),
            bg=C_BG_INPUT,
            fg=C_ACCENT,
            activebackground=C_BORDER,
            activeforeground=C_TEXT,
            relief="solid",
            bd=1,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="ОЧИСТИТЬ",
            command=self._clear,
            font=("Consolas", 11),
            bg=C_BG_INPUT,
            fg=C_TEXT_DIM,
            activebackground=C_BORDER,
            activeforeground=C_TEXT,
            relief="solid",
            bd=1,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=6)

        self.progress = ttk.Progressbar(
            self.win,
            mode="determinate",
            length=700,
            style="Angel.Horizontal.TProgressbar",
        )
        self.progress.pack(pady=(10, 4))

        tk.Label(
            self.win,
            textvariable=self.status_var,
            font=("Consolas", 9),
            fg=C_TEXT_DIM,
            bg=C_BG,
        ).pack()

        self.phone_buttons = tk.Frame(self.win, bg=C_BG)

        self.output = scrolledtext.ScrolledText(
            self.win,
            font=("Consolas", 10),
            bg=C_BG_PANEL,
            fg=C_ACCENT,
            insertbackground=C_TEXT,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=C_BORDER,
        )
        self.output.pack(fill="both", expand=True, padx=24, pady=(8, 18))

        self.output.tag_config("header", foreground=C_TEXT, font=("Consolas", 13, "bold"))
        self.output.tag_config("section", foreground=C_HIGHLIGHT, font=("Consolas", 11, "bold"))
        self.output.tag_config("key", foreground=C_TEXT_DIM)
        self.output.tag_config("value", foreground=C_ACCENT)
        self.output.tag_config("warn", foreground=C_TEXT)

        self._log_welcome()

    def _log_welcome(self) -> None:
        self._log("=" * 58 + "\n", "header")
        self._log("  ANGEL — OSINT-поиск\n", "header")
        self._log("=" * 58 + "\n\n", "header")
        self._log("Введите номер телефона, Telegram username или IP-адрес.\n\n", "value")
        self._log("Поддерживаемые форматы:\n", "key")
        self._log("  • +79991234567, 89991234567\n", "value")
        self._log("  • @username или username\n", "value")
        self._log("  • 192.168.1.1, 8.8.8.8\n\n", "value")
        self._log("Используйте только в законных целях.\n", "warn")

    def _log(self, text: str, tag: str | None = None) -> None:
        self.output.insert("end", text, tag)
        self.output.see("end")
        self.win.update_idletasks()

    def _clear(self) -> None:
        self.output.delete("1.0", "end")
        self.progress["value"] = 0
        self.status_var.set("Готов")
        self.found_phones = []
        for widget in self.phone_buttons.winfo_children():
            widget.destroy()
        self.phone_buttons.pack_forget()
        self._log_welcome()

    def _clear_phone_buttons(self) -> None:
        for widget in self.phone_buttons.winfo_children():
            widget.destroy()
        self.phone_buttons.pack_forget()

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Ошибка", "Введите номер, username или IP")
            return
        if self.scanning:
            return

        target_type = detect_target_type(target)
        if target_type == "unknown":
            messagebox.showerror(
                "Ошибка",
                "Не удалось определить тип цели.\n"
                "Введите номер (+7...), @username или IP.",
            )
            return

        self.scanning = True
        self.output.delete("1.0", "end")
        self.progress["value"] = 0
        self.status_var.set("Сканирование...")
        self._clear_phone_buttons()

        def worker():
            scanner = AngelScanner(target)
            try:
                data = scanner.run_all(
                    progress_callback=lambda v: self.win.after(
                        0, lambda val=v: self.progress.configure(value=val)
                    )
                )
                self.win.after(0, lambda: self._display(data, scanner))
                self.win.after(0, lambda: self.status_var.set("Завершено"))
                self.win.after(0, lambda: self.progress.configure(value=100))
            except Exception as exc:
                self.win.after(0, lambda: self._log(f"\nОШИБКА: {exc}\n", "warn"))
                self.win.after(0, lambda: self.status_var.set("Ошибка"))
            finally:
                self.scanning = False

        threading.Thread(target=worker, daemon=True).start()

    def _display(self, data: dict, scanner: AngelScanner) -> None:
        if scanner.is_ip:
            mode = "IP-АДРЕС"
        elif scanner.is_username:
            mode = f"TELEGRAM @{scanner.username}"
        else:
            mode = "НОМЕР ТЕЛЕФОНА"

        self._log("=" * 58 + "\n", "header")
        self._log(f"  РЕЗУЛЬТАТЫ — {mode}\n", "header")
        self._log("=" * 58 + "\n\n", "header")

        self.found_phones = []
        for section, content in data.items():
            self._log(f"\n▌ {section}\n", "section")
            self._log("─" * 50 + "\n", "section")
            self._render_content(content, indent=1)

            if section == "ВОЗМОЖНЫЕ НОМЕРА" and isinstance(content, list):
                self.found_phones.extend(content)

        if self.found_phones:
            self._show_phone_buttons()

        self._log("\n" + "=" * 58 + "\n", "header")
        self._log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "value")
        self._log("  ANGEL\n", "value")
        self._log("=" * 58 + "\n", "header")

    def _render_content(self, content, indent: int = 0) -> None:
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

    def _show_phone_buttons(self) -> None:
        self.phone_buttons.pack(pady=(0, 4))
        tk.Label(
            self.phone_buttons,
            text="Проверить найденный номер:",
            font=("Consolas", 9),
            fg=C_TEXT_DIM,
            bg=C_BG,
        ).pack()
        for phone in self.found_phones[:3]:
            tk.Button(
                self.phone_buttons,
                text=f"→ {phone}",
                command=lambda p=phone: self._scan_phone(p),
                font=("Consolas", 10),
                bg=C_BG_INPUT,
                fg=C_TEXT,
                activebackground=C_BORDER,
                activeforeground=C_TEXT,
                relief="solid",
                bd=1,
                padx=12,
                pady=4,
                cursor="hand2",
            ).pack(pady=2)

    def _scan_phone(self, phone: str) -> None:
        self.target_var.set(phone)
        self._start_scan()

    def _save(self) -> None:
        text = self.output.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Пусто", "Нет данных для сохранения")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt"), ("JSON", "*.json")],
            initialfile=f"angel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Готово", f"Сохранено:\n{path}")

    def run(self) -> None:
        self.win.mainloop()


if __name__ == "__main__":
    AngelApp().run()
