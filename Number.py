#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""  
WatcherOsint — Phone Intelligence module  (v1.0)
pip install flask flask-cors phonenumbers

Classifies a phone number from public numbering-plan data only:
carrier/prefix, region, line type, premium/service-number patterns,
a heuristic spam score, and ready-to-open messenger deep links.

Removed from the original draft: Telegram contact-import lookup
(ImportContactsRequest) — importing a number as a contact to pull a
stranger's name/photo/bio/last-seen is a de-anonymization technique,
not a numbering-plan classification, so it has no place here.
"""
from __future__ import annotations
import re, time
from flask import Blueprint, request, jsonify

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier as ph_carrier, timezone as ph_tz
    HAS_PN = True
except ImportError:
    HAS_PN = False

VERSION = "1.0.0"
bp = Blueprint("phone", __name__)

# ── public Iranian numbering-plan tables ──────────────────────────
MCI_PREFIXES = {
    "0910": {"regions": ["سراسری"], "type": "دائمی/اعتباری"},
    "0911": {"regions": ["گیلان", "مازندران", "گلستان"], "type": "دائمی/اعتباری"},
    "0912": {"regions": ["تهران", "البرز", "قم", "زنجان", "سمنان", "قزوین"], "type": "فقط دائمی"},
    "0913": {"regions": ["اصفهان", "یزد", "کرمان", "چهارمحال و بختیاری"], "type": "دائمی/اعتباری"},
    "0914": {"regions": ["آذربایجان شرقی", "آذربایجان غربی", "اردبیل"], "type": "دائمی/اعتباری"},
    "0915": {"regions": ["خراسان رضوی", "خراسان شمالی", "خراسان جنوبی", "سیستان و بلوچستان"], "type": "دائمی/اعتباری"},
    "0916": {"regions": ["خوزستان", "لرستان"], "type": "دائمی/اعتباری"},
    "0917": {"regions": ["فارس", "بوشهر", "هرمزگان", "کهگیلویه و بویراحمد"], "type": "دائمی/اعتباری"},
    "0918": {"regions": ["کردستان", "ایلام", "مرکزی", "کرمانشاه", "همدان"], "type": "دائمی/اعتباری"},
    "0919": {"regions": ["سراسری"], "type": "اعتباری"},
    "0990": {"regions": ["سراسری"], "type": "اعتباری"}, "0991": {"regions": ["سراسری"], "type": "دائمی/اعتباری"},
    "0992": {"regions": ["سراسری"], "type": "اعتباری"}, "0993": {"regions": ["سراسری"], "type": "اعتباری"},
    "0994": {"regions": ["سراسری"], "type": "اعتباری"}, "0903": {"regions": ["سراسری"], "type": "اعتباری"},
}
IRANCELL_PREFIXES = {p: {"type": t} for p, t in {
    "0930": "اعتباری", "0933": "اعتباری", "0935": "اعتباری", "0936": "اعتباری", "0937": "اعتباری",
    "0938": "اعتباری", "0939": "اعتباری", "0900": "دائمی/اعتباری", "0901": "فقط اعتباری",
    "0902": "اعتباری", "0904": "سیم‌کارت کودک", "0905": "اعتباری", "0941": "فقط اینترنت TD-LTE",
}.items()}
RIGHTEL_PREFIXES = {p: {"type": t} for p, t in {
    "0920": "دائمی", "0921": "اعتباری و دیتا", "0922": "اعتباری", "0923": "اعتباری",
}.items()}
SERVICE_NUMBERS = {
    "110": "پلیس", "115": "اورژانس", "125": "آتش‌نشانی", "118": "اطلاعات تلفن",
    "100": "مخابرات", "197": "شکایات مخابرات", "1420": "تاکسی تلفنی",
}

# ── tiny in-memory rate limiter (swap for Redis in real deployment) ──
_hits: dict[str, list[float]] = {}
def rate_limited(ip: str, limit=20, window=60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(ip, []) if now - t < window]
    arr.append(now)
    _hits[ip] = arr
    return len(arr) > limit

PHONE_RE = re.compile(r"^[\d+\-\s()]{3,20}$")


def normalize_iranian(phone: str) -> str:
    d = re.sub(r"[^\d]", "", phone)
    if d.startswith("0098"): d = d[2:]
    if d.startswith("98") and len(d) >= 12: d = "0" + d[2:]
    if not d.startswith("0"): d = "0" + d
    return d


def to_international(phone: str) -> str:
    d = normalize_iranian(phone)
    return "98" + d[1:] if d.startswith("0") else d


def detect_iranian_prefix(phone: str) -> dict | None:
    d = normalize_iranian(phone)
    if len(d) < 4: return None
    p4 = d[:4]
    for db, name in [(MCI_PREFIXES, "همراه اول (MCI)"), (IRANCELL_PREFIXES, "ایرانسل (Irancell)"), (RIGHTEL_PREFIXES, "رایتل (Rightel)")]:
        if p4 in db:
            info = db[p4]
            return {"carrier": name, "regions": info.get("regions", ["سراسری"]), "line_type": info["type"], "prefix": p4}
    return None


def detect_premium(phone: str) -> dict:
    d = re.sub(r"[^\d]", "", phone)
    local = d[-10:] if len(d) >= 10 else d
    out = {"is_premium": False, "patterns": [], "score": 0}
    pats = {
        "تکرار ۴ رقمی": r"(\d)\1{3,}", "تکرار ۳ رقمی": r"(\d)\1{2,}",
        "دنباله صعودی": r"0123|1234|2345|3456|4567|5678|6789",
        "دنباله نزولی": r"9876|8765|7654|6543|5432|4321",
        "آینه‌ای": r"(\d{2})\1{2,}", "پایان ۰۰۰": r"000$", "پایان ۹۹۹": r"999$",
    }
    for name, pat in pats.items():
        if re.search(pat, local):
            out["patterns"].append(name); out["score"] += 1
    if "تکرار ۴ رقمی" in out["patterns"]: out["score"] += 5
    if "آینه‌ای" in out["patterns"]: out["score"] += 4
    out["is_premium"] = out["score"] >= 3
    return out


def detect_service_number(phone: str) -> dict | None:
    d = re.sub(r"[^\d]", "", phone)
    local = d[-10:] if len(d) >= 10 else d
    for code, name in SERVICE_NUMBERS.items():
        if local.endswith(code) or d == code:
            return {"code": code, "name": name}
    return None


def validate_iranian_mobile(phone: str) -> dict:
    d = normalize_iranian(phone)
    out = {"valid": True, "errors": []}
    if len(d) != 11:
        out["valid"] = False; out["errors"].append(f"طول نامعتبر: {len(d)} رقم")
    if d[:3] not in ("090", "091", "092", "093", "094", "099"):
        out["valid"] = False; out["errors"].append(f"پیش‌شماره نامعتبر: {d[:3]}")
    return out


def phone_intel(phone: str) -> dict:
    out = {"raw": phone, "valid": False, "country": None, "country_code": 0, "region": None,
           "carrier": None, "line_type": None, "timezones": [], "international": None,
           "national": None, "e164": None}
    if not HAS_PN:
        d = re.sub(r"[^\d+]", "", phone)
        out["e164"] = d; out["valid"] = len(d) >= 12
        if d.startswith(("+98", "98")):
            out["country"] = "IR"; out["country_code"] = 98; out["timezones"] = ["Asia/Tehran"]
        return out
    try:
        num = phonenumbers.parse(phone, "IR" if not phone.strip().startswith("+") else None)
        out["valid"] = phonenumbers.is_valid_number(num)
        out["country_code"] = num.country_code
        out["country"] = phonenumbers.region_code_for_number(num)
        out["region"] = geocoder.description_for_number(num, "fa") or geocoder.description_for_number(num, "en")
        out["carrier"] = ph_carrier.name_for_number(num, "fa") or ph_carrier.name_for_number(num, "en")
        out["timezones"] = list(ph_tz.time_zones_for_number(num))
        out["international"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out["national"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
        out["e164"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        nt = phonenumbers.number_type(num)
        out["line_type"] = {
            phonenumbers.PhoneNumberType.MOBILE: "موبایل", phonenumbers.PhoneNumberType.FIXED_LINE: "ثابت",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "ثابت/موبایل", phonenumbers.PhoneNumberType.VOIP: "VoIP",
        }.get(nt, str(nt))
    except Exception as e:
        out["error"] = str(e)[:100]
    return out


def compute_spam_score(phone: str, carrier_info: dict | None) -> dict:
    score, reasons = 3, []
    premium = detect_premium(phone)
    if premium["is_premium"]:
        score -= 2; reasons.append("شماره رند (معمولاً خط شخصی/تجاری شناخته‌شده)")
    if carrier_info and "اعتباری" in carrier_info.get("line_type", ""):
        score += 1; reasons.append("خط اعتباری")
    return {"score": max(0, min(10, score)), "reasons": reasons or ["عادی"]}


def build_messenger_links(e164_digits: str) -> dict:
    # Deep links a WhatsApp-style "start a chat" link — not an identity lookup.
    return {
        "Telegram": f"https://t.me/+{e164_digits}",
        "WhatsApp": f"https://wa.me/{e164_digits}",
        "بله": f"https://ble.ir/+{e164_digits}",
        "روبیکا": f"https://rubika.ir/+{e164_digits}",
        "ایتا": f"https://eitaa.com/+{e164_digits}",
        "گپ": f"https://gap.im/+{e164_digits}",
        "iGap": f"https://igap.net/+{e164_digits}",
        # Instagram has no public phone-based deep link — flagged, not faked.
        "Instagram": None,
    }


@bp.route("/api/phone")
def api_phone():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if rate_limited(ip):
        return jsonify({"success": False, "error": "rate_limited", "message": "تعداد درخواست‌ها زیاد است، کمی صبر کنید."}), 429

    raw = (request.args.get("number") or "").strip()
    if not raw or not PHONE_RE.match(raw) or len(raw) > 20:
        return jsonify({"success": False, "error": "invalid_input", "message": "شماره نامعتبر است."}), 400

    intel = phone_intel(raw)
    iranian = detect_iranian_prefix(raw)
    digits = to_international(raw)

    return jsonify({
        "success": True, "version": VERSION, "raw": raw,
        "basic": intel, "iranian": iranian,
        "validation": validate_iranian_mobile(raw),
        "premium": detect_premium(raw),
        "service": detect_service_number(raw),
        "spam": compute_spam_score(raw, iranian),
        "messenger_links": build_messenger_links(digits),
    })
