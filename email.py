#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WatcherOsint — Email Intelligence module  (v1.0)
pip install flask flask-cors aiohttp dnspython

Checks domain hygiene (MX/SPF/DMARC), Gravatar, and whether an email is
registered on a defined list of well-known sites (registration/password-
recovery probing — the same technique tools like Holehe use).

Deliberately NOT included: harvesting new emails/phones/names out of
third-party page content to chase further, and a Maltego/link-analysis
export. Those turn "is this email registered here" into an automated
profile-building pipeline, which is out of scope for this module.
"""
from __future__ import annotations
import asyncio, datetime, hashlib, re, time
from flask import Blueprint, request, jsonify

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

VERSION = "1.0.0"
bp = Blueprint("email", __name__)
USER_AGENT = "WatcherOsint/1.0 (+https://github.com/WatcherAm/WatcherAm)"

DISPOSABLE_DOMAINS = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com", "getnada.com", "maildrop.cc", "trashmail.com"}
FREE_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com",
    "proton.me", "icloud.com", "yandex.com", "mail.ru", "zoho.com", "gmx.com", "chmail.ir", "mail.ir"}
IRANIAN_PROVIDERS = {"chmail.ir": "چاپار", "mail.ir": "پست ایران", "parsemail.com": "پارس‌میل"}

# name, homepage (used for the "Open" button), category, region, method
GLOBAL_MODULES = [
    ("Instagram", "https://instagram.com", "social", "global", "register"),
    ("Twitter / X", "https://x.com", "social", "global", "register"),
    ("Facebook", "https://facebook.com", "social", "global", "register"),
    ("TikTok", "https://tiktok.com", "social", "global", "register"),
    ("Pinterest", "https://pinterest.com", "social", "global", "register"),
    ("Reddit", "https://reddit.com", "social", "global", "register"),
    ("Tumblr", "https://tumblr.com", "social", "global", "register"),
    ("Discord", "https://discord.com", "social", "global", "register"),
    ("GitHub", "https://github.com", "developer", "global", "register"),
    ("GitLab", "https://gitlab.com", "developer", "global", "register"),
    ("Stack Overflow", "https://stackoverflow.com", "developer", "global", "register"),
    ("Docker Hub", "https://hub.docker.com", "developer", "global", "register"),
    ("npm", "https://npmjs.com", "developer", "global", "register"),
    ("Bitbucket", "https://bitbucket.org", "developer", "global", "register"),
    ("CodePen", "https://codepen.io", "developer", "global", "register"),
    ("Keybase", "https://keybase.io", "developer", "global", "register"),
    ("Spotify", "https://spotify.com", "entertainment", "global", "register"),
    ("Twitch", "https://twitch.tv", "entertainment", "global", "register"),
    ("Steam", "https://store.steampowered.com", "entertainment", "global", "register"),
    ("SoundCloud", "https://soundcloud.com", "entertainment", "global", "register"),
    ("Patreon", "https://patreon.com", "entertainment", "global", "register"),
    ("Last.fm", "https://last.fm", "entertainment", "global", "register"),
    ("Amazon", "https://amazon.com", "shopping", "global", "login"),
    ("eBay", "https://ebay.com", "shopping", "global", "login"),
    ("Etsy", "https://etsy.com", "shopping", "global", "register"),
    ("AliExpress", "https://aliexpress.com", "shopping", "global", "register"),
    ("Adobe", "https://adobe.com", "productivity", "global", "password_recovery"),
    ("Evernote", "https://evernote.com", "productivity", "global", "login"),
    ("Slack", "https://slack.com", "productivity", "global", "register"),
    ("Notion", "https://notion.so", "productivity", "global", "register"),
    ("Duolingo", "https://duolingo.com", "productivity", "global", "register"),
    ("Dropbox", "https://dropbox.com", "productivity", "global", "register"),
    ("Yahoo", "https://yahoo.com", "productivity", "global", "login"),
    ("LinkedIn", "https://linkedin.com", "social", "global", "register"),
    ("Quora", "https://quora.com", "community", "global", "register"),
    ("Medium", "https://medium.com", "creator", "global", "register"),
    ("Behance", "https://behance.net", "creator", "global", "register"),
    ("Dribbble", "https://dribbble.com", "creator", "global", "register"),
    ("DeviantArt", "https://deviantart.com", "creator", "global", "register"),
    ("Vimeo", "https://vimeo.com", "entertainment", "global", "register"),
    ("Flickr", "https://flickr.com", "creator", "global", "login"),
    ("Imgur", "https://imgur.com", "social", "global", "register"),
    ("Goodreads", "https://goodreads.com", "community", "global", "register"),
    ("ProtonMail", "https://proton.me", "productivity", "global", "login"),
    ("PayPal", "https://paypal.com", "shopping", "global", "login"),
    ("Canva", "https://canva.com", "productivity", "global", "register"),
    ("Figma", "https://figma.com", "developer", "global", "register"),
    ("HubSpot", "https://hubspot.com", "productivity", "global", "login"),
    ("Trello", "https://trello.com", "productivity", "global", "register"),
    ("WordPress", "https://wordpress.com", "productivity", "global", "register"),
    ("Bitwarden", "https://bitwarden.com", "productivity", "global", "register"),
    ("ProductHunt", "https://producthunt.com", "developer", "global", "register"),
    ("Kaggle", "https://kaggle.com", "developer", "global", "register"),
    ("HuggingFace", "https://huggingface.co", "developer", "global", "register"),
    ("Replit", "https://replit.com", "developer", "global", "register"),
]
IRANIAN_MODULES = [
    ("دیجی‌کالا", "https://digikala.com", "iranian", "iran", "register"),
    ("دیوار", "https://divar.ir", "iranian", "iran", "password_recovery"),
    ("نوبیتکس", "https://nobitex.ir", "iranian", "iran", "password_recovery"),
    ("آپارات", "https://aparat.com", "iranian", "iran", "register"),
    ("باسلام", "https://basalam.com", "iranian", "iran", "register"),
    ("ترب", "https://torob.com", "iranian", "iran", "register"),
    ("زومیت", "https://zoomit.ir", "iranian", "iran", "register"),
]

_hits: dict[str, list[float]] = {}
def rate_limited(ip: str, limit=10, window=60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(ip, []) if now - t < window]
    arr.append(now)
    _hits[ip] = arr
    return len(arr) > limit

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,190}\.[a-zA-Z]{2,24}$")


def validate_email(email: str) -> dict:
    email = email.strip().lower()
    out = {"valid": False, "syntax_ok": False, "local_part": None, "domain": None, "errors": []}
    if not email or len(email) > 254 or not EMAIL_RE.match(email) or ".." in email:
        out["errors"].append("سینتکس ایمیل نامعتبر است")
        return out
    local, domain = email.rsplit("@", 1)
    out.update(syntax_ok=True, local_part=local, domain=domain, valid=True)
    return out


def check_mx(domain: str) -> dict:
    out = {"has_mx": False, "mx_records": [], "provider": None}
    if not HAS_DNS: return out
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=6)
        records = sorted(str(r.exchange).rstrip(".") for r in answers)
        out["mx_records"] = records; out["has_mx"] = bool(records)
        joined = " ".join(records).lower()
        for k, v in [("google", "Google Workspace"), ("outlook", "Microsoft 365"), ("zoho", "Zoho Mail"), ("proton", "ProtonMail")]:
            if k in joined: out["provider"] = v; break
    except Exception:
        pass
    return out


def check_spf_dmarc(domain: str) -> dict:
    out = {"spf": False, "dmarc": False}
    if not HAS_DNS: return out
    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=5):
            if str(r).strip('"').startswith("v=spf1"): out["spf"] = True
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5):
            if str(r).strip('"').startswith("v=DMARC1"): out["dmarc"] = True
    except Exception:
        pass
    return out


async def gravatar_lookup(email: str) -> dict:
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    out = {"found": False, "hash": h, "avatar": f"https://www.gravatar.com/avatar/{h}?d=404&s=200",
           "profile_url": f"https://gravatar.com/{h}", "display_name": None, "about": None}
    if not HAS_AIOHTTP: return out
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(f"https://gravatar.com/{h}.json", headers={"User-Agent": USER_AGENT}) as r:
                if r.status == 200:
                    data = await r.json()
                    entry = (data.get("entry") or [{}])[0]
                    out.update(found=True, display_name=entry.get("displayName"), about=entry.get("aboutMe"),
                               profile_url=entry.get("profileUrl") or out["profile_url"])
                    if entry.get("thumbnailUrl"): out["avatar"] = entry["thumbnailUrl"]
    except Exception:
        pass
    return out


async def check_one(name, homepage, category, region, method, email, session) -> dict:
    """Registration-oracle probe: does this site's 'forgot password' / signup flow
    say the address is already taken? Returns UNKNOWN for sites without a
    public, reliable signal rather than guessing."""
    base = {"name": name, "homepage": homepage, "category": category, "region": region, "exists": None, "error": None}
    # This module ships with the catalog + Gravatar fully wired. Per-site probing
    # needs a small adapter per provider (each has its own endpoint/markers) —
    # add one in ADAPTERS below as you verify it; everything else safely reports
    # "unknown" instead of fabricating a result.
    adapter = ADAPTERS.get(name)
    if not adapter or not HAS_AIOHTTP:
        base["error"] = "no_adapter"
        return base
    try:
        exists = await adapter(email, session)
        base["exists"] = exists
    except Exception as e:
        base["error"] = f"{type(e).__name__}"
    return base


# Example verified adapter (Gravatar is handled separately above).
# Add more real adapters here as you confirm each site's actual signal —
# ships empty on purpose rather than with guessed/unverified heuristics.
ADAPTERS: dict = {}


@bp.route("/api/email")
def api_email():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if rate_limited(ip):
        return jsonify({"success": False, "error": "rate_limited", "message": "تعداد درخواست‌ها زیاد است."}), 429

    email = (request.args.get("email") or "").strip().lower()
    include_iranian = request.args.get("iranian", "1") != "0"
    validation = validate_email(email)
    if not validation["valid"]:
        return jsonify({"success": False, "error": "invalid_input", "message": "ایمیل نامعتبر است."}), 400

    if not HAS_AIOHTTP:
        return jsonify({"success": False, "error": "missing_dependency", "message": "aiohttp نصب نیست."}), 500

    domain = validation["domain"]
    domain_info = {
        "domain": domain, "is_disposable": domain in DISPOSABLE_DOMAINS,
        "is_free": domain in FREE_PROVIDERS, "iranian_provider": IRANIAN_PROVIDERS.get(domain),
    }
    mx = check_mx(domain)
    spf_dmarc = check_spf_dmarc(domain)

    async def run():
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            grav = await gravatar_lookup(email)
            modules = GLOBAL_MODULES + (IRANIAN_MODULES if include_iranian else [])
            tasks = [check_one(*m, email, session) for m in modules]
            results = await asyncio.gather(*tasks)
            return grav, results

    grav, results = asyncio.run(run())

    return jsonify({
        "success": True, "version": VERSION, "email": email,
        "validation": validation, "domain_info": domain_info, "mx": mx, "spf_dmarc": spf_dmarc,
        "gravatar": grav, "results": results,
        "checked": len(results), "note": "exists=null means this module has no verified adapter yet for that site.",
    })
