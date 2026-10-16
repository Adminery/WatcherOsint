#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WatcherOsint — Username Intelligence module  (v1.0)
pip install flask flask-cors aiohttp

For a given username, checks which known platforms have a matching
public profile page, and reads that page's own public title/meta-
description as a "bio" line. That's the whole job.

Deliberately removed from the earlier draft: AI-persona inference
(age/profession/interests guessed from bios), a knowledge graph
auto-linking every found account, pHash face/avatar fingerprinting
across platforms, username-fuzzing (guessing a person's *other*
possible usernames), Maltego export, and rotating fake user agents
to evade per-site rate limiting. Those turn "does this handle exist"
into an automated profiling pipeline, which is out of scope here.

This module also identifies itself honestly over HTTP (a real,
static User-Agent) instead of impersonating a browser to dodge
detection — good citizenship for a tool meant to run in the open.
"""
from __future__ import annotations
import asyncio, re, time
from dataclasses import dataclass
from flask import Blueprint, request, jsonify

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

VERSION = "1.0.0"
bp = Blueprint("username", __name__)
USER_AGENT = "WatcherOsint/1.0 (+https://github.com/WatcherAm/WatcherAm; contact via repo issues)"


@dataclass
class Platform:
    name: str
    url: str
    category: str
    region: str = "global"           # "global" needs the user's own VPN/proxy from Iran; "iran" needs a direct connection
    not_found_marker: str | None = None


PLATFORMS: list[Platform] = [
    Platform("Instagram", "https://www.instagram.com/{u}/", "social"),
    Platform("Telegram", "https://t.me/{u}", "social", not_found_marker="tgme_page_icon"),
    Platform("X / Twitter", "https://x.com/{u}", "social"),
    Platform("TikTok", "https://www.tiktok.com/@{u}", "video", not_found_marker="couldn't find this account"),
    Platform("Reddit", "https://www.reddit.com/user/{u}/", "social", not_found_marker="page not found"),
    Platform("Pinterest", "https://www.pinterest.com/{u}/", "social"),
    Platform("Tumblr", "https://{u}.tumblr.com/", "social"),
    Platform("LinkedIn", "https://www.linkedin.com/in/{u}", "social"),
    Platform("Mastodon", "https://mastodon.social/@{u}", "social"),
    Platform("GitHub", "https://github.com/{u}", "developer"),
    Platform("GitLab", "https://gitlab.com/{u}", "developer"),
    Platform("Bitbucket", "https://bitbucket.org/{u}/", "developer"),
    Platform("CodePen", "https://codepen.io/{u}", "developer"),
    Platform("Dev.to", "https://dev.to/{u}", "developer"),
    Platform("Replit", "https://replit.com/@{u}", "developer"),
    Platform("Kaggle", "https://www.kaggle.com/{u}", "developer"),
    Platform("HuggingFace", "https://huggingface.co/{u}", "developer"),
    Platform("NPM", "https://www.npmjs.com/~{u}", "developer"),
    Platform("PyPI", "https://pypi.org/user/{u}/", "developer"),
    Platform("Stack Overflow", "https://stackoverflow.com/users/{u}", "developer"),
    Platform("Steam", "https://steamcommunity.com/id/{u}", "gaming", not_found_marker="The specified profile could not be found"),
    Platform("Chess.com", "https://www.chess.com/member/{u}", "gaming"),
    Platform("Lichess", "https://lichess.org/@/{u}", "gaming"),
    Platform("Twitch", "https://www.twitch.tv/{u}", "entertainment"),
    Platform("SoundCloud", "https://soundcloud.com/{u}", "entertainment"),
    Platform("Spotify", "https://open.spotify.com/user/{u}", "entertainment"),
    Platform("Medium", "https://medium.com/@{u}", "creator"),
    Platform("Dribbble", "https://dribbble.com/{u}", "creator"),
    Platform("Behance", "https://www.behance.net/{u}", "creator"),
    Platform("DeviantArt", "https://www.deviantart.com/{u}", "creator"),
    Platform("Linktree", "https://linktr.ee/{u}", "creator"),
    Platform("Quora", "https://www.quora.com/profile/{u}", "community"),
    Platform("Goodreads", "https://www.goodreads.com/{u}", "community"),
    Platform("Keybase", "https://keybase.io/{u}", "community"),
    Platform("Gravatar", "https://gravatar.com/{u}", "community"),
    # ─ Iranian (reachable directly, no VPN needed) ─
    Platform("آپارات", "https://www.aparat.com/{u}", "iranian", region="iran"),
    Platform("ویرگول", "https://virgool.io/@{u}", "iranian", region="iran"),
    Platform("روبیکا", "https://rubika.ir/{u}", "iranian", region="iran"),
    Platform("ایتا", "https://eitaa.com/{u}", "iranian", region="iran"),
    Platform("بله", "https://ble.ir/{u}", "iranian", region="iran"),
    Platform("دیجی‌کالا", "https://www.digikala.com/profile/{u}/", "iranian", region="iran"),
    Platform("زومیت", "https://www.zoomit.ir/author/{u}/", "iranian", region="iran"),
]

NOT_FOUND_PATTERNS = [
    r"page not found", r"user not found", r"no such user", r"doesn'?t exist",
    r"couldn'?t find (?:this|the) (?:account|user|page)", r"this page is unavailable",
    r"صفحه(?:‌| )?مورد(?:‌| )?نظر(?:‌| )?یافت(?:‌| )?نشد", r"کاربر(?:‌| )?مورد(?:‌| )?نظر(?:‌| )?یافت(?:‌| )?نشد",
]
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\u0600-\u06FF]{2,40}$")

_hits: dict[str, list[float]] = {}
def rate_limited(ip: str, limit=8, window=60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(ip, []) if now - t < window]
    arr.append(now)
    _hits[ip] = arr
    return len(arr) > limit


def extract_meta(html: str) -> dict:
    out = {"title": None, "bio": None}
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m: out["title"] = m.group(1).strip()[:200]
    m = re.search(r'<meta[^>]+(?:property|name)=["\'](?:og:description|description)["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m: out["bio"] = m.group(1)[:280]
    return out


def matches_any(text: str, patterns: list[str]) -> bool:
    low = text.lower()
    return any(re.search(p, low, re.I) for p in patterns)


async def check_platform(session, platform: Platform, username: str, sem: asyncio.Semaphore) -> dict:
    url = platform.url.format(u=username)
    base = {"platform": platform.name, "category": platform.category, "region": platform.region, "url": url,
            "status": "ERROR", "bio": None, "title": None}
    async with sem:
        try:
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 404:
                    base["status"] = "NOT_FOUND"; return base
                if resp.status != 200:
                    base["status"] = "UNKNOWN"; return base
                raw = await resp.text(errors="ignore")
                html = re.sub(r"<script[^>]*>.*?</script>", "", raw, flags=re.S | re.I)
                if platform.not_found_marker and platform.not_found_marker.lower() in html.lower():
                    base["status"] = "NOT_FOUND"; return base
                if matches_any(html[:12000], NOT_FOUND_PATTERNS):
                    base["status"] = "NOT_FOUND"; return base
                if username.lower() not in html.lower():
                    base["status"] = "UNKNOWN"; return base
                meta = extract_meta(html)
                base.update(status="FOUND", bio=meta["bio"], title=meta["title"])
                return base
        except asyncio.TimeoutError:
            base["status"] = "TIMEOUT"; return base
        except Exception:
            base["status"] = "ERROR"; return base


async def scan_username(username: str, region: str, proxy: str | None) -> list[dict]:
    selected = [p for p in PLATFORMS if region == "all" or p.region == region]
    sem = asyncio.Semaphore(12)
    connector = aiohttp.TCPConnector(limit=12, ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as session:
        tasks = [check_platform(session, p, username, sem) for p in selected]
        # `proxy` is the user's own VPN/proxy, passed straight to aiohttp per-request
        # (aiohttp takes it per-call), never rotated or spoofed.
        if proxy:
            tasks = [check_platform_proxied(session, p, username, sem, proxy) for p in selected]
        return await asyncio.gather(*tasks)


async def check_platform_proxied(session, platform, username, sem, proxy):
    url = platform.url.format(u=username)
    base = {"platform": platform.name, "category": platform.category, "region": platform.region, "url": url,
            "status": "ERROR", "bio": None, "title": None}
    async with sem:
        try:
            async with session.get(url, proxy=proxy, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 404:
                    base["status"] = "NOT_FOUND"; return base
                if resp.status != 200:
                    base["status"] = "UNKNOWN"; return base
                raw = await resp.text(errors="ignore")
                html = re.sub(r"<script[^>]*>.*?</script>", "", raw, flags=re.S | re.I)
                if platform.not_found_marker and platform.not_found_marker.lower() in html.lower():
                    base["status"] = "NOT_FOUND"; return base
                if matches_any(html[:12000], NOT_FOUND_PATTERNS):
                    base["status"] = "NOT_FOUND"; return base
                if username.lower() not in html.lower():
                    base["status"] = "UNKNOWN"; return base
                meta = extract_meta(html)
                base.update(status="FOUND", bio=meta["bio"], title=meta["title"])
                return base
        except Exception:
            return base


@bp.route("/api/username")
def api_username():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if rate_limited(ip):
        return jsonify({"success": False, "error": "rate_limited", "message": "تعداد درخواست‌ها زیاد است."}), 429

    username = (request.args.get("u") or "").strip().lstrip("@")
    region = request.args.get("region", "all")          # "iran" | "global" | "all"
    proxy = request.args.get("proxy") or None             # the USER's own proxy/VPN endpoint, optional
    if not username or not USERNAME_RE.match(username):
        return jsonify({"success": False, "error": "invalid_input", "message": "نام‌کاربری نامعتبر است."}), 400
    if region not in ("iran", "global", "all"):
        region = "all"
    if not HAS_AIOHTTP:
        return jsonify({"success": False, "error": "missing_dependency", "message": "aiohttp نصب نیست."}), 500

    results = asyncio.run(scan_username(username, region, proxy))
    found = [r for r in results if r["status"] == "FOUND"]

    return jsonify({
        "success": True, "version": VERSION, "username": username, "region": region,
        "checked": len(results), "found_count": len(found), "results": results,
    })
