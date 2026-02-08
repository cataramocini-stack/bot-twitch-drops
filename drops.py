import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


TWITCHDROPS_NET_URL = "https://twitchdrops.net/"
TWITCHDROPS_NET_GAMES_URL = "https://www.twitchdrops.net/games"
TRACKER_GG_TWITCH_DROPS_URL = "https://www.tracker.gg/twitch-drops"
DISCORD_API_BASE = "https://discord.com/api/v10"
DEFAULT_STATE_FILE = "active_drops.json"

CHROME_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Referer": "https://www.twitch.tv/",
}


@dataclass(frozen=True)
class Drop:
    drop_id: str
    game: str
    item: str
    expires_at: int


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout_s: int = 30,
) -> tuple[int, dict[str, str], bytes]:
    request_headers = {
        "Accept": "*/*",
    }
    if headers:
        request_headers.update(headers)

    req = urllib.request.Request(url=url, method=method, headers=request_headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw = resp.read()
            encoding = (resp_headers.get("content-encoding") or "").lower().strip()
            if encoding == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return status, resp_headers, raw
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        raw = e.read() if e.fp else b""
        encoding = (resp_headers.get("content-encoding") or "").lower().strip()
        if encoding == "gzip":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        return int(e.code), resp_headers, raw


def parse_iso8601_to_epoch_seconds(value: str) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def stable_drop_id(game: str, item: str, expires_at: int) -> str:
    raw = f"{game}\n{item}\n{expires_at}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


MONTH_RE = re.compile(
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\b",
    flags=re.IGNORECASE,
)


def parse_date_to_epoch_seconds(text: str) -> int | None:
    s = normalize_ws(text)
    if not s:
        return None

    m = re.search(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?", s)
    if m:
        ts = parse_iso8601_to_epoch_seconds(m.group(0))
        if ts is not None:
            return ts

    if not MONTH_RE.search(s):
        return None

    s = re.sub(r"\b(UTC|GMT)\b", "", s, flags=re.IGNORECASE).strip()
    s = s.replace("Sept", "Sep").replace("sept", "Sep")

    fmts = (
        "%b %d, %Y",
        "%B %d, %Y",
        "%b %d %Y",
        "%B %d %Y",
        "%d %b %Y",
        "%d %B %Y",
        "%b %d, %Y %H:%M",
        "%B %d, %Y %H:%M",
        "%b %d, %Y %H:%M:%S",
        "%B %d, %Y %H:%M:%S",
    )
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


def fetch_html(url: str) -> str:
    try:
        import cloudscraper  # type: ignore

        scraper = cloudscraper.create_scraper()
        resp = scraper.get(url, headers=CHROME_HEADERS, timeout=30)
        if int(resp.status_code) // 100 != 2:
            raise RuntimeError(f"Falha ao buscar {url} (status={resp.status_code})")
        return str(resp.text)
    except Exception:
        status, _, body = http_request("GET", url, headers=CHROME_HEADERS, timeout_s=30)
        if status // 100 != 2:
            raise RuntimeError(f"Falha ao buscar {url} (status={status})")
        return body.decode("utf-8", errors="replace")


def guess_game_name_from_container(container: Any) -> str | None:
    try:
        for tag_name in ("h1", "h2", "h3", "h4", "strong"):
            t = container.find(tag_name)
            if t:
                val = normalize_ws(t.get_text(" ", strip=True))
                if 3 <= len(val) <= 80 and "active" not in val.lower():
                    return val
    except Exception:
        pass

    try:
        for a in container.find_all("a"):
            val = normalize_ws(a.get_text(" ", strip=True))
            if 3 <= len(val) <= 80 and "active" not in val.lower() and "drops" not in val.lower():
                return val
    except Exception:
        pass
    return None


def extract_active_drops_from_table(html_text: str) -> list[Drop]:
    from bs4 import BeautifulSoup  # type: ignore

    soup = BeautifulSoup(html_text, "html.parser")
    now = int(time.time())
    drops: list[Drop] = []

    for table in soup.find_all("table"):
        header_cells = table.find_all("th")
        headers = [normalize_ws(h.get_text(" ", strip=True)).lower() for h in header_cells]
        if not headers:
            continue

        def find_col(*needles: str) -> int | None:
            for i, h in enumerate(headers):
                for n in needles:
                    if n in h:
                        return i
            return None

        game_i = find_col("game", "jogo")
        status_i = find_col("status")
        date_i = find_col("date", "data", "end", "until", "expires")
        if game_i is None or status_i is None or date_i is None:
            continue

        for tr in table.find_all("tr"):
            tds = tr.find_all(["td", "th"])
            if len(tds) <= max(game_i, status_i, date_i):
                continue

            game = normalize_ws(tds[game_i].get_text(" ", strip=True))
            status = normalize_ws(tds[status_i].get_text(" ", strip=True))
            date_text = normalize_ws(tds[date_i].get_text(" ", strip=True))

            if not game:
                continue
            if "active" not in status.lower():
                continue

            expires_at = parse_date_to_epoch_seconds(date_text)
            if expires_at is None or expires_at <= now:
                continue

            item = "Active"
            drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
            drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))

    return drops


def extract_active_drops_from_cards(html_text: str) -> list[Drop]:
    from bs4 import BeautifulSoup  # type: ignore

    soup = BeautifulSoup(html_text, "html.parser")
    now = int(time.time())
    drops: list[Drop] = []

    date_pat = re.compile(
        r"(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?"
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})",
        flags=re.IGNORECASE,
    )

    for node in soup.find_all(string=re.compile(r"\bactive\b", flags=re.IGNORECASE)):
        container = getattr(node, "find_parent", lambda *_: None)(["tr", "article", "li", "div"])
        if not container:
            continue

        text = normalize_ws(container.get_text(" ", strip=True))
        if "active" not in text.lower():
            continue

        m = date_pat.search(text)
        if not m:
            continue
        expires_at = parse_date_to_epoch_seconds(m.group(1))
        if expires_at is None or expires_at <= now:
            continue

        game = guess_game_name_from_container(container)
        if not game:
            continue

        item = "Active"
        drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
        drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))

    dedup: dict[str, Drop] = {}
    for d in drops:
        dedup[d.drop_id] = d
    return list(dedup.values())


def fetch_active_drops_from_twitchdrops_net() -> list[Drop]:
    html_text = fetch_html(TWITCHDROPS_NET_URL)
    drops = extract_active_drops_from_table(html_text)
    if drops:
        return drops

    drops = extract_active_drops_from_cards(html_text)
    if drops:
        return drops

    html_text = fetch_html(TWITCHDROPS_NET_GAMES_URL)
    drops = extract_active_drops_from_table(html_text)
    if drops:
        return drops
    drops = extract_active_drops_from_cards(html_text)
    if drops:
        return drops

    raise RuntimeError("Não foi possível extrair drops ativos do TwitchDrops.net")


def fetch_active_drops_from_tracker_gg() -> list[Drop]:
    html_text = fetch_html(TRACKER_GG_TWITCH_DROPS_URL)
    drops = extract_active_drops_from_table(html_text)
    if drops:
        return drops
    drops = extract_active_drops_from_cards(html_text)
    if drops:
        return drops
    raise RuntimeError("Não foi possível extrair drops ativos do tracker.gg")


def fetch_active_drops() -> list[Drop]:
    try:
        return fetch_active_drops_from_twitchdrops_net()
    except Exception:
        return fetch_active_drops_from_tracker_gg()


def ensure_wait_true(webhook_url: str) -> str:
    parsed = urllib.parse.urlparse(webhook_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query["wait"] = ["true"]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def discord_webhook_post_message(webhook_url: str, embed: dict[str, Any]) -> dict[str, Any]:
    url = ensure_wait_true(webhook_url)
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    status, _, resp = http_request(
        "POST",
        url,
        headers={"Content-Type": "application/json"},
        body=body,
    )
    if status // 100 != 2:
        raise RuntimeError(f"Falha ao postar no webhook (status={status}) {resp[:400]!r}")
    try:
        return json.loads(resp.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Resposta inválida do webhook: {e}") from e


def discord_bot_delete_message(bot_token: str, channel_id: str, message_id: str) -> int:
    url = f"{DISCORD_API_BASE}/channels/{channel_id}/messages/{message_id}"
    status, _, _ = http_request(
        "DELETE",
        url,
        headers={"Authorization": f"Bot {bot_token}"},
    )
    return status


def build_embed(drop: Drop) -> dict[str, Any]:
    return {
        "title": drop.game,
        "description": f"{drop.item}\nExpira <t:{drop.expires_at}:R>",
        "color": 0x9146FF,
    }


def load_active_drops_from_env() -> dict[str, Any]:
    raw = (os.getenv("ACTIVE_DROPS") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def load_active_drops_from_file(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        return {}
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def normalize_active_drops(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            continue
        msg_id = v.get("message_id")
        ch_id = v.get("channel_id")
        exp = v.get("expires_at")
        if not isinstance(msg_id, str) or not msg_id.strip():
            continue
        if not isinstance(ch_id, str) or not ch_id.strip():
            continue
        if not isinstance(exp, int):
            continue
        out[k] = {
            "message_id": msg_id.strip(),
            "channel_id": ch_id.strip(),
            "expires_at": exp,
            "game": v.get("game"),
            "item": v.get("item"),
        }
    return out


def dump_active_drops_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--output-json", default=None)
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args()

    webhook_url = (os.getenv("WEBHOOK_DROPS_URL") or "").strip()
    bot_token = (os.getenv("DISCORD_BOT_TOKEN") or "").strip()
    if not webhook_url:
        print("WEBHOOK_DROPS_URL não definido.", file=sys.stderr)
        return 2
    if not bot_token:
        print("DISCORD_BOT_TOKEN não definido.", file=sys.stderr)
        return 2

    active_raw = load_active_drops_from_env()
    if not active_raw:
        active_raw = load_active_drops_from_file(args.state_file)
    active = normalize_active_drops(active_raw)

    now = int(time.time())
    scrape_ok = True
    try:
        scraped = fetch_active_drops()
    except Exception as e:
        scrape_ok = False
        scraped = []
        print(f"Scraping falhou: {e}", file=sys.stderr)
        if (os.getenv("GITHUB_ACTIONS") or "").lower() == "true":
            return 3

    scraped_by_id = {d.drop_id: d for d in scraped}
    scraped_ids = set(scraped_by_id.keys())

    deleted = 0
    kept = 0
    to_delete = []
    for drop_id, entry in active.items():
        expires_at = int(entry["expires_at"])
        expired_by_time = expires_at <= now
        expired_by_missing = scrape_ok and (drop_id not in scraped_ids)
        if expired_by_time or expired_by_missing:
            to_delete.append((drop_id, entry))
        else:
            kept += 1

    for drop_id, entry in to_delete:
        status = discord_bot_delete_message(
            bot_token=bot_token,
            channel_id=str(entry["channel_id"]),
            message_id=str(entry["message_id"]),
        )
        if status in (200, 204, 404):
            deleted += 1
            active.pop(drop_id, None)
        else:
            print(f"Falha ao deletar mensagem {entry['message_id']} (status={status})", file=sys.stderr)

    posted = 0
    for drop_id, drop in scraped_by_id.items():
        if drop_id in active:
            continue
        embed = build_embed(drop)
        msg = discord_webhook_post_message(webhook_url=webhook_url, embed=embed)
        message_id = msg.get("id")
        channel_id = msg.get("channel_id")
        if not isinstance(message_id, str) or not message_id.strip():
            raise RuntimeError(f"Webhook não retornou message_id: {msg}")
        if not isinstance(channel_id, str) or not channel_id.strip():
            raise RuntimeError(f"Webhook não retornou channel_id: {msg}")
        active[drop_id] = {
            "message_id": message_id,
            "channel_id": channel_id,
            "expires_at": drop.expires_at,
            "game": drop.game,
            "item": drop.item,
        }
        posted += 1

    updated_json = dump_active_drops_json(active)
    output_path = args.output_json or args.state_file
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(updated_json)

    if args.json_only:
        print(updated_json)
    else:
        print(
            json.dumps(
                {
                    "scrape_ok": scrape_ok,
                    "scraped": len(scraped),
                    "posted": posted,
                    "deleted": deleted,
                    "kept": kept,
                    "active_total": len(active),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
