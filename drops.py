import argparse
import gzip
import hashlib
import html
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
from typing import Any, Iterable


TWITCH_GQL_URL = "https://gql.twitch.tv/gql"
TWITCH_WEB_CLIENT_ID = "kimne78kx3ncx6brgo4mv6wki5h1ko"
TWITCH_DROPS_CAMPAIGNS_URL = "https://www.twitch.tv/drops/campaigns"
TWITCH_DROPS_INVENTORY_URL = "https://www.twitch.tv/drops/inventory"
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


class AuthRequiredError(RuntimeError):
    pass


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


def iter_nodes(node: Any) -> Iterable[Any]:
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from iter_nodes(v)
    elif isinstance(node, list):
        yield node
        for it in node:
            yield from iter_nodes(it)


def pick_first_str(d: Any, keys: Iterable[str]) -> str | None:
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def extract_item_names_from_reward(reward: Any) -> list[str]:
    names: list[str] = []
    direct = pick_first_str(reward, ("name", "displayName", "title"))
    if direct:
        names.append(direct)

    if isinstance(reward, dict):
        benefit = reward.get("benefit")
        if isinstance(benefit, dict):
            n = pick_first_str(benefit, ("name", "displayName", "title"))
            if n:
                names.append(n)
        benefits = reward.get("benefits")
        if isinstance(benefits, list):
            for b in benefits:
                n = pick_first_str(b, ("name", "displayName", "title"))
                if n:
                    names.append(n)
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            out.append(n)
            seen.add(n)
    return out


def extract_campaign_reward_items(campaign: dict[str, Any]) -> list[str]:
    items: list[str] = []
    for key in ("timeBasedDrops", "drops", "rewards", "benefits"):
        v = campaign.get(key)
        if isinstance(v, list):
            for entry in v:
                items.extend(extract_item_names_from_reward(entry))

    if not items:
        fallback = pick_first_str(campaign, ("name", "displayName", "title"))
        if fallback:
            items.append(fallback)

    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            out.append(it)
            seen.add(it)
    return out


def extract_campaign_end_at(campaign: dict[str, Any]) -> int | None:
    for key in ("endAt", "endTime", "endsAt", "endDate", "expiresAt"):
        v = campaign.get(key)
        if isinstance(v, str):
            ts = parse_iso8601_to_epoch_seconds(v)
            if ts is not None:
                return ts
        if isinstance(v, (int, float)) and v > 0:
            if v > 10_000_000_000:
                return int(v // 1000)
            return int(v)
    return None


def extract_campaign_game_name(campaign: dict[str, Any]) -> str:
    game = campaign.get("game")
    if isinstance(game, dict):
        name = pick_first_str(game, ("displayName", "name", "title"))
        if name:
            return name
    direct = pick_first_str(campaign, ("gameName", "gameTitle"))
    if direct:
        return direct
    return "Twitch Drops"


def extract_next_data_json(html_text: str) -> dict[str, Any] | None:
    raw: str | None = None
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html_text, "html.parser")
        tag = soup.find("script", attrs={"id": "__NEXT_DATA__"})
        if tag:
            raw = tag.string or tag.get_text()
    except Exception:
        raw = None

    if raw is None:
        m = re.search(
            r'<script[^>]*id="__NEXT_DATA__"[^>]*type="application/json"[^>]*>(?P<json>.*?)</script>',
            html_text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if not m:
            return None
        raw = m.group("json")

    raw = html.unescape(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data
    return None


def find_best_campaign_list(root: Any) -> list[dict[str, Any]]:
    candidates: list[list[dict[str, Any]]] = []
    for node in iter_nodes(root):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in {"campaigns", "activecampaigns"} and isinstance(v, list):
                    if v and all(isinstance(x, dict) for x in v):
                        candidates.append([x for x in v if isinstance(x, dict)])
        if isinstance(node, list) and node and all(isinstance(x, dict) for x in node):
            sample = node[0]
            if isinstance(sample, dict) and ("game" in sample) and (
                ("endAt" in sample) or ("endTime" in sample) or ("endsAt" in sample)
            ):
                candidates.append([x for x in node if isinstance(x, dict)])

    if not candidates:
        return []

    candidates.sort(key=lambda xs: len(xs), reverse=True)
    return candidates[0]


def twitch_gql_post(operations: list[dict[str, Any]], oauth_token: str | None) -> Any:
    headers = {
        "Client-ID": TWITCH_WEB_CLIENT_ID,
        "Client-Id": TWITCH_WEB_CLIENT_ID,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "User-Agent": CHROME_HEADERS["User-Agent"],
    }
    if oauth_token:
        headers["Authorization"] = f"OAuth {oauth_token}"

    status, _, body = http_request(
        "POST",
        TWITCH_GQL_URL,
        headers=headers,
        body=json.dumps(operations, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        timeout_s=30,
    )
    if status in (401, 403):
        raise AuthRequiredError(f"GQL retornou status={status}")
    if status // 100 != 2:
        snippet = body[:800].decode("utf-8", errors="replace")
        raise RuntimeError(f"Falha ao chamar Twitch GQL (status={status}) body={snippet!r}")

    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Resposta inválida do Twitch GQL: {e}") from e
    return parsed


def find_best_drop_campaigns_list(root: Any) -> list[dict[str, Any]]:
    candidates: list[list[dict[str, Any]]] = []
    for node in iter_nodes(root):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in {"dropcampaigns", "campaigns"} and isinstance(v, list):
                    if v and all(isinstance(x, dict) for x in v):
                        candidates.append([x for x in v if isinstance(x, dict)])
    if not candidates:
        return []
    candidates.sort(key=lambda xs: len(xs), reverse=True)
    return candidates[0]


def extract_campaign_benefit_names_gql(campaign: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for node in iter_nodes(campaign):
        if not isinstance(node, dict):
            continue
        benefit = node.get("benefit")
        if isinstance(benefit, dict):
            n = pick_first_str(benefit, ("name",))
            if n:
                names.append(n)
    if not names:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            out.append(n)
            seen.add(n)
    return out


def fetch_active_drops_from_twitch_gql() -> list[Drop]:
    oauth_token = (os.getenv("TWITCH_OAUTH_TOKEN") or os.getenv("TWITCH_AUTH_TOKEN") or "").strip() or None
    query_variants = [
        (
            "ViewerDropsDashboard",
            """query ViewerDropsDashboard {
  viewer {
    dropCampaigns {
      endAt
      game { displayName }
      timeBasedDrops { benefit { name } }
    }
  }
}""",
        ),
        (
            "ViewerDropsDashboard",
            """query ViewerDropsDashboard {
  dropCampaigns {
    endAt
    game { displayName }
    timeBasedDrops { benefit { name } }
  }
}""",
        ),
        (
            "ViewerDropsDashboard",
            """query ViewerDropsDashboard {
  viewer {
    dropCampaigns {
      endAt
      game { displayName }
      drops { benefit { name } }
    }
  }
}""",
        ),
    ]

    last_error: Exception | None = None
    for operation_name, query in query_variants:
        operations = [{"operationName": operation_name, "variables": {}, "query": query}]
        try:
            resp = twitch_gql_post(operations=operations, oauth_token=oauth_token)
        except AuthRequiredError as e:
            raise
        except Exception as e:
            last_error = e
            continue

        entry = resp[0] if isinstance(resp, list) and resp else resp
        if isinstance(entry, dict) and entry.get("errors"):
            errors = entry.get("errors")
            if isinstance(errors, list):
                joined = " | ".join(str(e.get("message")) for e in errors if isinstance(e, dict))
                if "unauth" in joined.lower() or "forbidden" in joined.lower():
                    raise AuthRequiredError(joined)
                raise RuntimeError(joined)
            raise RuntimeError(f"Twitch GQL retornou errors: {errors}")

        data = entry.get("data") if isinstance(entry, dict) else None
        if not data:
            last_error = RuntimeError("Twitch GQL sem data")
            continue

        campaigns = find_best_drop_campaigns_list(data)
        if not campaigns:
            last_error = RuntimeError("Não foi possível localizar dropCampaigns no payload GQL")
            continue

        now = int(time.time())
        drops: list[Drop] = []
        for campaign in campaigns:
            if not isinstance(campaign, dict):
                continue
            game = extract_campaign_game_name(campaign)
            expires_at = extract_campaign_end_at(campaign)
            if expires_at is None or expires_at <= now:
                continue
            items = extract_campaign_benefit_names_gql(campaign)
            if not items:
                continue
            for item in items:
                drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
                drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))
        if drops:
            return drops

    if last_error:
        raise last_error
    raise RuntimeError("Twitch GQL falhou")


def fetch_twitch_campaigns_html() -> str:
    try:
        import cloudscraper  # type: ignore

        scraper = cloudscraper.create_scraper()
        resp = scraper.get(TWITCH_DROPS_CAMPAIGNS_URL, headers=CHROME_HEADERS, timeout=30)
        if int(resp.status_code) // 100 != 2:
            raise RuntimeError(f"Falha ao buscar Twitch Drops (status={resp.status_code})")
        return resp.text
    except Exception:
        status, _, body = http_request(
            "GET",
            TWITCH_DROPS_CAMPAIGNS_URL,
            headers=CHROME_HEADERS,
            timeout_s=30,
        )
        if status // 100 != 2:
            raise RuntimeError(f"Falha ao buscar Twitch Drops (status={status})")
        return body.decode("utf-8", errors="replace")


def fetch_twitch_inventory_html() -> str:
    try:
        import cloudscraper  # type: ignore

        scraper = cloudscraper.create_scraper()
        resp = scraper.get(TWITCH_DROPS_INVENTORY_URL, headers=CHROME_HEADERS, timeout=30)
        if int(resp.status_code) // 100 != 2:
            raise RuntimeError(f"Falha ao buscar Twitch Drops Inventory (status={resp.status_code})")
        return resp.text
    except Exception:
        status, _, body = http_request(
            "GET",
            TWITCH_DROPS_INVENTORY_URL,
            headers=CHROME_HEADERS,
            timeout_s=30,
        )
        if status // 100 != 2:
            raise RuntimeError(f"Falha ao buscar Twitch Drops Inventory (status={status})")
        return body.decode("utf-8", errors="replace")


def fetch_active_drops_from_twitch_inventory_html() -> list[Drop]:
    text = fetch_twitch_inventory_html()
    next_data = extract_next_data_json(text)
    if not next_data:
        raise RuntimeError("Não foi possível extrair __NEXT_DATA__ do Drops Inventory")

    campaigns = find_best_campaign_list(next_data)
    if not campaigns:
        raise RuntimeError("Não foi possível localizar campanhas no Drops Inventory")

    now = int(time.time())
    drops: list[Drop] = []
    for campaign in campaigns:
        if not isinstance(campaign, dict):
            continue
        expires_at = extract_campaign_end_at(campaign)
        if expires_at is None or expires_at <= now:
            continue
        game = extract_campaign_game_name(campaign)
        items = extract_campaign_reward_items(campaign)
        if not items:
            continue
        for item in items:
            drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
            drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))

    return drops


def fetch_active_drops_from_twitch_html() -> list[Drop]:
    text = fetch_twitch_campaigns_html()
    next_data = extract_next_data_json(text)
    if not next_data:
        raise RuntimeError("Não foi possível extrair __NEXT_DATA__ da Twitch")

    campaigns = find_best_campaign_list(next_data)
    if not campaigns:
        raise RuntimeError("Não foi possível localizar campanhas de drops no payload")

    now = int(time.time())
    drops: list[Drop] = []
    for campaign in campaigns:
        if not isinstance(campaign, dict):
            continue
        expires_at = extract_campaign_end_at(campaign)
        if expires_at is None or expires_at <= now:
            continue
        game = extract_campaign_game_name(campaign)
        items = extract_campaign_reward_items(campaign)
        if not items:
            continue
        for item in items:
            drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
            drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))

    return drops


def fetch_active_drops_from_twitchdrops_net() -> list[Drop]:
    status, _, body = http_request(
        "GET",
        "https://www.twitchdrops.net/games",
        headers=CHROME_HEADERS,
        timeout_s=30,
    )
    if status // 100 != 2:
        raise RuntimeError(f"Falha ao buscar TwitchDrops.net (status={status})")

    text = body.decode("utf-8", errors="replace")
    next_data = extract_next_data_json(text)
    root: Any = next_data if next_data is not None else text

    candidates = find_best_campaign_list(root) if next_data is not None else []
    if not candidates and isinstance(root, str):
        links = re.findall(r'href="(/drops/[^"]+)"', root, flags=re.IGNORECASE)
        seen_links: list[str] = []
        seen_set: set[str] = set()
        for l in links:
            if l not in seen_set:
                seen_set.add(l)
                seen_links.append(l)

        for path in seen_links[:8]:
            status2, _, body2 = http_request(
                "GET",
                urllib.parse.urljoin("https://www.twitchdrops.net", path),
                headers=CHROME_HEADERS,
                timeout_s=30,
            )
            if status2 // 100 != 2:
                continue
            page = body2.decode("utf-8", errors="replace")
            nd = extract_next_data_json(page)
            if nd is None:
                continue
            candidates = find_best_campaign_list(nd)
            if candidates:
                break

    if not candidates:
        raise RuntimeError("Fallback TwitchDrops.net não expôs campanhas de forma detectável")

    now = int(time.time())
    drops: list[Drop] = []
    for campaign in candidates:
        if not isinstance(campaign, dict):
            continue
        expires_at = extract_campaign_end_at(campaign)
        if expires_at is None or expires_at <= now:
            continue
        game = extract_campaign_game_name(campaign)
        items = extract_campaign_reward_items(campaign)
        if not items:
            items = extract_campaign_benefit_names_gql(campaign)
        if not items:
            continue
        for item in items:
            drop_id = stable_drop_id(game=game, item=item, expires_at=expires_at)
            drops.append(Drop(drop_id=drop_id, game=game, item=item, expires_at=expires_at))

    if not drops:
        raise RuntimeError("Fallback TwitchDrops.net não retornou drops ativos")
    return drops


def fetch_active_drops_from_twitch() -> list[Drop]:
    try:
        return fetch_active_drops_from_twitch_gql()
    except AuthRequiredError:
        pass
    try:
        return fetch_active_drops_from_twitch_inventory_html()
    except Exception:
        pass
    try:
        return fetch_active_drops_from_twitch_html()
    except Exception:
        return fetch_active_drops_from_twitchdrops_net()


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
        scraped = fetch_active_drops_from_twitch()
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
