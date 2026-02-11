import argparse
import json
import os
import sys
import random
import string
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

TWITCH_GQL_URL = "https://gql.twitch.tv/gql"
TWITCH_WEB_CLIENT_ID = "kimne78kx3ncx6brgo4mv6wki5h1ko"
DISCORD_API_BASE = "https://discord.com/api/v10"
DEFAULT_STATE_FILE = "active_drops.json"
PLAYWRIGHT_DROPS_URL = "https://www.twitch.tv/drops"
PLAYWRIGHT_DEFAULT_WAIT_MS = 8000
PLAYWRIGHT_MAX_GQL_RESPONSES = 25

# QUERY GLOBAL: Usa o schema que lista TODAS as campanhas ativas na plataforma
GLOBAL_DROPS_QUERY = """
query {
  allDropCampaigns {
    id
    name
    status
    endAt
    game {
      id
      displayName
    }
    timeBasedDrops {
      id
      benefitEdges {
        benefit {
          name
        }
      }
    }
  }
}
""".strip()

CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

@dataclass
class Drop:
    id: str
    game: str
    item: str
    expires_at: str

def build_stealth_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.twitch.tv/"
    }

def build_launch_args(ci_mode: bool) -> list[str]:
    args = [
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-breakpad",
        "--disable-default-apps",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-service-autorun",
        "--disable-sync",
        "--disable-features=IsolateOrigins,site-per-process"
    ]
    if ci_mode:
        args.append("--no-sandbox")
    return args

def scrape_twitch_drops_playwright(
    headless: bool,
    block_resources: bool,
    user_agent: str,
    wait_ms: int,
    max_gql_responses: int,
    ci_mode: bool
) -> Iterable[Drop]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return []
    drops: list[Drop] = []
    seen_ids: set[str] = set()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=build_launch_args(ci_mode))
        context = browser.new_context(
            user_agent=user_agent,
            viewport={"width": 1280, "height": 720},
            extra_http_headers=build_stealth_headers()
        )
        page = context.new_page()
        if block_resources:
            def route_handler(route):
                rt = route.request.resource_type
                if rt in ("image", "media", "font"):
                    route.abort()
                else:
                    route.continue_()
            page.route("**/*", route_handler)
        gql_payloads: list[Any] = []
        def on_response(response):
            url = response.url
            if "gql.twitch.tv/gql" in url and response.request.method == "POST":
                try:
                    if len(gql_payloads) >= max_gql_responses:
                        return
                    gql_payloads.append(response.json())
                except Exception:
                    pass
        page.on("response", on_response)
        try:
            page.goto(PLAYWRIGHT_DROPS_URL, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(wait_ms)
        except Exception:
            pass
        campaigns: list[dict] = []
        def extract(obj: Any):
            if isinstance(obj, list):
                for it in obj:
                    extract(it)
            elif isinstance(obj, dict):
                data = obj.get("data") or {}
                if isinstance(data, dict) and "allDropCampaigns" in data:
                    vals = data.get("allDropCampaigns") or []
                    if isinstance(vals, list):
                        campaigns.extend(vals)
        for payload in gql_payloads:
            extract(payload)
        for campaign in campaigns:
            if campaign.get("status") != "ACTIVE":
                continue
            game_name = (campaign.get("game") or {}).get("displayName") or "Jogo Desconhecido"
            expires_at = campaign.get("endAt")
            for d in campaign.get("timeBasedDrops") or []:
                drop_id = d.get("id")
                item_name = "Recompensa de Drop"
                benefits = d.get("benefitEdges") or []
                if benefits:
                    b = (benefits[0] or {}).get("benefit") or {}
                    item_name = b.get("name") or item_name
                if drop_id and expires_at and drop_id not in seen_ids:
                    drops.append(Drop(id=drop_id, game=game_name, item=item_name, expires_at=expires_at))
                    seen_ids.add(drop_id)
        try:
            context.close()
            browser.close()
        except Exception:
            pass
    return drops

def twitch_gql_request(query: str, oauth_token: str) -> dict:
    headers = {
        "Client-Id": TWITCH_WEB_CLIENT_ID,
        "User-Agent": CHROME_USER_AGENT,
        "Content-Type": "application/json",
        "X-Device-Id": ''.join(random.choices(string.ascii_lowercase + string.digits, k=32)),
    }
    # Se tivermos o token, enviamos, mas para queries globais ele é menos crítico
    if oauth_token:
        headers["Authorization"] = f"OAuth {oauth_token}"
    
    req = urllib.request.Request(
        TWITCH_GQL_URL,
        data=json.dumps({"query": query}).encode("utf-8"),
        headers=headers,
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def scrape_twitch_drops_resilient(
    oauth_token: str,
    use_playwright: bool,
    headless: bool,
    block_resources: bool,
    user_agent: str,
    wait_ms: int,
    max_gql_responses: int,
    ci_mode: bool
) -> Iterable[Drop]:
    if use_playwright:
        primary = list(scrape_twitch_drops_playwright(
            headless=headless,
            block_resources=block_resources,
            user_agent=user_agent,
            wait_ms=wait_ms,
            max_gql_responses=max_gql_responses,
            ci_mode=ci_mode
        ))
        if primary:
            return primary
    return list(scrape_twitch_drops(oauth_token))

def scrape_twitch_drops(oauth_token: str) -> Iterable[Drop]:
    try:
        data = twitch_gql_request(GLOBAL_DROPS_QUERY, oauth_token)
        
        if "errors" in data:
            # Se a query global falhar, o log nos dirá o porquê
            raise RuntimeError(f"Twitch GQL Erro: {data['errors']}")
        
        campaigns = data.get("data", {}).get("allDropCampaigns") or []
        
        for campaign in campaigns:
            # Filtramos apenas campanhas ativas (ACTIVE)
            if campaign.get("status") != "ACTIVE":
                continue

            game_name = campaign.get("game", {}).get("displayName", "Jogo Desconhecido")
            expires_at = campaign.get("endAt")
            
            for d in campaign.get("timeBasedDrops", []):
                drop_id = d.get("id")
                item_name = "Recompensa de Drop"
                
                benefits = d.get("benefitEdges", [])
                if benefits and len(benefits) > 0:
                    b = benefits[0].get("benefit")
                    if b:
                        item_name = b.get("name", item_name)

                yield Drop(id=drop_id, game=game_name, item=item_name, expires_at=expires_at)
    except Exception as e:
        raise RuntimeError(f"Scraping falhou: {e}")

def discord_api_delete_message(token: str, channel_id: str, message_id: str):
    req = urllib.request.Request(
        f"{DISCORD_API_BASE}/channels/{channel_id}/messages/{message_id}",
        method="DELETE",
        headers={"Authorization": f"Bot {token}"},
    )
    try:
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"Erro ao deletar: {e}")

def discord_webhook_post_message(webhook_url: str, embed: dict) -> dict:
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps({"embeds": [embed]}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--use-playwright", action=argparse.BooleanOptionalAction, default=os.getenv("USE_PLAYWRIGHT") == "1")
    parser.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--block-resources", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--gql-wait-ms", type=int, default=PLAYWRIGHT_DEFAULT_WAIT_MS)
    parser.add_argument("--gql-max-responses", type=int, default=PLAYWRIGHT_MAX_GQL_RESPONSES)
    parser.add_argument("--ci", action=argparse.BooleanOptionalAction, default=os.getenv("GITHUB_ACTIONS") == "true")
    parser.add_argument("--user-agent", default=CHROME_USER_AGENT)
    args = parser.parse_args()

    webhook_url = os.getenv("WEBHOOK_DROPS_URL")
    bot_token = os.getenv("DISCORD_BOT_TOKEN")
    oauth_token = os.getenv("TWITCH_OAUTH_TOKEN")

    if os.path.exists(args.state_file):
        with open(args.state_file, "r", encoding="utf-8") as f:
            try: active = json.load(f)
            except: active = {}
    else: active = {}

    scraped = []
    scrape_ok = True
    try:
        scraped = list(scrape_twitch_drops_resilient(
            oauth_token=oauth_token,
            use_playwright=args.use_playwright,
            headless=args.headless,
            block_resources=args.block_resources,
            user_agent=args.user_agent,
            wait_ms=args.gql_wait_ms,
            max_gql_responses=args.gql_max_responses,
            ci_mode=args.ci
        ))
    except Exception as e:
        print(f"{e}", file=sys.stderr)
        scrape_ok = False

    now = datetime.now(timezone.utc)
    scraped_ids = {d.id for d in scraped}
    to_remove = []

    # Deletar expirados
    for drop_id, info in active.items():
        try:
            expiry = datetime.fromisoformat(info["expires_at"].replace("Z", "+00:00"))
            if expiry < now:
                discord_api_delete_message(bot_token, info["channel_id"], info["message_id"])
                to_remove.append(drop_id)
        except: to_remove.append(drop_id)

    for r in to_remove: active.pop(r, None)

    # Postar novos
    posted = 0
    for drop in scraped:
        if drop.id in active: continue
        try:
            embed = {
                "title": f"🌍 Drop Global: {drop.game}",
                "description": f"**Item:** {drop.item}\n**Expira em:** {drop.expires_at}",
                "color": 0x00ff00,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            msg = discord_webhook_post_message(webhook_url, embed)
            if msg and "id" in msg:
                active[drop.id] = {
                    "message_id": msg["id"],
                    "channel_id": msg["channel_id"],
                    "expires_at": drop.expires_at
                }
                posted += 1
        except: pass

    with open(args.state_file, "w", encoding="utf-8") as f:
        json.dump(active, f, indent=2, ensure_ascii=False)

    print(json.dumps({"status": "ok" if scrape_ok else "failed", "found": len(scraped), "new": posted}))

if __name__ == "__main__":
    main()
