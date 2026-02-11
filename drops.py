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
        scraped = list(scrape_twitch_drops(oauth_token))
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
