import argparse
import gzip
import hashlib
import json
import os
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
DISCORD_API_BASE = "https://discord.com/api/v10"
DEFAULT_STATE_FILE = "active_drops.json"

# QUERY ATUALIZADA: Removido currentUser para busca global e corrigido campos de benefício
VIEWER_DROPS_DASHBOARD_QUERIES = [
    """
query GlobalDrops {
  dropCampaigns(filter: ACTIVE) {
    id
    name
    endAt
    game {
      id
      displayName
    }
    timeBasedDrops {
      id
      benefitEdges {
        node {
          name
        }
      }
    }
  }
}
""".strip(),
    """
query GlobalDropsFallback {
  dropCampaigns {
    id
    name
    endAt
    game {
      displayName
    }
    timeBasedDrops {
      id
    }
  }
}
""".strip()
]

CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

@dataclass
class Drop:
    id: str
    game: str
    item: str
    expires_at: str

def twitch_gql_request(query: str, oauth_token: str) -> dict:
    req = urllib.request.Request(
        TWITCH_GQL_URL,
        data=json.dumps({"query": query}).encode("utf-8"),
        headers={
            "Client-Id": TWITCH_WEB_CLIENT_ID,
            "Authorization": f"OAuth {oauth_token}",
            "User-Agent": CHROME_USER_AGENT,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def scrape_twitch_drops(oauth_token: str) -> Iterable[Drop]:
    errors = []
    for query in VIEWER_DROPS_DASHBOARD_QUERIES:
        try:
            data = twitch_gql_request(query, oauth_token)
            if "errors" in data:
                errors.append(data["errors"])
                continue
            
            # Ajuste para ler campanhas globais ou de usuário
            campaigns = data.get("data", {}).get("dropCampaigns") or \
                        data.get("data", {}).get("currentUser", {}).get("dropCampaigns")
            
            if not campaigns:
                continue

            for campaign in campaigns:
                game_name = campaign.get("game", {}).get("displayName") or campaign.get("game", {}).get("name", "Unknown Game")
                expires_at = campaign.get("endAt")
                
                for d in campaign.get("timeBasedDrops", []):
                    drop_id = d.get("id")
                    # Tenta pegar o nome do item de diferentes estruturas
                    item_name = "Recompensa de Drop"
                    benefits = d.get("benefitEdges", [])
                    if benefits and isinstance(benefits, list):
                        item_name = benefits[0].get("node", {}).get("name", item_name)
                    elif d.get("benefit"):
                        item_name = d.get("benefit", {}).get("name", item_name)

                    yield Drop(id=drop_id, game=game_name, item=item_name, expires_at=expires_at)
            return
        except Exception as e:
            errors.append(str(e))
    
    raise RuntimeError(f"Scraping falhou: {errors}")

def discord_api_delete_message(token: str, channel_id: str, message_id: str):
    req = urllib.request.Request(
        f"{DISCORD_API_BASE}/channels/{channel_id}/messages/{message_id}",
        method="DELETE",
        headers={"Authorization": f"Bot {token}", "User-Agent": "TwitchDropsBot/1.0"},
    )
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"Erro ao deletar mensagem {message_id}: {e}")

def discord_webhook_post_message(webhook_url: str, embed: dict) -> dict:
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps({"embeds": [embed]}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "TwitchDropsBot/1.0"},
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def build_embed(drop: Drop) -> dict:
    return {
        "title": f"Novo Drop Disponível: {drop.game}",
        "description": f"**Item:** {drop.item}\n**Expira em:** {drop.expires_at}",
        "color": 0x9146FF,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def load_active_drops(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def dump_active_drops_json(active: dict) -> str:
    return json.dumps(active, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--output-json", help="Caminho para salvar o novo estado")
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args()

    webhook_url = os.getenv("WEBHOOK_DROPS_URL")
    bot_token = os.getenv("DISCORD_BOT_TOKEN")
    oauth_token = os.getenv("TWITCH_OAUTH_TOKEN")

    active = load_active_drops(args.state_file)
    scraped = []
    scrape_ok = True

    try:
        scraped = list(scrape_twitch_drops(oauth_token))
    except Exception as e:
        print(f"Falha no Scraping: {e}", file=sys.stderr)
        scrape_ok = False

    now = datetime.now(timezone.utc)
    scraped_ids = {d.id for d in scraped}
    
    deleted = 0
    kept = 0
    to_remove = []

    # Verificar o que precisa ser deletado (expirados ou que sumiram da Twitch)
    for drop_id, info in active.items():
        try:
            expiry = datetime.fromisoformat(info["expires_at"].replace("Z", "+00:00"))
            if expiry < now or (scrape_ok and drop_id not in scraped_ids):
                discord_api_delete_message(bot_token, info["channel_id"], info["message_id"])
                to_remove.append(drop_id)
                deleted += 1
            else:
                kept += 1
        except Exception:
            to_remove.append(drop_id)

    for r in to_remove:
        active.pop(r, None)

    # Postar novos drops
    posted = 0
    for drop in scraped:
        if drop.id in active:
            continue
        
        embed = build_embed(drop)
        try:
            msg = discord_webhook_post_message(webhook_url, embed)
            active[drop.id] = {
                "message_id": msg["id"],
                "channel_id": msg["channel_id"],
                "expires_at": drop.expires_at,
                "game": drop.game,
                "item": drop.item
            }
            posted += 1
        except Exception as e:
            print(f"Erro ao postar drop {drop.id}: {e}")

    updated_json = dump_active_drops_json(active)
    with open(args.state_file, "w", encoding="utf-8") as f:
        f.write(updated_json)

    print(json.dumps({
        "scrape_ok": scrape_ok,
        "scraped": len(scraped),
        "posted": posted,
        "deleted": deleted,
        "active_total": len(active)
    }))

if __name__ == "__main__":
    main()
