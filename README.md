# bot-twitch-drops

Bot que coleta Twitch Drops ativos e publica no Discord.

**Como funciona**
- Busca campanhas de Drops (via Twitch GQL quando possível; fallback para HTML).
- Para cada item de drop ativo, posta uma embed no Discord via webhook.
- Mantém `active_drops.json` com `message_id`/`channel_id` para conseguir deletar mensagens expiradas.
- Um workflow roda a cada 30 minutos e comita `active_drops.json` quando houver mudança.

## Secrets necessários (GitHub Actions)
- `WEBHOOK_DROPS_URL`: URL do webhook do canal
- `DISCORD_BOT_TOKEN`: token do bot que tem permissão de deletar mensagens no canal

### Recomendado (evita bloqueios da Twitch)
- `TWITCH_OAUTH_TOKEN`: token OAuth de uma conta Twitch (viewer)

Sem `TWITCH_OAUTH_TOKEN`, a Twitch pode bloquear scraping e o workflow vai falhar (para você perceber e corrigir).

## Rodar localmente
```powershell
$env:WEBHOOK_DROPS_URL="https://discord.com/api/webhooks/..."
$env:DISCORD_BOT_TOKEN="..."
$env:TWITCH_OAUTH_TOKEN="..."   # opcional, mas recomendado
python drops.py --state-file active_drops.json
```

