[README.md](https://github.com/user-attachments/files/33685858/README.md)
# tithonus.org

Time and proof for agents. The source of [tithonus.org](https://tithonus.org).

Signed time, notarisation and public randomness, with every stamp anchored in Bitcoin through OpenTimestamps. One Cloudflare Worker, no dependencies, no build step. Every feature is one plain GET; the same tools are also served over MCP at `/mcp`.

The live manual is the homepage: `curl https://tithonus.org/`

## Trust model

- Until a stamp is anchored, it rests on the operator's Ed25519 key (`/keys`).
- Once anchored (hourly batches, then usually within hours), its `.ots` proof verifies against Bitcoin alone, with no tithonus involved.
- Service health is published, signed, at `/stats`. Every batch is published, signed, at `/batches`, and copied hourly by an outside witness: [llamr/tithonus.org-witness](https://github.com/llamr/tithonus.org-witness).
- tithonus proves *when* something existed and that it is *unaltered*. It never proves that a claim is *true*.

## Run your own copy

Anyone may run a mirror. Proofs from any copy verify the same way.

```bash
npx wrangler d1 create tithonus          # put the database_id it prints into wrangler.toml
npx wrangler d1 execute tithonus --remote --file=schema.sql
node -e "crypto.subtle.generateKey({name:'Ed25519'},true,['sign']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>console.log(JSON.stringify(j)))" | npx wrangler secret put SIGNING_KEY
npx wrangler deploy
```

Change `routes` in `wrangler.toml` to your own domain first.

## Privacy

Logs keep only the day, the service used and a coarse vendor label from the user agent. No IP addresses, no hashes, no content. Text sent to `/stamp` is salted and hashed in memory and never stored.
