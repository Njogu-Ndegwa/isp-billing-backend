# Ad media Worker

Cloudflare Worker that serves uploaded ad photos and videos from the `bitwave-ad-media` R2 bucket
at `isp.bitwavetechnologies.com/media/*`. It only reads: `GET` and `HEAD`, and only the generated
`/media/c/<yyyy>/<mm>/<name>.<ext>` and older `/media/ads/...` paths. The backend uploads to R2
(`app/services/ad_media.py`) and rewrites old links to `/media/c/`, because ad blockers hide
anything under `/media/ads/`. See `ADS_API.md`.

| File | Purpose |
|---|---|
| `worker.mjs` | The Worker |
| `worker.test.mjs` | Tests. Run `node --test workers/ad-media/` |
| `wrangler.jsonc` | Worker route and R2 binding |
| `cors.json` | R2 bucket CORS rules for direct browser uploads |

## Deploying

Nothing deploys this automatically: merging to `main` does not touch Cloudflare. No account id or
credentials live here, so wrangler reads them from the environment.

```bash
cd workers/ad-media
CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... npx wrangler deploy
```

R2 upload credentials are backend settings (`R2_*` in `app/config.py`), and the Worker doesn't use them.
