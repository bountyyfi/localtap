# LocalTap

**The 2026 Localhost Attack Surface Scanner**

Security research by [Bountyy Oy](https://bountyy.com) / Mihalis Haatainen

## What is this?

Every developer's machine runs dozens of unauthenticated services on localhost. Ollama on `:11434`. Vite on `:5173`. Docker API on `:2375`. Jupyter on `:8888`. None require authentication by default. All are reachable from any website through DNS rebinding.

LocalTap maps this attack surface. It's a Cloudflare Worker that serves:

- **`/`** - Research writeup explaining the attack chain
- **`/scan`** - Interactive browser-based localhost port scanner
- **`/dashboard`** - Aggregated anonymous results from all scans

## How the scanner works

The scanner uses **timing-based port detection** via `fetch()` against `127.0.0.1`:

1. Send a `no-cors` fetch request to `http://127.0.0.1:<port>/` with a timeout
2. If the request errors quickly (CORS block), a service is listening = **port open**
3. If the request hangs until timeout (TCP RST or no response), **port closed**

No data leaves the browser unless the visitor explicitly clicks "Report Results".

## Attack chain

```
1. Victim visits attacker.com
2. JavaScript probes localhost ports (timing-based fingerprinting)
3. Attacker's DNS server rebinds attacker.com -> 127.0.0.1
4. Browser treats attacker.com as same-origin with localhost
5. JavaScript calls localhost APIs freely (Ollama, Docker, Redis, etc.)
6. Data exfiltrated to attacker's callback server
```

## What we scan

**147 services** across 7 categories:

| Category | Examples | Count |
|----------|----------|-------|
| **AI/ML** | Ollama, Jupyter, ComfyUI, Gradio, Streamlit, Qdrant, Milvus, MLflow, TensorBoard, LocalAI, LM Studio | 20+ |
| **Web Dev** | Vite, Next.js, Angular, Webpack, Astro, Hugo, Prisma Studio, LiveReload, Storybook | 20+ |
| **Infrastructure** | Docker API, Kubernetes, Consul, Vault, Nomad, Caddy, Envoy, Traefik, LocalStack | 25+ |
| **Databases** | Redis, MongoDB, Elasticsearch, PostgreSQL, ClickHouse, Neo4j, etcd, CouchDB, Kafka | 25+ |
| **Developer Tools** | Chrome DevTools Protocol, Node.js Inspector, VS Code Server, Selenium, ADB, ttyd | 20+ |
| **Automation** | n8n, Node-RED, Home Assistant, Immich, Windmill, ToolJet | 10+ |
| **Blockchain** | Hardhat, Ganache, Solana Validator | 4 |

## Key findings

- **Ollama (CVE-2024-28224):** DNS rebinding confirmed. Arbitrary file read, model poisoning, data exfil.
- **Docker API (:2375):** TCP socket = instant host RCE via container mount.
- **Chrome DevTools (:9222):** Complete browser takeover - all tabs, cookies, localStorage.
- **Node.js Inspector (:9229):** Debugger attach = arbitrary code execution, confirmed rebindable.
- **Hardhat/Ganache (:8545):** Private key access, fund transfer. Confirmed rebindable.
- **MCP Servers:** No auth by default. DNS rebinding gives attacker the same tool access as the AI agent.

## Deploy

```bash
# Clone
git clone https://github.com/bountyyfi/localtap.git
cd localtap

# Create KV namespace (one time)
wrangler kv namespace create LOCALTAP
# Update wrangler.toml with the KV namespace ID

# Deploy
wrangler deploy
```

## Architecture

- Single `worker.js`, zero dependencies
- Cloudflare Workers + KV for result aggregation
- Scanner runs entirely client-side (browser JavaScript)
- Brutalist black/red design, IBM Plex Mono + Instrument Sans
- Results stored anonymously (IP hashed, country only)

## Ethical notice

This scanner **only probes the visitor's own localhost**. No data is sent anywhere unless the visitor explicitly clicks "Report Results". This is a research tool for demonstrating the attack surface, not an exploitation tool.

## Defenses

**For service developers:**
- Validate the `Host` header
- Require authentication even on localhost
- Set restrictive CORS policies

**For browser vendors:**
- Enforce Private Network Access (CORS-RFC1918) consistently

**For developers:**
- Bind to `127.0.0.1` not `0.0.0.0`
- Use authentication on everything
- Monitor what's listening: `lsof -i -P -n | grep LISTEN`

## License

MIT

## Responsible disclosure

This research maps a systemic issue, not a single vulnerability. Individual CVEs have been filed where appropriate. Published to raise awareness and help developers audit their own exposure.
