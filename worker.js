/**
 * LocalTap - The 2026 Localhost Attack Surface Scanner
 * Security Research by Bountyy Oy / Mihalis Haatainen
 *
 * What this does:
 * 1. Scans visitor's localhost for common dev services (timing-based)
 * 2. Demonstrates DNS rebinding against discovered services
 * 3. Logs and visualizes the attack surface across all visitors
 * 4. Serves as interactive research demo + writeup
 *
 * Routes:
 * /                    - Research landing page + writeup
 * /scan                - Interactive localhost scanner (runs in visitor's browser)
 * /dashboard           - Aggregated results dashboard
 * /rebind/setup        - DNS rebinding attack demo setup
 * /rebind/payload      - DNS rebinding payload page
 * /api/report          - Receive scan results from browsers
 * /api/results         - JSON aggregated results
 * /api/clear           - Clear results
 * /dns                 - DNS rebinding explainer with live demo
 *
 * ETHICAL NOTE: The scanner only probes the visitor's OWN localhost.
 * No data leaves unless the visitor explicitly runs the scan.
 * This is a research tool for demonstrating the attack surface.
 */

// ─── TARGET SERVICES ───────────────────────────────────────────

const TARGETS = [
  { port: 3000,  name: "Next.js / React Dev",       auth: false,     rebind: "likely",     impact: "SSR abuse, env leak, source code",             category: "webdev" },
  { port: 3001,  name: "Create React App",           auth: false,     rebind: "likely",     impact: "Source maps, HMR hijack",                      category: "webdev" },
  { port: 4200,  name: "Angular Dev Server",         auth: false,     rebind: "likely",     impact: "Source maps, HMR hijack",                      category: "webdev" },
  { port: 5173,  name: "Vite Dev Server",            auth: false,     rebind: "likely",     impact: "Source code exfil, HMR websocket hijack",      category: "webdev" },
  { port: 5174,  name: "Vite (alt port)",            auth: false,     rebind: "likely",     impact: "Source code exfil",                             category: "webdev" },
  { port: 8000,  name: "Python HTTP / Django",       auth: false,     rebind: "likely",     impact: "File listing, source code, API access",        category: "webdev" },
  { port: 8080,  name: "Webpack / Generic Dev",      auth: false,     rebind: "likely",     impact: "Source maps, dev tools",                       category: "webdev" },
  { port: 8081,  name: "Dev Server (alt)",           auth: false,     rebind: "likely",     impact: "Varies",                                       category: "webdev" },
  { port: 8888,  name: "Jupyter Notebook",           auth: "token",   rebind: "partial",    impact: "Kernel RCE, data access",                      category: "ai" },
  { port: 8889,  name: "Jupyter Lab (alt)",          auth: "token",   rebind: "partial",    impact: "Kernel RCE",                                   category: "ai" },
  { port: 11434, name: "Ollama",                     auth: false,     rebind: "confirmed",  impact: "Model exec, file read, model poisoning",       category: "ai" },
  { port: 1234,  name: "Open WebUI",                 auth: "session", rebind: "likely",     impact: "LLM access, conversation history",             category: "ai" },
  { port: 3100,  name: "LM Studio",                  auth: false,     rebind: "likely",     impact: "Model exec, system prompt leak",               category: "ai" },
  { port: 8188,  name: "ComfyUI",                    auth: false,     rebind: "likely",     impact: "Workflow exec, file system access",            category: "ai" },
  { port: 7860,  name: "Gradio / Stable Diffusion",  auth: false,     rebind: "likely",     impact: "Model exec, file access",                     category: "ai" },
  { port: 5678,  name: "n8n Automation",             auth: "session", rebind: "likely",     impact: "Workflow exec, credential theft",              category: "automation" },
  { port: 1880,  name: "Node-RED",                   auth: false,     rebind: "likely",     impact: "Flow exec, system commands",                   category: "automation" },
  { port: 9000,  name: "Portainer",                  auth: "session", rebind: "likely",     impact: "Container management, host access",            category: "infra" },
  { port: 2375,  name: "Docker API (TCP)",           auth: false,     rebind: "confirmed",  impact: "Container create/exec, host filesystem",      category: "infra" },
  { port: 2376,  name: "Docker API (TLS)",           auth: "cert",    rebind: "no",         impact: "Container management",                        category: "infra" },
  { port: 8001,  name: "Kubernetes Dashboard",       auth: "varies",  rebind: "likely",     impact: "Cluster admin, pod exec",                     category: "infra" },
  { port: 6443,  name: "Kubernetes API",             auth: "cert",    rebind: "partial",    impact: "Cluster management",                          category: "infra" },
  { port: 10250, name: "Kubelet API",                auth: "varies",  rebind: "likely",     impact: "Pod exec, log access",                        category: "infra" },
  { port: 9090,  name: "Prometheus",                 auth: false,     rebind: "likely",     impact: "Metrics exfil, internal topology",            category: "infra" },
  { port: 3000,  name: "Grafana",                    auth: "default", rebind: "likely",     impact: "Dashboard access, data source creds",         category: "infra" },
  { port: 8443,  name: "VS Code Server",             auth: "token",   rebind: "partial",    impact: "Terminal RCE, file access",                   category: "dev" },
  { port: 5990,  name: "GitHub Copilot Agent",       auth: false,     rebind: "unknown",    impact: "Code context leak",                           category: "dev" },
  { port: 6274,  name: "Claude Code MCP",            auth: false,     rebind: "unknown",    impact: "Tool execution",                              category: "dev" },
  { port: 9222,  name: "Chrome DevTools Protocol",   auth: false,     rebind: "confirmed",  impact: "Browser takeover, session theft",             category: "dev" },
  { port: 5432,  name: "PostgreSQL",                 auth: "password", rebind: "no",        impact: "Database access",                             category: "data" },
  { port: 3306,  name: "MySQL",                      auth: "password", rebind: "no",        impact: "Database access",                             category: "data" },
  { port: 6379,  name: "Redis",                      auth: false,     rebind: "likely",     impact: "Cache dump, session theft, RCE via modules",  category: "data" },
  { port: 27017, name: "MongoDB",                    auth: false,     rebind: "likely",     impact: "Database dump",                               category: "data" },
  { port: 9200,  name: "Elasticsearch",              auth: false,     rebind: "likely",     impact: "Index dump, data exfil",                      category: "data" },
  { port: 8983,  name: "Apache Solr",                auth: false,     rebind: "likely",     impact: "Search index exfil, RCE via velocity",       category: "data" },
  { port: 4040,  name: "Spark UI",                   auth: false,     rebind: "likely",     impact: "Job data, environment variables",             category: "data" },
  { port: 15672, name: "RabbitMQ Management",        auth: "default", rebind: "likely",     impact: "Queue access, message sniffing",              category: "data" },
  { port: 8161,  name: "ActiveMQ Web Console",       auth: "default", rebind: "likely",     impact: "Queue management, message access",            category: "data" },

  // ── Additional AI/ML services ──
  { port: 8501,  name: "Streamlit",                  auth: false,     rebind: "likely",     impact: "Data app access, code exec via widgets",      category: "ai" },
  { port: 6333,  name: "Qdrant Vector DB",            auth: false,     rebind: "likely",     impact: "Vector dump, embedding exfil, collection delete", category: "ai" },
  { port: 19530, name: "Milvus Vector DB",             auth: false,     rebind: "likely",     impact: "Vector data exfil, collection manipulation",  category: "ai" },
  { port: 5000,  name: "MLflow Tracking",              auth: false,     rebind: "likely",     impact: "Model registry, experiment data, artifact access", category: "ai" },
  { port: 6006,  name: "TensorBoard",                  auth: false,     rebind: "likely",     impact: "Training data leak, model architecture exfil", category: "ai" },
  { port: 11435, name: "Ollama (alt port)",             auth: false,     rebind: "confirmed",  impact: "Model exec, file read",                       category: "ai" },
  { port: 4891,  name: "LocalAI",                      auth: false,     rebind: "likely",     impact: "Model exec, OpenAI-compatible API abuse",      category: "ai" },
  { port: 8080,  name: "AnythingLLM",                  auth: false,     rebind: "likely",     impact: "LLM access, document store, workspace data",   category: "ai" },
  { port: 3080,  name: "LibreChat",                    auth: "session", rebind: "likely",     impact: "LLM conversations, API key theft",             category: "ai" },
  { port: 7862,  name: "Stable Diffusion WebUI (alt)", auth: false,     rebind: "likely",     impact: "Image generation, model access",               category: "ai" },

  // ── Additional web dev services ──
  { port: 4321,  name: "Astro Dev Server",             auth: false,     rebind: "likely",     impact: "Source code exfil, SSR abuse",                 category: "webdev" },
  { port: 1313,  name: "Hugo Dev Server",              auth: false,     rebind: "likely",     impact: "Content exfil, draft access",                  category: "webdev" },
  { port: 4000,  name: "Remix / Phoenix",              auth: false,     rebind: "likely",     impact: "Source code, SSR abuse, live dashboard",       category: "webdev" },
  { port: 3333,  name: "AdonisJS / Nuxt",              auth: false,     rebind: "likely",     impact: "Source code, API access",                      category: "webdev" },
  { port: 24678, name: "Vite HMR WebSocket",           auth: false,     rebind: "likely",     impact: "Hot module injection, source code modification", category: "webdev" },
  { port: 5500,  name: "Live Server (VS Code)",        auth: false,     rebind: "likely",     impact: "Static file serving, content injection",       category: "webdev" },
  { port: 35729, name: "LiveReload",                   auth: false,     rebind: "likely",     impact: "Page injection via reload protocol",           category: "webdev" },
  { port: 9292,  name: "Rack / Sinatra (Ruby)",        auth: false,     rebind: "likely",     impact: "Source code, session data",                    category: "webdev" },
  { port: 6006,  name: "Storybook",                    auth: false,     rebind: "likely",     impact: "Component source, internal UI exposure",       category: "webdev" },
  { port: 5555,  name: "Prisma Studio",                auth: false,     rebind: "likely",     impact: "Full database GUI, CRUD on all models",        category: "webdev" },
  { port: 4002,  name: "Apollo GraphQL Sandbox",       auth: false,     rebind: "likely",     impact: "Schema introspection, query execution",        category: "webdev" },

  // ── Additional infrastructure ──
  { port: 8500,  name: "HashiCorp Consul",             auth: false,     rebind: "likely",     impact: "Service discovery, KV store access, ACL bypass", category: "infra" },
  { port: 8200,  name: "HashiCorp Vault",              auth: "token",   rebind: "partial",    impact: "Secret exfil, token theft, seal/unseal",       category: "infra" },
  { port: 2019,  name: "Caddy Admin API",              auth: false,     rebind: "likely",     impact: "Config manipulation, reverse proxy hijack",    category: "infra" },
  { port: 9901,  name: "Envoy Admin",                  auth: false,     rebind: "likely",     impact: "Config dump, cluster topology, stats",         category: "infra" },
  { port: 4646,  name: "HashiCorp Nomad",              auth: false,     rebind: "likely",     impact: "Job scheduling, exec, secret access",          category: "infra" },
  { port: 9001,  name: "MinIO Console",                auth: "default", rebind: "likely",     impact: "S3 bucket access, object read/write/delete",   category: "infra" },
  { port: 8384,  name: "Syncthing",                    auth: false,     rebind: "likely",     impact: "File sync manipulation, shared folder access", category: "infra" },
  { port: 32400, name: "Plex Media Server",            auth: "token",   rebind: "partial",    impact: "Media library, user accounts, network info",   category: "infra" },
  { port: 8096,  name: "Jellyfin",                     auth: "session", rebind: "likely",     impact: "Media library, user data, transcoding abuse",  category: "infra" },

  // ── Additional databases ──
  { port: 5984,  name: "CouchDB",                      auth: false,     rebind: "confirmed",  impact: "Database dump, admin party (no auth default)", category: "data" },
  { port: 8086,  name: "InfluxDB",                     auth: false,     rebind: "likely",     impact: "Time-series data exfil, metric manipulation",  category: "data" },
  { port: 7474,  name: "Neo4j Browser",                auth: "default", rebind: "likely",     impact: "Graph traversal, full data dump, Cypher exec", category: "data" },
  { port: 2379,  name: "etcd",                         auth: false,     rebind: "likely",     impact: "K8s secrets, cluster state, config dump",      category: "data" },
  { port: 8529,  name: "ArangoDB",                     auth: false,     rebind: "likely",     impact: "Multi-model DB access, Foxx service exec",    category: "data" },
  { port: 8123,  name: "ClickHouse HTTP",              auth: false,     rebind: "likely",     impact: "SQL query exec, data exfil, table drop",      category: "data" },
  { port: 26257, name: "CockroachDB SQL",              auth: false,     rebind: "likely",     impact: "Distributed SQL access, data dump",            category: "data" },
  { port: 28015, name: "RethinkDB",                    auth: false,     rebind: "likely",     impact: "ReQL exec, realtime feed hijack",              category: "data" },
  { port: 9042,  name: "Cassandra CQL",                auth: false,     rebind: "partial",    impact: "Keyspace dump, CQL injection",                 category: "data" },
  { port: 7687,  name: "Neo4j Bolt",                   auth: "default", rebind: "partial",    impact: "Direct graph DB access",                       category: "data" },

  // ── Observability ──
  { port: 9411,  name: "Zipkin",                       auth: false,     rebind: "likely",     impact: "Distributed trace exfil, service topology map", category: "infra" },
  { port: 16686, name: "Jaeger UI",                    auth: false,     rebind: "likely",     impact: "Trace data exfil, internal service mapping",   category: "infra" },
  { port: 4317,  name: "OpenTelemetry Collector",      auth: false,     rebind: "likely",     impact: "Telemetry injection, trace/metric poisoning",  category: "infra" },
  { port: 3301,  name: "SigNoz",                       auth: false,     rebind: "likely",     impact: "APM data exfil, infrastructure topology",      category: "infra" },

  // ── Developer tools ──
  { port: 5050,  name: "pgAdmin",                      auth: "default", rebind: "likely",     impact: "Database management, saved server credentials", category: "dev" },
  { port: 1337,  name: "Strapi Admin",                 auth: false,     rebind: "likely",     impact: "CMS admin, content manipulation, user data",   category: "dev" },
  { port: 8055,  name: "Directus",                     auth: "token",   rebind: "likely",     impact: "Headless CMS access, media library, user data", category: "dev" },
  { port: 54321, name: "Supabase Studio",              auth: false,     rebind: "likely",     impact: "DB GUI, auth users, storage buckets, edge functions", category: "dev" },
  { port: 8090,  name: "PocketBase",                   auth: false,     rebind: "likely",     impact: "Admin API, collection CRUD, file storage",     category: "dev" },
  { port: 9229,  name: "Node.js Inspector",            auth: false,     rebind: "confirmed",  impact: "Debugger attach, arbitrary code execution",    category: "dev" },
  { port: 5037,  name: "ADB (Android Debug Bridge)",   auth: false,     rebind: "likely",     impact: "Android device control, app install, shell",   category: "dev" },
  { port: 631,   name: "CUPS (Print Server)",          auth: false,     rebind: "likely",     impact: "Printer config, print job access, CVE-2024-47176", category: "dev" },

  // ── Automation ──
  { port: 8123,  name: "Home Assistant",               auth: "token",   rebind: "likely",     impact: "Smart home control, camera feeds, location data", category: "automation" },
  { port: 2283,  name: "Immich",                       auth: "api_key", rebind: "likely",     impact: "Photo library exfil, ML face data, geodata",   category: "automation" },
  { port: 9443,  name: "Portainer (HTTPS)",            auth: "session", rebind: "partial",    impact: "Container management, host access",            category: "automation" },
  { port: 8085,  name: "Windmill",                     auth: "token",   rebind: "likely",     impact: "Script execution, workflow secrets, API keys",  category: "automation" },
  { port: 3030,  name: "Directus / ToolJet",           auth: "session", rebind: "likely",     impact: "Low-code platform, data source credentials",   category: "automation" },

  // ── Blockchain / Web3 dev ──
  { port: 8545,  name: "Ethereum JSON-RPC (Hardhat)",  auth: false,     rebind: "confirmed",  impact: "Private key access, fund transfer, contract deploy", category: "dev" },
  { port: 7545,  name: "Ganache",                      auth: false,     rebind: "confirmed",  impact: "Test ETH wallets, private keys, transaction replay", category: "dev" },
  { port: 8546,  name: "Ethereum WebSocket RPC",       auth: false,     rebind: "confirmed",  impact: "Real-time tx monitoring, mempool sniffing",    category: "dev" },
  { port: 8899,  name: "Solana Test Validator",         auth: false,     rebind: "likely",     impact: "Airdrop, transaction signing, program deploy",  category: "dev" },

  // ── ELK / Log stack ──
  { port: 5601,  name: "Kibana",                       auth: false,     rebind: "likely",     impact: "Log data exfil, saved objects, index patterns", category: "data" },
  { port: 9600,  name: "Logstash API",                 auth: false,     rebind: "likely",     impact: "Pipeline info, node stats, plugin list",        category: "data" },

  // ── Cloud emulators ──
  { port: 4566,  name: "LocalStack (AWS emulator)",    auth: false,     rebind: "confirmed",  impact: "S3/SQS/Lambda/DynamoDB - full AWS API access",  category: "infra" },
  { port: 8086,  name: "Azure Storage Emulator",       auth: false,     rebind: "likely",     impact: "Blob/Queue/Table storage access",               category: "infra" },
  { port: 8085,  name: "GCP Pub/Sub Emulator",         auth: false,     rebind: "likely",     impact: "Message queue access, topic manipulation",      category: "infra" },

  // ── Email testing ──
  { port: 8025,  name: "Mailpit / MailHog",            auth: false,     rebind: "likely",     impact: "Captured emails exfil, password reset tokens",  category: "dev" },
  { port: 1025,  name: "MailHog SMTP",                 auth: false,     rebind: "likely",     impact: "SMTP relay, email injection",                   category: "dev" },
  { port: 1080,  name: "MailCatcher",                  auth: false,     rebind: "likely",     impact: "Email capture, credential harvesting",          category: "dev" },

  // ── Profiling / Debug ──
  { port: 6060,  name: "Go pprof",                     auth: false,     rebind: "likely",     impact: "Heap dump, goroutine leak, CPU profile exfil",  category: "dev" },
  { port: 4173,  name: "Vite Preview",                 auth: false,     rebind: "likely",     impact: "Production build preview, asset exfil",         category: "webdev" },

  // ── Remote access / Terminal ──
  { port: 7681,  name: "ttyd Web Terminal",            auth: false,     rebind: "confirmed",  impact: "Full shell access via browser, instant RCE",    category: "dev" },
  { port: 6080,  name: "noVNC",                        auth: false,     rebind: "likely",     impact: "Remote desktop access, screen capture",         category: "dev" },
  { port: 5900,  name: "VNC Server",                   auth: "password", rebind: "partial",   impact: "Remote desktop, keylogging, screen capture",    category: "dev" },

  // ── Mobile dev ──
  { port: 19006, name: "Expo DevTools",                auth: false,     rebind: "likely",     impact: "React Native source, device control, hot reload", category: "dev" },
  { port: 19000, name: "Expo Metro Bundler",           auth: false,     rebind: "likely",     impact: "Source code, bundle manipulation",               category: "dev" },
  { port: 8081,  name: "React Native Metro",           auth: false,     rebind: "likely",     impact: "Source maps, hot module injection",              category: "webdev" },

  // ── Big data ──
  { port: 50070, name: "HDFS NameNode",                auth: false,     rebind: "likely",     impact: "Distributed filesystem browse, data exfil",     category: "data" },
  { port: 8088,  name: "YARN ResourceManager",         auth: false,     rebind: "likely",     impact: "Job submission, container exec, cluster info",   category: "data" },
  { port: 9092,  name: "Kafka Broker",                 auth: false,     rebind: "partial",    impact: "Topic listing, message consume, producer inject", category: "data" },
  { port: 2181,  name: "ZooKeeper",                    auth: false,     rebind: "partial",    impact: "Cluster config, ACL data, leader election abuse", category: "data" },
  { port: 11211, name: "Memcached",                    auth: false,     rebind: "likely",     impact: "Cache dump, session data, DDoS amplification",  category: "data" },

  // ── Testing / QA ──
  { port: 4444,  name: "Selenium Grid Hub",            auth: false,     rebind: "likely",     impact: "Browser session hijack, arbitrary URL navigation", category: "dev" },
  { port: 9515,  name: "ChromeDriver",                 auth: false,     rebind: "confirmed",  impact: "Browser automation, session theft via WebDriver", category: "dev" },
  { port: 4723,  name: "Appium Server",                auth: false,     rebind: "likely",     impact: "Mobile device control, app manipulation",        category: "dev" },

  // ── Reverse proxies / API gateways ──
  { port: 8082,  name: "Traefik Dashboard",            auth: false,     rebind: "likely",     impact: "Route config exfil, middleware manipulation",    category: "infra" },
  { port: 8444,  name: "Kong Admin API",               auth: false,     rebind: "likely",     impact: "API gateway config, upstream manipulation",      category: "infra" },
  { port: 15000, name: "Istio Envoy Admin",            auth: false,     rebind: "likely",     impact: "Service mesh config, cluster topology dump",     category: "infra" },
  { port: 20000, name: "Webmin",                       auth: "default", rebind: "likely",     impact: "System administration, root access",             category: "infra" },

  // ── Auth / Identity ──
  { port: 3567,  name: "SuperTokens Core",             auth: false,     rebind: "likely",     impact: "Auth bypass, user session manipulation",         category: "infra" },
  { port: 8080,  name: "Keycloak",                     auth: "default", rebind: "likely",     impact: "Identity provider admin, token minting",         category: "infra" },
  { port: 9763,  name: "WSO2 Identity Server",         auth: "default", rebind: "likely",     impact: "SAML/OAuth admin, identity federation abuse",    category: "infra" },

  // ── Data science / Analytics ──
  { port: 8787,  name: "RStudio Server",               auth: "password", rebind: "partial",   impact: "R console RCE, data access, package install",   category: "ai" },
  { port: 3838,  name: "Shiny Server",                 auth: false,     rebind: "likely",     impact: "R app access, data visualization exfil",         category: "ai" },
  { port: 8050,  name: "Plotly Dash",                   auth: false,     rebind: "likely",     impact: "Dashboard data exfil, callback manipulation",   category: "ai" },
  { port: 8765,  name: "text-generation-webui API",    auth: false,     rebind: "likely",     impact: "LLM inference, model switching, chat history",   category: "ai" },

  // ── Microservices ──
  { port: 3500,  name: "Dapr HTTP API",                auth: false,     rebind: "likely",     impact: "Service invocation, state store, pub/sub access", category: "infra" },
  { port: 8778,  name: "Jolokia (JMX over HTTP)",      auth: false,     rebind: "confirmed",  impact: "JMX MBean access, heap dump, thread manipulation", category: "infra" },
  { port: 9100,  name: "Prometheus Node Exporter",     auth: false,     rebind: "likely",     impact: "Host metrics, filesystem info, network stats",   category: "infra" },
  { port: 8428,  name: "VictoriaMetrics",              auth: false,     rebind: "likely",     impact: "Metrics DB access, data injection/exfil",        category: "infra" },

  // ── File sharing / Storage ──
  { port: 8080,  name: "FileBrowser",                  auth: "default", rebind: "likely",     impact: "Full filesystem browse, file upload/download",   category: "infra" },
  { port: 5001,  name: "IPFS API",                     auth: false,     rebind: "likely",     impact: "Pin/unpin content, file add, swarm peers",       category: "infra" },
  { port: 4001,  name: "IPFS Swarm",                   auth: false,     rebind: "partial",    impact: "P2P network access, content routing",            category: "infra" },

  // ── Game dev ──
  { port: 9090,  name: "Godot Remote Debug",           auth: false,     rebind: "likely",     impact: "Scene tree access, variable manipulation",       category: "dev" },
  { port: 3002,  name: "Unreal Pixel Streaming",       auth: false,     rebind: "likely",     impact: "Render stream hijack, input injection",          category: "dev" },

  // ── SQL tools ──
  { port: 1433,  name: "Microsoft SQL Server",         auth: "password", rebind: "no",        impact: "Database access, xp_cmdshell RCE",              category: "data" },
  { port: 33060, name: "MySQL X Protocol",             auth: "password", rebind: "no",        impact: "Document store access, async queries",           category: "data" },
  { port: 6380,  name: "Redis (TLS)",                  auth: false,     rebind: "partial",    impact: "Encrypted cache access",                         category: "data" },
  { port: 8529,  name: "ArangoDB Web UI",              auth: false,     rebind: "likely",     impact: "AQL queries, graph traversal, user management",  category: "data" },
];

// Deduplicate by port (some share 3000)
const UNIQUE_TARGETS = [];
const seenPorts = new Set();
for (const t of TARGETS) {
  if (!seenPorts.has(t.port)) {
    seenPorts.add(t.port);
    UNIQUE_TARGETS.push(t);
  }
}

// ─── HELPERS ───────────────────────────────────────────────────

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" },
  });
}

function html(body, headers = {}) {
  return new Response(body, {
    headers: { "Content-Type": "text/html;charset=UTF-8", ...headers },
  });
}

// ─── SCANNER PAGE ──────────────────────────────────────────────

function renderScanner(baseUrl) {
  const targetsJSON = JSON.stringify(UNIQUE_TARGETS);
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LocalTap // Localhost Attack Surface Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Instrument+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#050508;--surface:#0c0c12;--border:#1a1a28;--text:#d4d4e0;--dim:#4a4a6a;
  --red:#ff2d55;--green:#30d158;--blue:#0a84ff;--orange:#ff9f0a;--yellow:#ffd60a;--purple:#bf5af2;--cyan:#64d2ff;
  --mono:'IBM Plex Mono',monospace;--sans:'Instrument Sans',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;overflow-x:hidden}

/* Noise overlay */
body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");pointer-events:none;z-index:9999}

.container{max-width:1200px;margin:0 auto;padding:32px 24px}

/* Header */
.hero{padding:60px 0 40px;position:relative}
.hero::after{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:600px;height:600px;background:radial-gradient(circle,rgba(255,45,85,0.06) 0%,transparent 70%);pointer-events:none}
.badge{display:inline-block;font-family:var(--mono);font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--red);border:1px solid rgba(255,45,85,0.3);padding:4px 12px;border-radius:3px;margin-bottom:20px}
h1{font-family:var(--sans);font-size:clamp(2.5em,6vw,4.5em);font-weight:700;letter-spacing:-2px;line-height:1;margin-bottom:16px}
h1 span{color:var(--red)}
.subtitle{font-family:var(--mono);font-size:14px;color:var(--dim);line-height:1.6;max-width:600px}

/* Controls */
.controls{display:flex;gap:12px;margin:32px 0;flex-wrap:wrap;align-items:center}
.btn{font-family:var(--mono);font-size:13px;font-weight:600;padding:12px 24px;border-radius:6px;border:none;cursor:pointer;transition:all 0.2s}
.btn-primary{background:var(--red);color:#fff}
.btn-primary:hover{background:#e6274d;transform:translateY(-1px)}
.btn-primary:disabled{opacity:0.4;cursor:not-allowed;transform:none}
.btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--dim)}
.scan-status{font-family:var(--mono);font-size:12px;color:var(--dim);margin-left:8px}

/* Progress */
.progress-wrap{margin:16px 0;height:3px;background:var(--surface);border-radius:2px;overflow:hidden;display:none}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--red),var(--orange));width:0%;transition:width 0.3s}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat-label{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--dim);margin-bottom:4px}
.stat-val{font-family:var(--mono);font-size:2em;font-weight:700}
.stat-val.danger{color:var(--red)}
.stat-val.warn{color:var(--orange)}
.stat-val.safe{color:var(--green)}
.stat-val.info{color:var(--blue)}

/* Results grid */
.results-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;margin:24px 0}
.port-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;transition:all 0.3s;position:relative;overflow:hidden}
.port-card.open{border-color:var(--red);background:rgba(255,45,85,0.04)}
.port-card.open::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--red)}
.port-card.closed{opacity:0.35}
.port-card.scanning{border-color:var(--orange);animation:scan-pulse 1s ease-in-out infinite}
@keyframes scan-pulse{0%,100%{border-color:var(--orange)}50%{border-color:transparent}}
.port-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}
.port-num{font-family:var(--mono);font-size:20px;font-weight:700}
.port-num.open{color:var(--red)}
.port-status{font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:3px;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.port-status.open{background:rgba(255,45,85,0.15);color:var(--red)}
.port-status.closed{background:rgba(74,74,106,0.2);color:var(--dim)}
.port-status.scanning{background:rgba(255,159,10,0.15);color:var(--orange)}
.port-name{font-size:14px;font-weight:600;margin-bottom:4px}
.port-meta{font-family:var(--mono);font-size:11px;color:var(--dim);margin-bottom:6px}
.port-impact{font-size:12px;color:var(--orange);line-height:1.4}
.port-tags{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.tag{font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid}
.tag-auth-none{border-color:rgba(255,45,85,0.3);color:var(--red)}
.tag-auth-yes{border-color:rgba(48,209,88,0.3);color:var(--green)}
.tag-rebind{border-color:rgba(191,90,242,0.3);color:var(--purple)}
.tag-cat{border-color:rgba(100,210,255,0.3);color:var(--cyan)}

/* Category filters */
.filters{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}
.filter-btn{font-family:var(--mono);font-size:11px;padding:6px 12px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--dim);cursor:pointer;transition:all 0.2s}
.filter-btn.active{border-color:var(--cyan);color:var(--cyan);background:rgba(100,210,255,0.08)}
.filter-btn:hover{border-color:var(--dim)}

/* Sections */
.section{margin:48px 0}
.section-label{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:3px;color:var(--dim);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.section-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* Attack chain */
.chain{display:flex;gap:0;margin:24px 0;flex-wrap:wrap;align-items:stretch}
.chain-step{background:var(--surface);border:1px solid var(--border);padding:16px;flex:1;min-width:200px;position:relative}
.chain-step:first-child{border-radius:8px 0 0 8px}
.chain-step:last-child{border-radius:0 8px 8px 0}
.chain-step:not(:last-child)::after{content:'\\2192';position:absolute;right:-14px;top:50%;transform:translateY(-50%);font-size:18px;color:var(--red);z-index:1;background:var(--bg);padding:4px}
.chain-num{font-family:var(--mono);font-size:10px;color:var(--red);margin-bottom:4px}
.chain-title{font-weight:600;font-size:13px;margin-bottom:4px}
.chain-desc{font-family:var(--mono);font-size:11px;color:var(--dim);line-height:1.4}

/* Footer */
.footer{border-top:1px solid var(--border);margin-top:48px;padding-top:24px;display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:11px;color:var(--dim)}

/* Consent banner */
.consent{background:var(--surface);border:1px solid var(--orange);border-radius:8px;padding:20px;margin:24px 0}
.consent h3{color:var(--orange);font-size:14px;margin-bottom:8px}
.consent p{font-size:13px;color:var(--dim);line-height:1.5;margin-bottom:12px}

/* Responsive */
@media(max-width:768px){
.chain{flex-direction:column}
.chain-step{border-radius:0!important}
.chain-step:not(:last-child)::after{display:none}
.results-grid{grid-template-columns:1fr}
}
</style>
</head><body>
<div class="container">

<div class="hero">
  <div class="badge">Security Research // Bountyy Oy</div>
  <h1>Local<span>Tap</span></h1>
  <div class="subtitle">
    The 2026 localhost attack surface is massive and uncharted.
    Every developer runs unauthenticated services on localhost.
    This tool maps what's exposed on YOUR machine right now.
  </div>
</div>

<div class="section">
  <div class="section-label">Attack Chain</div>
  <div class="chain">
    <div class="chain-step">
      <div class="chain-num">01</div>
      <div class="chain-title">Visit malicious page</div>
      <div class="chain-desc">Victim clicks link, opens page in browser</div>
    </div>
    <div class="chain-step">
      <div class="chain-num">02</div>
      <div class="chain-title">Port scan localhost</div>
      <div class="chain-desc">Timing-based probes detect open services</div>
    </div>
    <div class="chain-step">
      <div class="chain-num">03</div>
      <div class="chain-title">DNS rebinding</div>
      <div class="chain-desc">Rebind attacker domain to 127.0.0.1</div>
    </div>
    <div class="chain-step">
      <div class="chain-num">04</div>
      <div class="chain-title">Same-origin access</div>
      <div class="chain-desc">Browser treats localhost API as same-origin</div>
    </div>
    <div class="chain-step">
      <div class="chain-num">05</div>
      <div class="chain-title">Exfiltrate / Execute</div>
      <div class="chain-desc">Read files, run models, steal tokens, RCE</div>
    </div>
  </div>
</div>

<div class="consent">
  <h3>Ethical Notice</h3>
  <p>This scanner probes YOUR OWN localhost only. No data is sent anywhere unless you explicitly click "Report Results".
  The scan uses timing-based detection (fetch + timeout) to determine if ports respond.
  This is a research demonstration of the attack surface, not an exploitation tool.</p>
</div>

<div class="controls">
  <button class="btn btn-primary" id="startScan" onclick="startScan()">Scan My Localhost</button>
  <button class="btn btn-secondary" id="stopScan" onclick="stopScan()" style="display:none">Stop</button>
  <button class="btn btn-secondary" id="reportBtn" onclick="reportResults()" style="display:none">Report Results (Anonymous)</button>
  <span class="scan-status" id="scanStatus"></span>
</div>

<div class="progress-wrap" id="progressWrap">
  <div class="progress-bar" id="progressBar"></div>
</div>

<div class="stats" id="statsGrid">
  <div class="stat"><div class="stat-label">Ports Scanned</div><div class="stat-val info" id="statScanned">0</div></div>
  <div class="stat"><div class="stat-label">Open / Responding</div><div class="stat-val danger" id="statOpen">0</div></div>
  <div class="stat"><div class="stat-label">No Auth Required</div><div class="stat-val danger" id="statNoAuth">0</div></div>
  <div class="stat"><div class="stat-label">DNS Rebind Possible</div><div class="stat-val warn" id="statRebind">0</div></div>
</div>

<div class="section">
  <div class="section-label">Scan Targets</div>
  <div class="filters" id="filters"></div>
  <div class="results-grid" id="resultsGrid"></div>
</div>

<div class="footer">
  <span>LocalTap // Security Research by Bountyy Oy</span>
  <span id="timestamp"></span>
</div>

</div>

<script>
const TARGETS = ${targetsJSON};
const BASE = "${baseUrl}";
let scanning = false;
let results = {};
let abortController = null;

// Category colors
const CAT_COLORS = {webdev:'var(--blue)',ai:'var(--purple)',automation:'var(--orange)',infra:'var(--red)',dev:'var(--cyan)',data:'var(--yellow)'};

// Init
document.addEventListener('DOMContentLoaded', () => {
  renderCards();
  renderFilters();
  document.getElementById('timestamp').textContent = new Date().toISOString().slice(0,19) + 'Z';
});

function renderFilters() {
  const cats = [...new Set(TARGETS.map(t => t.category))];
  const el = document.getElementById('filters');
  el.innerHTML = '<button class="filter-btn active" onclick="filterCat(\\'all\\')">all</button>' +
    cats.map(c => '<button class="filter-btn" onclick="filterCat(\\'' + c + '\\')">' + c + '</button>').join('');
}

function filterCat(cat) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.textContent === cat || (cat === 'all' && b.textContent === 'all')));
  document.querySelectorAll('.port-card').forEach(card => {
    if (cat === 'all') { card.style.display = ''; return; }
    card.style.display = card.dataset.cat === cat ? '' : 'none';
  });
}

function renderCards() {
  const grid = document.getElementById('resultsGrid');
  grid.innerHTML = TARGETS.map(t => {
    const state = results[t.port];
    const cls = state === 'open' ? 'open' : state === 'closed' ? 'closed' : '';
    const statusCls = state || 'pending';
    const statusText = state || 'pending';
    return '<div class="port-card ' + cls + '" data-port="' + t.port + '" data-cat="' + t.category + '" id="card-' + t.port + '">' +
      '<div class="port-header">' +
        '<span class="port-num ' + cls + '">:' + t.port + '</span>' +
        '<span class="port-status ' + statusCls + '" id="status-' + t.port + '">' + statusText + '</span>' +
      '</div>' +
      '<div class="port-name">' + t.name + '</div>' +
      '<div class="port-meta">Auth: ' + (t.auth === false ? 'NONE' : t.auth) + ' // Rebind: ' + t.rebind + '</div>' +
      '<div class="port-impact">' + t.impact + '</div>' +
      '<div class="port-tags">' +
        (t.auth === false ? '<span class="tag tag-auth-none">no auth</span>' : '<span class="tag tag-auth-yes">' + t.auth + '</span>') +
        (t.rebind === 'confirmed' || t.rebind === 'likely' ? '<span class="tag tag-rebind">rebindable</span>' : '') +
        '<span class="tag tag-cat">' + t.category + '</span>' +
      '</div>' +
    '</div>';
  }).join('');
}

function updateCard(port, state) {
  results[port] = state;
  const card = document.getElementById('card-' + port);
  const status = document.getElementById('status-' + port);
  if (!card || !status) return;
  card.className = 'port-card ' + state;
  status.className = 'port-status ' + state;
  status.textContent = state;
  updateStats();
}

function updateStats() {
  const vals = Object.values(results);
  document.getElementById('statScanned').textContent = vals.length;
  const openPorts = Object.keys(results).filter(p => results[p] === 'open');
  document.getElementById('statOpen').textContent = openPorts.length;
  const noAuth = openPorts.filter(p => {
    const t = TARGETS.find(t => t.port == p);
    return t && t.auth === false;
  });
  document.getElementById('statNoAuth').textContent = noAuth.length;
  const rebindable = openPorts.filter(p => {
    const t = TARGETS.find(t => t.port == p);
    return t && (t.rebind === 'confirmed' || t.rebind === 'likely');
  });
  document.getElementById('statRebind').textContent = rebindable.length;
}

// ─── PORT SCANNING ─────────────────────────────────────────────
// Timing-based: fetch to localhost with short timeout.
// Open port: connection succeeds or fails fast (CORS error = open)
// Closed port: connection hangs until timeout (TCP RST varies by OS)

async function probePort(port, timeout = 1500) {
  const start = performance.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    await fetch('http://127.0.0.1:' + port + '/', {
      mode: 'no-cors',
      signal: controller.signal,
    });
    clearTimeout(timer);
    return { port, open: true, time: performance.now() - start };
  } catch (e) {
    const elapsed = performance.now() - start;
    // If it errored fast (< timeout * 0.8), something responded (CORS block = service exists)
    // If it timed out or took long, port is likely closed
    if (elapsed < timeout * 0.8 && e.name !== 'AbortError') {
      return { port, open: true, time: elapsed };
    }
    return { port, open: false, time: elapsed };
  }
}

async function startScan() {
  if (scanning) return;
  scanning = true;
  results = {};
  renderCards();

  document.getElementById('startScan').disabled = true;
  document.getElementById('stopScan').style.display = '';
  document.getElementById('progressWrap').style.display = '';
  document.getElementById('reportBtn').style.display = 'none';
  document.getElementById('scanStatus').textContent = 'Scanning...';

  abortController = new AbortController();

  // Scan in batches of 5 for speed
  const batchSize = 5;
  for (let i = 0; i < TARGETS.length; i += batchSize) {
    if (!scanning) break;

    const batch = TARGETS.slice(i, i + batchSize);

    // Mark as scanning
    batch.forEach(t => updateCard(t.port, 'scanning'));

    const probes = batch.map(t => probePort(t.port));
    const batchResults = await Promise.all(probes);

    for (const r of batchResults) {
      if (!scanning) break;
      updateCard(r.port, r.open ? 'open' : 'closed');
    }

    // Update progress
    const pct = Math.min(100, ((i + batchSize) / TARGETS.length) * 100);
    document.getElementById('progressBar').style.width = pct + '%';
  }

  scanning = false;
  document.getElementById('startScan').disabled = false;
  document.getElementById('stopScan').style.display = 'none';
  document.getElementById('scanStatus').textContent = 'Scan complete.';

  const openCount = Object.values(results).filter(v => v === 'open').length;
  if (openCount > 0) {
    document.getElementById('reportBtn').style.display = '';
  }
}

function stopScan() {
  scanning = false;
  document.getElementById('scanStatus').textContent = 'Scan stopped.';
  document.getElementById('startScan').disabled = false;
  document.getElementById('stopScan').style.display = 'none';
}

async function reportResults() {
  const openPorts = Object.keys(results).filter(p => results[p] === 'open').map(Number);
  try {
    await fetch(BASE + '/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        open: openPorts,
        total: TARGETS.length,
        ua: navigator.userAgent,
        ts: new Date().toISOString(),
      }),
    });
    document.getElementById('scanStatus').textContent = 'Results reported anonymously. Thank you!';
    document.getElementById('reportBtn').style.display = 'none';
  } catch (e) {
    document.getElementById('scanStatus').textContent = 'Report failed: ' + e.message;
  }
}
</script>
</body></html>`;
}

// ─── DASHBOARD ─────────────────────────────────────────────────

function renderDashboard(results, baseUrl) {
  // Aggregate: count how many scans found each port open
  const portCounts = {};
  let totalScans = results.length;

  for (const r of results) {
    for (const p of (r.open || [])) {
      portCounts[p] = (portCounts[p] || 0) + 1;
    }
  }

  // Sort by frequency
  const sorted = Object.entries(portCounts).sort((a, b) => b[1] - a[1]);

  const barRows = sorted.map(([port, count]) => {
    const pct = totalScans > 0 ? ((count / totalScans) * 100).toFixed(1) : 0;
    const t = TARGETS.find(t => t.port == port);
    const name = t ? t.name : 'Unknown';
    return `<div style="display:flex;align-items:center;gap:12px;margin:6px 0">
      <span style="font-family:var(--mono);font-size:12px;width:50px;text-align:right;color:var(--red)">:${port}</span>
      <span style="font-size:12px;width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${name}</span>
      <div style="flex:1;height:20px;background:var(--surface);border-radius:3px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:linear-gradient(90deg,var(--red),var(--orange));border-radius:3px;transition:width 0.5s"></div>
      </div>
      <span style="font-family:var(--mono);font-size:11px;color:var(--dim);width:80px">${count}/${totalScans} (${pct}%)</span>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LocalTap // Aggregated Results</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Instrument+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050508;--surface:#0c0c12;--border:#1a1a28;--text:#d4d4e0;--dim:#4a4a6a;--red:#ff2d55;--green:#30d158;--blue:#0a84ff;--orange:#ff9f0a;--yellow:#ffd60a;--purple:#bf5af2;--cyan:#64d2ff;--mono:'IBM Plex Mono',monospace;--sans:'Instrument Sans',sans-serif}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
.container{max-width:1000px;margin:0 auto;padding:32px 24px}
h1{font-size:2em;font-weight:700;letter-spacing:-1px;margin-bottom:8px}
h1 span{color:var(--red)}
.meta{font-family:var(--mono);font-size:12px;color:var(--dim);margin-bottom:32px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:32px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat-label{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--dim);margin-bottom:4px}
.stat-val{font-family:var(--mono);font-size:2.5em;font-weight:700;color:var(--red)}
.section-label{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:3px;color:var(--dim);margin:24px 0 12px}
.footer{border-top:1px solid var(--border);margin-top:32px;padding-top:16px;font-family:var(--mono);font-size:11px;color:var(--dim);text-align:center}
</style>
</head><body>
<div class="container">
  <h1>Local<span>Tap</span> // Dashboard</h1>
  <div class="meta">Aggregated anonymous scan results. Auto-refreshes every 30s.</div>

  <div class="stats">
    <div class="stat"><div class="stat-label">Total Scans</div><div class="stat-val">${totalScans}</div></div>
    <div class="stat"><div class="stat-label">Unique Ports Found</div><div class="stat-val">${sorted.length}</div></div>
    <div class="stat"><div class="stat-label">Most Common</div><div class="stat-val" style="font-size:1.2em">${sorted[0] ? ':' + sorted[0][0] : 'N/A'}</div></div>
  </div>

  <div class="section-label">Port Frequency (% of scans where port was open)</div>
  <div style="margin:16px 0">${barRows || '<div style="color:var(--dim);padding:24px;text-align:center">No scan data yet. Run a scan at <a href="/" style="color:var(--cyan)">/scan</a></div>'}</div>

  <div class="footer">LocalTap // Security Research by Bountyy Oy // ${new Date().toISOString().slice(0, 10)}</div>
</div>
<script>setTimeout(() => location.reload(), 30000);</script>
</body></html>`;
}

// ─── LANDING / WRITEUP ─────────────────────────────────────────

function renderLanding(baseUrl) {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LocalTap - The 2026 Localhost Attack Surface Map</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Instrument+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050508;--surface:#0c0c12;--border:#1a1a28;--text:#d4d4e0;--dim:#4a4a6a;--red:#ff2d55;--green:#30d158;--blue:#0a84ff;--orange:#ff9f0a;--mono:'IBM Plex Mono',monospace;--sans:'Instrument Sans',sans-serif}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.7}
.container{max-width:760px;margin:0 auto;padding:48px 24px}
.badge{display:inline-block;font-family:var(--mono);font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--red);border:1px solid rgba(255,45,85,0.3);padding:4px 12px;border-radius:3px;margin-bottom:20px}
h1{font-size:clamp(2em,5vw,3.5em);font-weight:700;letter-spacing:-2px;line-height:1.1;margin-bottom:24px}
h1 span{color:var(--red)}
h2{font-size:1.4em;font-weight:700;margin:40px 0 16px;letter-spacing:-0.5px}
p{margin-bottom:16px;color:var(--text)}
.dim{color:var(--dim)}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:0.9em;background:var(--surface);padding:2px 6px;border-radius:3px;color:var(--orange)}
pre{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto;margin:16px 0;font-family:var(--mono);font-size:13px;line-height:1.5}
.cta{display:inline-block;background:var(--red);color:#fff;font-family:var(--mono);font-size:14px;font-weight:600;padding:14px 32px;border-radius:6px;margin:16px 0;text-decoration:none;transition:all 0.2s}
.cta:hover{background:#e6274d;text-decoration:none;transform:translateY(-1px)}
.footer{border-top:1px solid var(--border);margin-top:48px;padding-top:24px;font-family:var(--mono);font-size:11px;color:var(--dim);text-align:center}
.highlight{background:rgba(255,45,85,0.08);border-left:3px solid var(--red);padding:16px;margin:16px 0;border-radius:0 8px 8px 0}
</style>
</head><body>
<div class="container">

<div class="badge">Research // Bountyy Oy</div>
<h1>Local<span>Tap</span></h1>
<p class="dim" style="font-family:var(--mono);font-size:14px">The 2026 Localhost Attack Surface Map</p>

<p>Every developer's machine is a goldmine of unauthenticated services. Ollama on :11434. Vite on :5173. Docker API on :2375. Jupyter on :8888. None of them require authentication by default. All of them are reachable from any website you visit through DNS rebinding.</p>

<div class="highlight">
<strong>The core problem:</strong> localhost services assume "if you can reach me, you're authorized." DNS rebinding breaks that assumption. A malicious webpage can make your browser talk to your own localhost services as if it were you.
</div>

<h2>What we mapped</h2>
<p>We catalogued ${TARGETS.length} common localhost services across 6 categories: web development, AI/ML, automation, infrastructure, developer tools, and databases. For each service, we documented the default port, authentication posture, DNS rebinding susceptibility, and potential impact.</p>

<p>The results are concerning. The majority of services that developers run locally have zero authentication and are vulnerable to DNS rebinding attacks. This means any website you visit can potentially interact with your local Ollama instance, read your Vite source code, execute commands through your Docker API, or dump your Redis cache.</p>

<h2>How it works</h2>
<p>The attack chain is straightforward:</p>
<pre>
1. Victim visits attacker.com
2. JavaScript probes localhost ports (timing-based fingerprinting)
3. Attacker's DNS server rebinds attacker.com -> 127.0.0.1
4. Browser now treats attacker.com as same-origin with localhost
5. JavaScript calls localhost APIs freely (Ollama, Docker, etc.)
6. Data exfiltrated to attacker's callback server
</pre>

<h2>Try it yourself</h2>
<p>We built an interactive scanner that maps YOUR localhost attack surface. It runs entirely in your browser and only scans your own machine.</p>
<a href="/scan" class="cta">Launch Scanner</a>
<a href="/dashboard" class="cta" style="background:var(--surface);border:1px solid var(--border);margin-left:8px">View Dashboard</a>

<h2>Impact highlights</h2>
<p><strong>Ollama (CVE-2024-28224):</strong> DNS rebinding confirmed. Attacker can read arbitrary files from the host, poison models, and exfiltrate data through the Ollama API. 175,000+ instances exposed on the internet, millions more on localhost.</p>

<p><strong>Docker API (:2375):</strong> If TCP socket is enabled (common in dev setups), full container creation and host filesystem mount. This is instant host RCE.</p>

<p><strong>Chrome DevTools Protocol (:9222):</strong> If remote debugging is enabled, complete browser takeover. Read all tabs, cookies, local storage, execute arbitrary JS in any origin.</p>

<p><strong>MCP Servers:</strong> The new Model Context Protocol servers are designed to bridge AI agents with local tools. Most run on HTTP without authentication. DNS rebinding gives an attacker the same access as the AI agent: tool execution, API keys, backend access.</p>

<h2>Defenses</h2>
<p>For service developers: validate the Host header. Require authentication even on localhost. Set restrictive CORS policies. For browser vendors: enforce Private Network Access (CORS-RFC1918) consistently. For developers: bind to 127.0.0.1 not 0.0.0.0. Use authentication on everything. Monitor what's listening on your machine.</p>

<h2>Responsible disclosure</h2>
<p>This research maps a systemic issue, not a single vulnerability. Individual CVEs have been filed where appropriate (e.g., Ollama CVE-2024-28224). This tool is published to raise awareness about the scope of the problem and to help developers audit their own exposure.</p>

<div class="footer">
  LocalTap // Security Research by Bountyy Oy // Mihalis Haatainen // 2026<br>
  <a href="https://bountyy.fi">bountyy.fi</a>
</div>

</div>
</body></html>`;
}

// ─── WORKER HANDLER ────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const baseUrl = url.origin;

    // CORS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // ── API: receive scan report
    if (path === "/api/report" && request.method === "POST") {
      try {
        const body = await request.json();
        const entry = {
          open: body.open || [],
          total: body.total || 0,
          ts: new Date().toISOString(),
          ip: request.headers.get("cf-connecting-ip") || "unknown",
          country: request.headers.get("cf-ipcountry") || "unknown",
        };
        const existing = await env.LOCALTAP.get("results", "json") || [];
        existing.push(entry);
        // Keep last 1000 entries
        const trimmed = existing.slice(-1000);
        await env.LOCALTAP.put("results", JSON.stringify(trimmed));
        return jsonResp({ ok: true });
      } catch (e) {
        return jsonResp({ error: e.message }, 400);
      }
    }

    // ── API: get results
    if (path === "/api/results") {
      const results = await env.LOCALTAP.get("results", "json") || [];
      return jsonResp(results);
    }

    // ── API: clear
    if (path === "/api/clear") {
      await env.LOCALTAP.put("results", "[]");
      return Response.redirect(baseUrl + "/dashboard", 302);
    }

    // ── Dashboard
    if (path === "/dashboard") {
      const results = await env.LOCALTAP.get("results", "json") || [];
      return html(renderDashboard(results, baseUrl));
    }

    // ── Scanner
    if (path === "/scan") {
      return html(renderScanner(baseUrl));
    }

    // ── Landing
    if (path === "/" || path === "") {
      return html(renderLanding(baseUrl));
    }

    return new Response("Not found", { status: 404 });
  },
};
