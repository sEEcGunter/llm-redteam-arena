# LLM Red Team Arena

A self-contained red team lab for hands-on offensive assessment of LLM-powered
applications. The target — **NovaTech AI Assistant** — is a realistic Flask application
backed by Mistral 7B that reproduces the vulnerability patterns most commonly found in
production AI deployments today.

The goal is to demonstrate, end-to-end, how a black-box attacker moves from zero
knowledge to full compromise across nine OWASP LLM Top 10 (2025) categories — and to
show the concrete, real-world impact of each finding (stolen API keys that work against
live endpoints, forged JWT tokens, session cookie theft, privilege escalation via
autonomous agent actions).

**Coverage:** OWASP LLM Top 10 (2025) · MITRE ATLAS · 12 chained techniques · fully local, no external connectivity

---

## Target Environment

**Company:** NovaTech Solutions — fictional mid-size SaaS company (~350 employees) operating
a B2B customer support platform. The AI assistant was rolled out internally six months ago
to handle tier-1 support, internal knowledge queries, and back-office automation.

**Product:** Nova AI Assistant — a multi-function LLM-powered interface exposed to both
external customers and internal staff. Six surfaces are in scope:

| Surface | Business function | Attack surface |
|---------|------------------|----------------|
| **Chat** | Customer support / general queries | T-01, T-03, T-04, T-07, T-08, T-11, T-12 |
| **Document Summarizer** | Ops team summarizes inbound reports and vendor docs | T-02, T-10 |
| **Email Composer** | Staff drafts outbound comms with a `context` field for reference material | T-02, T-08, T-12 |
| **Knowledge Base (Ask)** | RAG-backed Q&A over internal documentation | T-05 |
| **Smart Search** | Natural language → SQL search over internal support DB | T-09, T-10 |
| **Feedback** | Public-facing feedback form, reviewed by admins weekly | T-06, T-10 |

**Threat model:** NovaTech's security team has raised concerns about the AI rollout.
The application was built rapidly, bypassing the standard security review. The key risks
flagged before this engagement — and which will be validated during it:

- Production credentials copy-pasted into the AI system prompt by a developer
- No access control on the knowledge base ingestion endpoint (`POST /ingest`)
- Admin panel processes user-submitted feedback through the LLM with no sanitisation
- LLM output rendered directly as HTML — no output encoding
- Backend automation platform (Nova Actions) connected to the LLM with no action validation

**Objective:** Validate each flagged risk, demonstrate exploitability with concrete impact
evidence, and produce findings for the engineering and leadership teams.

---

## Architecture

```
┌─ Host Machine ────────────────────────────────────────────────────────────────┐
│                                                                                │
│   Browser / curl                                                               │
│        │ :5000                                                                 │
│        ▼                                                                       │
│  ┌─ Docker container ───────────────────────┐          ┌─ LM Studio (native) ┐│
│  │  NovaTech Flask Webapp (target)          │  :1234   │  Mistral 7B          ││
│  │  Flask · ChromaDB · SQLite               │ ────────►│  Instruct v0.3       ││
│  │                                          │          │  (Vulkan / GPU)      ││
│  └──────────────────────────────────────────┘          └─────────────────────┘│
└────────────────────────────────────────────────────────────────────────────────┘
```

**Webapp:** NovaTech AI Assistant — Flask + ChromaDB + SQLite — runs in **Docker**  
**Model:** Mistral 7B Instruct v0.3 — runs natively via **LM Studio** on the host (`:1234`)  
**Communication:** Docker container reaches LM Studio via `host.docker.internal:1234`  
**Scope:** Fully local, no external API calls, no internet required

---

## Setup

**Prerequisites:** Docker Desktop · LM Studio (local server running on `:1234`)

1. Load **Mistral 7B Instruct v0.3** in LM Studio and start the local server
2. Build and start the webapp container:

```bash
docker compose up -d --build
```

> **First build:** ~1–2 min (sentence-transformers baked at build time). **Subsequent starts:** `docker compose up -d`

The model runs natively on your host via LM Studio — no container needed for inference.

### Access

| URL | What |
|-----|------|
| `http://localhost:5000` | NovaTech AI Assistant (Chat / Summarize / Compose / Ask KB / Smart Search / Feedback) |
| `http://localhost:5000/admin` | Admin panel — `admin / novatech2024` |

See `ASSESSMENT.md` for methodology and findings documentation.

---

## Vulnerability Surface

The application covers 9 of the 10 OWASP LLM Top 10 2025 categories (LLM03 Supply Chain
is out of scope for a local lab). Each vulnerability is exploitable end-to-end.

| Vulnerability | Location | OWASP 2025 |
|---------------|----------|-----------|
| Secrets embedded in system prompt | `app.py` — `CHAT_SYSTEM` | LLM07 |
| No input sanitisation on any endpoint | `/chat`, `/summarize`, `/compose`, `/feedback` | LLM01 |
| Unauthenticated knowledge base write | `POST /ingest` | LLM08 |
| Confidential document in public RAG store | ChromaDB — `doc-hr-internal` | LLM08 |
| LLM output rendered with `innerHTML` | `index.html`, `admin.html` | LLM05 |
| Pre-seeded production token in feedback DB | SQLite — feedback entry #3 | LLM01 |
| Nova Actions backend integration — no action validation | `app.py` — `_extract_actions()` | LLM06 |
| `/capture` exfiltration sink — no authentication | `app.py` — `/capture` endpoint | LLM05 |
| LLM-generated SQL executed without parameterisation | `app.py` — `/search` endpoint | LLM05 |
| No rate limiting or `max_tokens` cap on inference endpoints | `app.py` — `_llm()`, all routes | LLM10 |
| IDOR on `customer_id` in `/chat` — PII injected into Nova context without auth check | `app.py` — `/chat`, `customer_id` param | LLM02 |
| No factual grounding in COMPOSE_SYSTEM — model generates false advisories/certs with confidence | `app.py` — `COMPOSE_SYSTEM` | LLM09 |

Seven secrets distributed across three surfaces — each reachable only through its
corresponding technique:

| Secret | Surface | Impact |
|--------|---------|--------|
| `NOVA_API_KEY` | System prompt | `GET /api/v2/customers` — 147k customer records |
| `DB_PASSWORD` | System prompt | Direct PostgreSQL access — customers + billing tables |
| `ADMIN_URL` | System prompt + RAG document | Admin panel entry point |
| `HELPDESK_PIN` | System prompt | ServiceNow internal staff portal |
| `JWT_SECRET` | System prompt | Forge Bearer tokens for admin + SSO |
| `EMPLOYEE_RECORD` | RAG knowledge base (`doc-hr-internal`) | Executive PII (SSN, salary) — GDPR breach |
| `WEBHOOK_TOKEN` | Feedback database (pre-seeded developer error) | Post arbitrary messages to internal Slack #alerts |

---

## Techniques

The twelve techniques are designed to chain: each finding unlocks the next attack
surface. See `ASSESSMENT.md` for the full phased methodology with payloads, findings,
and impact analysis.

### T-01 · Direct Prompt Injection

**OWASP:** LLM01:2025 · **MITRE:** AML.T0054 · **Surface:** `/chat`

The attacker controls the user-turn and attempts to override the system prompt. LLMs
process all context as a flat token sequence — no cryptographic boundary separates
developer instructions from user input. A sufficiently crafted message can redirect the
model's goal, disable operational constraints, or exfiltrate embedded secrets.

Attack vectors: role override, goal hijacking, delimiter injection, fictional framing,
instruction priority claim.

---

### T-02 · Indirect Prompt Injection

**OWASP:** LLM01:2025 · **MITRE:** AML.T0054.001 · **Surface:** `/summarize`, `/compose`

Malicious instructions embedded in external content (documents, emails) processed by the
LLM on behalf of a legitimate user. The attacker never interacts with the model directly.
This is the dominant threat vector for agentic systems that ingest external data.

The `/compose` endpoint exposes a `context` field — external reference material passed
directly into the model's context — making it an explicit indirect injection surface.

---

### T-03 · Jailbreak

**OWASP:** LLM01:2025 · **MITRE:** AML.T0054.002 · **Surface:** `/chat`

Attacks targeting the model's alignment layer (RLHF fine-tuning) rather than the
application system prompt. A jailbreak succeeds when a semantically harmful request is
framed in a way that doesn't activate the refusal classifier — demonstrating that safety
training provides probabilistic, not absolute, guarantees.

Single-turn: DAN persona, fictional framing, many-shot priming, base64 token smuggling.  
Multi-turn: progressive escalation, trust-building then pivot, incremental boundary erosion.

---

### T-04 · System Prompt Extraction

**OWASP:** LLM07:2025 · **MITRE:** AML.T0057 · **Surface:** `/chat`

The system prompt resides in the model's context window and can be reproduced if the
model is not specifically trained to refuse. Nova's system prompt contains five
production secrets. A single successful extraction yields all five simultaneously.

Attack vectors: direct request, completion trap, translation trick, JSON dump,
authority roleplay, urgency and identity claim.

---

### T-05 · RAG Poisoning

**OWASP:** LLM08:2025 + LLM04:2025 · **MITRE:** AML.T0054.001 · **Surface:** `/ask`, `POST /ingest`

Two sub-findings: (1) `/ingest` is unauthenticated — any client can write arbitrary
documents to the ChromaDB knowledge base; injected documents are retrieved by semantic
similarity and treated as trusted context by the LLM. (2) A confidential HR record
(`doc-hr-internal`) was accidentally ingested at startup — extractable without any
injection by any user whose query triggers its semantic similarity.

---

### T-06 · Stored Prompt Injection

**OWASP:** LLM01:2025 · **MITRE:** AML.T0054.001 · **Surface:** `/feedback` → `/admin/summarize`

A cross-user asynchronous attack. The attacker submits a malicious feedback entry
through the unauthenticated form. The payload persists in SQLite. It fires when an admin
triggers the AI-powered feedback summary — the attacker is offline, and the victim is a
privileged user. The feedback DB also contains a production webhook token stored by a
developer — the secondary objective of this technique.

---

### T-07 · LLM Output Attacks

**OWASP:** LLM05:2025 · **MITRE:** AML.T0048 · **Surface:** `/chat` (browser), `/admin`

The frontend renders LLM responses with `innerHTML` — no sanitisation. The LLM becomes
a payload delivery vehicle: `<script>` tags in the response execute in the browser.
The admin panel's feedback summary is rendered the same way, meaning a successful stored
injection (T-06) can carry an XSS payload that fires in the admin's browser session.

Also covers: markdown link injection for phishing.

---

### T-08 · Excessive Agency

**OWASP:** LLM06:2025 · **MITRE:** AML.T0054 · **Surface:** `/chat`, `/compose`, `/admin/summarize`

Nova is connected to a backend automation platform and can trigger real operations via
`[NOVA_ACTION: type=X ...]` tags in its responses. The backend parses these tags from every
LLM response — including injected ones — without any human-in-the-loop gate.

An attacker who makes Nova output `[NOVA_ACTION: type=create_user email=attacker@evil.com role=admin]`
achieves privilege escalation via prompt injection. All triggered actions are logged at
`GET /admin/actions` and visible in the admin dashboard.

This can be chained with T-01, T-02, or T-06 to demonstrate a full injection → unauthorized
action chain.

---

### T-09 · SQL Injection via LLM Output

**OWASP:** LLM05:2025 · **MITRE:** AML.T0048 · **Surface:** `/search`

The Smart Search feature converts natural language questions to SQL using the LLM and
executes the generated query directly against SQLite without parameterisation. An attacker
crafts a natural language prompt that makes the model output a `UNION SELECT`, `DROP TABLE`,
or `SELECT * FROM sqlite_master` — turning the LLM into a SQL injection proxy.

Attack vectors: schema enumeration, UNION SELECT across privileged tables, destructive
DML statements, `sqlite_master` dump for full schema discovery.

---

### T-10 · Unbounded Consumption

**OWASP:** LLM10:2025 · **MITRE:** AML.T0034 · **Surface:** `/chat`, `/summarize`, `/compose`, `/admin/summarize`

No rate limiting and no `max_tokens` cap on any inference endpoint. An unauthenticated
attacker can flood the inference backend with token-maximising prompts or parallel
concurrent requests, degrading service for all users. Chains with T-06: a stored feedback
payload can trigger unbounded generation in the admin's inference call without the
attacker being present.

Attack vectors: direct token flood, parallel request flood (20+ concurrent), recursive
expansion prompts, stored DoS chain via feedback entry.

---

### T-11 · Sensitive Information Disclosure

**OWASP:** LLM02:2025 · **MITRE:** AML.T0057 · **Surface:** `/chat` (portal session bar)

The Chat interface exposes a portal session selector. When a `customer_id` is provided in
the request body, Nova injects that customer's full CRM record into its context — contact
name, email, phone, MRR, CSM, and contract dates. The `customer_id` is **not validated
against the authenticated session** — any unauthenticated caller passes any ID and reads
another customer's PII. Classic IDOR amplified by LLM over-disclosure.

Attack vectors: enumerate sequential IDs `cust-00001` → `cust-00005`, ask account-specific
questions to extract PII, correlate with `/api/v2/customers` data (T-04 API key required).

---

### T-12 · Misinformation as Attack Vector

**OWASP:** LLM09:2025 · **MITRE:** AML.T0048 · **Surface:** `/chat`, `/compose`

Nova generates responses with confident, professional tone regardless of factual accuracy.
No grounding check, no source citation, no uncertainty hedging in `COMPOSE_SYSTEM`. Prompts
that request "official" content produce convincing fake security advisories (invented CVE IDs,
fake patch URLs), false SLA clause numbers, and fabricated compliance certificates —
ready for social engineering or contract disputes.

Attack vectors: fake CVE advisory (phishing), false SLA clause numbers, invented compliance
certificates, fabricated incident root cause for forensic report falsification.

---

## Defensive Controls

For each finding, a targeted remediation. Controls are ordered from highest to lowest
impact — fixing T-04 and T-06 alone eliminates the critical path of the attack chain.

| Control | Addresses |
|---------|-----------|
| Remove secrets from system prompts — use a secrets manager | T-04 |
| Authenticate `/ingest` — enforce API key or service-account token | T-05 |
| HTML-escape LLM output — replace `innerHTML` with `textContent` or DOMPurify | T-07 |
| Use parameterised queries — never interpolate LLM output into SQL | T-07, T-09 |
| Sanitise stored data before injecting into LLM context | T-06 |
| Separate instruction context from data context in the prompt | T-02, T-06 |
| Add document provenance and access classification to the vector store | T-05 |
| Deploy output monitoring for credential patterns and injection markers | T-04, T-06 |
| Instruction-hierarchy fine-tuning + independent output classifier | T-01, T-03 |
| Minimal-privilege for agent tools — human confirmation gate for high-risk actions | T-08 |
| Server-side validation of all agent action parameters — never trust LLM output as input | T-08 |
| Set `max_tokens` on all LLM calls — enforce a hard output length ceiling | T-10 |
| Rate-limit all inference endpoints per IP — e.g. 10 req/min with token bucket | T-10 |
| Validate and whitelist LLM-generated SQL before execution | T-09 |
| Validate `customer_id` against authenticated session — never trust client-provided IDs | T-11 |
| Add grounding constraint to COMPOSE_SYSTEM — require source citation for factual claims | T-12 |
| Human review gate for high-stakes generated content (advisories, legal, compliance) | T-12 |

---

## Project Structure

```
.
├── docker-compose.yml       # NovaTech webapp container (LM Studio runs on host)
├── README.md                # Project overview and setup
├── ASSESSMENT.md            # Methodology, findings, and results documentation
├── webapp_client.py         # Python HTTP client — scripted testing utility
└── webapp/
    ├── Dockerfile           # sentence-transformers baked at build time
    ├── requirements.txt
    ├── app.py               # Flask target app — deliberately vulnerable
    └── templates/
        ├── index.html       # Chat / Summarize / Compose / Ask KB / Smart Search / Feedback
        └── admin.html       # Admin dashboard — stored injection + capture log
```

---

## Disclaimer

All tests target a locally running application with no external connectivity. All
credentials, customer data, and company names are entirely fictional and created
for this lab. The techniques documented here reflect real-world attack patterns
against production LLM deployments and are published for educational and defensive
purposes only.
