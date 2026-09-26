# ContextKeeper 2.0 — Developer Governance & Release Engine

> An all-in-one developer governance, runtime modernization, actor-critic review, and release
> engine built for **IBM Bob 2.0** and agentic IDE workflows.

---

## Architectural Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ContextKeeper 2.0                               │
│                    FastMCP Server  (stdio transport)                    │
├──────────────┬──────────────┬────────────────┬───────────┬─────────────┤
│ core/        │ core/        │ core/          │ core/     │ core/       │
│ memory.py    │ budget_guard │ modernizer.py  │ critic_   │ artifact_   │
│              │ .py          │                │ gate.py   │ engine.py   │
│ Persistent   │ Token-scoped │ Dependency     │ Diff      │ Mermaid /   │
│ storage      │ context      │ & runtime      │ security  │ PR / wx     │
│ .context/    │ compaction   │ audit          │ heuristics│ Orchestrate │
│ AGENTS.md    │              │                │ + SARIF   │             │
└──────────────┴──────────────┴────────────────┴───────────┴─────────────┘
         │                                                       │
         ▼                                                       ▼
  .context/sessions.json                              reports/bob_audit.sarif
  .context/constraints.json                           AGENTS.md (Bob /init)
  .context/deprecated_rules.json                      PR markdown template
```

### Module responsibilities

| Module | Responsibility |
|--------|---------------|
| [`server.py`](src/context_keeper_mcp/server.py) | FastMCP entry point; registers all 7 MCP tools with type annotations and docstrings |
| [`core/memory.py`](src/context_keeper_mcp/core/memory.py) | Atomic JSON storage for `.context/`; bi-directional AGENTS.md sync compatible with Bob's `/init` |
| [`core/budget_guard.py`](src/context_keeper_mcp/core/budget_guard.py) | Token compaction engine; returns only top 5–7 relevant constraints per focus area |
| [`core/modernizer.py`](src/context_keeper_mcp/core/modernizer.py) | Manifest scanner; detects deprecated packages, CVEs, and outdated runtimes |
| [`core/critic_gate.py`](src/context_keeper_mcp/core/critic_gate.py) | Diff auditor with deterministic security heuristics; exports OASIS SARIF v2.1.0 |
| [`core/artifact_engine.py`](src/context_keeper_mcp/core/artifact_engine.py) | Generates Mermaid diagrams, Conventional Commits PR templates, watsonx Orchestrate payloads |

---

## MCP Tools Reference

| Tool | Purpose |
|------|---------|
| `checkpoint_task` | Persist task state to `.context/sessions.json`; sync AGENTS.md |
| `get_scoped_context` | Return top 5–7 relevant constraints for a focus area |
| `audit_dependencies_and_runtime` | Scan `package.json` / `requirements.txt` / `pyproject.toml` for deprecated packages and CVEs |
| `audit_diff_compliance` | Evaluate a `git diff` against project constraints and security heuristics |
| `export_sarif_report` | Write an OASIS SARIF v2.1.0 report to `reports/` |
| `generate_mermaid_flow` | Generate `sequenceDiagram` or `flowchart LR` Mermaid syntax |
| `draft_pull_request` | Compile a Conventional Commits PR template with embedded Mermaid diagrams |

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

---

## Install

```bash
# From source (development)
uv tool install -e .

# From GitHub (after push)
uv tool install git+https://github.com/YOUR_USER/context-keeper-mcp
```

---

## Bob IDE MCP Configuration

Add ContextKeeper 2.0 to Bob's `mcp.json` (workspace or global):

```json
{
  "mcpServers": {
    "context-keeper": {
      "command": "context-keeper-mcp",
      "env": {
        "CONTEXT_KEEPER_DIR": "${workspaceFolder}/.context"
      }
    }
  }
}
```

> If the binary is not on PATH, use the absolute path:
> `"command": "/home/user/.local/bin/context-keeper-mcp"`

### Bob `settings.json` snippet

```json
{
  "bob.mcp.servers": {
    "context-keeper": {
      "command": "context-keeper-mcp",
      "transport": "stdio",
      "env": {
        "CONTEXT_KEEPER_DIR": "${workspaceFolder}/.context"
      }
    }
  }
}
```

---

## Example Agent Mode Workflow

The following end-to-end example shows how Bob uses ContextKeeper 2.0 during a feature sprint.

### 1 — Start a task checkpoint

```
Call checkpoint_task with:
  task_id   = "feat-payment-v2"
  summary   = "Upgrade payment processing to Stripe v3 API"
  decisions = ["Use idempotency keys for all charge requests",
               "Store webhook secrets in environment variables"]
  status    = "in_progress"
```

ContextKeeper writes `.context/sessions.json` and syncs `AGENTS.md`.

### 2 — Get scoped context before editing

```
Call get_scoped_context with:
  focus_area   = "payment processing"
  current_file = "src/payments/stripe_client.py"
```

Returns only the 5–7 constraints most relevant to payment code — no noise.

### 3 — Audit dependencies

```
Call audit_dependencies_and_runtime with:
  manifest_content = <contents of package.json>
  manifest_type    = "package.json"
  target_runtime   = "node@22"
```

ContextKeeper flags `request` (deprecated), `moment` (maintenance mode),
and any CVE-listed packages, with recommended modern alternatives.

### 4 — Review a diff before merging

```
Call audit_diff_compliance with:
  diff_text      = <output of git diff main..feature/payment-v2>
  modified_files = ["src/payments/stripe_client.py", "src/payments/webhook.py"]
```

ContextKeeper runs deterministic security heuristics and checks project
constraints. Returns verdict `pass` or `fail` with line-level findings.

### 5 — Export SARIF for CI

```
Call export_sarif_report with:
  audit_findings = <findings list from step 4>
  output_file    = "reports/payment-v2.sarif"
```

The SARIF file is ready for upload to GitHub Code Scanning or any SARIF-compatible tool.

### 6 — Generate a Mermaid diagram

```
Call generate_mermaid_flow with:
  subsystem_name     = "PaymentService"
  components_touched = ["StripeClient", "WebhookHandler", "OrderStore"]
  flow_type          = "sequence"
```

Paste the result into a `````mermaid` fence in the PR body or documentation.

### 7 — Draft the pull request

```
Call draft_pull_request with:
  task_id      = "feat-payment-v2"
  branch_name  = "feature/payment-v2"
  tests_passed = true
```

Returns a production-ready PR title and markdown body using Conventional Commits
format, with embedded Mermaid diagram and decision log.

---

## Storage Layout

```
.context/
├── sessions.json          # task checkpoints (written by checkpoint_task)
├── constraints.json       # project rules and banned patterns (edit once)
├── deprecated_rules.json  # deprecated package/CVE database (update periodically)
└── .lock                  # file lock (auto-managed)

AGENTS.md                  # auto-synced session log (Bob /init compatible)

reports/
└── bob_audit.sarif        # SARIF reports (written by export_sarif_report)

bob_sessions/
└── .gitkeep               # placeholder for session screenshots
```

Commit `.context/constraints.json` and `.context/deprecated_rules.json` to your repo.
`sessions.json` and `AGENTS.md` are generated at runtime — commit them if you want
context to survive across machines.

---

## Concurrency

All writes are guarded by a `filelock` with a 5-second timeout. Concurrent
IDE windows on the same project will serialise rather than corrupt storage.

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Publishing to PyPI

```bash
git tag v2.0.0
git push --tags
```

Triggers `.github/workflows/publish.yml` automatically once a `PYPI_API_TOKEN`
secret is set on the repo.

---

## License

MIT
