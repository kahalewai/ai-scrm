<div align="center">
  
<img width="583" height="472" alt="ai-scrm" src="https://github.com/user-attachments/assets/4abb6fae-6297-41ed-8794-cd54e97ae76b" />

<br>

[![ai-scrm](https://img.shields.io/badge/AI--SCS-v1.0.0-blue)](https://github.com/kahalewai/ai-scs)
![python](https://img.shields.io/badge/python-3.9+-green) 
![license](https://img.shields.io/badge/license-Apache%202.0-orange)
[![Version](https://img.shields.io/badge/version-1.0.1-red.svg)](https://github.com/kahalewai/ai-scrm)

</div>

<br>

## Intro

AI-SCRM is the reference implementation of the AI-SCS (AI Supply Chain Security) standard for securing AI infrastructure. It provides production-ready tools to document, sign, and validate AI system components—protecting against model backdooring, dataset poisoning, unauthorized tool activation, and supply chain attacks.

AI-SCRM is intended to:
* Auto-discover models, MCP servers, libraries, and prompts with one command
* Infer metadata for 100+ common model families automatically
* Sign and verify AI artifacts with Ed25519/RSA/ECDSA
* Continuously monitor for drift with configurable intervals
* Integrate easily with LangChain, FastAPI, and CI/CD pipelines
* Provide clear, actionable error messages
* Support production deployments with SIEM integration

<br>

## Quick Start: One Command Setup

```bash
# Install with all features
pip install ai-scrm[all]

# Initialize everything (scan + template + keys + sign)
ai-scrm init

# View status
ai-scrm status

# Start continuous monitoring
ai-scrm monitor
```

That's it. In under 2 minutes, AI-SCRM will:

1. Scan for models, MCP servers, libraries, and prompts
2. Infer suppliers for known models (Llama, Mistral, GPT, etc.)
3. Generate a metadata template for items needing review
4. Create signing keys and sign your ABOM
5. Start monitoring for drift

<br>

## How AI-SCRM Works

Implementing AI Supply Chain Standard requires that your AI system becomes inventory-aware AND your runtime environment validates against the declared inventory. AI-SCRM automates both. Each Control Domain enforces the same core requirement:

<br>

> An AI system may only execute components that are declared in its ABOM, cryptographically verified, and continuously validated at runtime.

<br>

**The AI-SCRM Workflow**

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI-SCRM Workflow                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [1] SCAN (Automatic)                                           │
│      └── Discovers models, MCP, libraries, prompts              │
│                                                                 │
│  [2] ENRICH (Review ~5 min)                                     │
│      └── Fill in TODOs for unknown suppliers                    │
│                                                                 │
│  [3] SIGN (Automatic)                                           │
│      └── Cryptographically sign the ABOM                        │
│                                                                 │
│  [4] MONITOR (Continuous)                                       │
│      ├── Hash checks (every 60s)                                │
│      ├── MCP heartbeat (every 5 min)                            │
│      ├── Full re-scan (every 30 min)                            │
│      └── On drift → RADE event → SIEM                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<br>

## AI-SCRM Design

AI-SCRM is designed to conform to the AI-SCS (AI Supply Chain Standard)
* AI-SCS Standard v1.0.0 Document: https://github.com/kahalewai/ai-scs

<br>

**AI-SCRM Characteristics**

| Aspect              | Scope                                    |
| ------------------- | ---------------------------------------- |
| Asset coverage      | Models, data, tools, MCP, agents, infra  |
| Inventory format    | CycloneDX 1.6 + AI-SCS extensions        |
| Integrity           | SHA-256 cryptographic hashes             |
| Authenticity        | Ed25519, RSA-PSS, ECDSA-P256 signatures  |
| Validation          | Continuous runtime drift detection       |
| Integration         | SIEM, SOAR, policy engines               |

<br>

**Works with Your Existing Security Infrastructure**

AI-SCRM was designed to work with your existing security tools:

* Uses CycloneDX 1.6, a standard SBOM format
* Emits SIEM-compatible structured events
* Integrates with policy engines via callbacks
* Supports existing key management (HSM, cloud KMS)
* Works with CI/CD pipelines (GitHub Actions, GitLab)
* Compatible with Kubernetes admission controllers

<br>

**Trust Boundary Classification**

| Pattern | Trust Boundary |
|---------|----------------|
| `localhost:*` | internal |
| `127.0.0.1:*` | internal |
| `192.168.*`, `10.*` | internal |
| `stdio://` | internal |
| Everything else | external |

Override with patterns in `ai-scrm-metadata.yaml`:
```yaml
trust_boundaries:
  "*.internal.mycompany.com": internal
  "*": external
```

<br>

## Installation

```bash
# Basic installation
pip install ai-scrm

# With all features (signing, CLI, YAML support)
pip install ai-scrm[all]
```

<br>

## Basic Usage

```python
from ai_scrm import ABOMBuilder, ABOM, Signer, Verifier, DriftDetector

# 1. Build ABOM with your AI components
builder = ABOMBuilder()
builder.add_model(
    name="llama-3-8b",
    version="1.0.0",
    hash_value="a1b2c3d4e5f6...",
    format="safetensors",
    supplier="Meta"
)
builder.add_mcp_server(
    name="filesystem-mcp",
    version="1.0.0",
    endpoint="http://localhost:3000",
    trust_boundary="internal",
    capabilities=["read_file", "write_file"]
)
abom = builder.finalize(system_name="my-ai-assistant")

# 2. Sign the ABOM
signer = Signer.generate("ed25519")
signer.sign(abom)
abom.to_file("abom-signed.json")

# 3. Verify at runtime
abom = ABOM.from_file("abom-signed.json")
verifier = Verifier(reject_unsigned=True)
verifier.verify(abom)

# 4. Detect drift
detector = DriftDetector(abom)
event = detector.check_tool_authorized("filesystem-mcp")
if event.is_compliant():
    print("✓ Tool authorized")
```

<br>

## Framework Integrations

**Decorator Guard**

```python
from ai_scrm import guard

@guard(tool="web-search")
def search_web(query):
    return search_api.search(query)  # Only runs if authorized
```

**LangChain**

```python
from ai_scrm import langchain_guard

agent = create_react_agent(llm, tools, prompt)
secure_agent = langchain_guard(agent, abom_path="abom.json")
```

**FastAPI Middleware**

```python
from ai_scrm import FastAPIMiddleware

app.add_middleware(FastAPIMiddleware, abom_path="abom.json")
```

**Emergency Bypass**

```python
from ai_scrm import emergency_bypass

with emergency_bypass(reason="Production incident #1234"):
    # All checks disabled, but fully logged
    do_emergency_fix()
```

<br>

## CLI Reference

```bash
# First-time setup (does everything)
ai-scrm init
ai-scrm init --dir ./my-project --no-sign

# Scanning
ai-scrm scan
ai-scrm scan --dir ./models --output results.json

# Status (with live updates)
ai-scrm status
ai-scrm status --watch

# ABOM management
ai-scrm abom validate abom.json --strict
ai-scrm abom info abom.json

# Trust operations
ai-scrm trust keygen --algorithm ed25519
ai-scrm trust sign abom.json --key ./keys/private.pem
ai-scrm trust verify abom-signed.json

# Validation
ai-scrm validation check --abom abom.json
ai-scrm monitor --hash-interval 30

# Change management
ai-scrm approve mcp:new-server --trust internal
ai-scrm reject mcp:suspicious-server
```

<br>

## Full Implementation Guide

See the Implementation Guide https://github.com/kahalewai/ai-scrm/blob/main/python/README.md for full detailed specification and usage.

<br>

## AI-SCRM Features

**Auto-Discovery**

AI-SCRM automatically finds your AI components:

| Component | How It's Discovered |
|-----------|---------------------|
| **Models** | Scans directories for `.safetensors`, `.gguf`, `.pt`, `.onnx` files |
| **MCP Servers** | Parses Claude Desktop config, `mcp.json`, environment variables |
| **Libraries** | Reads `pip list`, `requirements.txt`, `pyproject.toml` |
| **Prompts** | Finds `*.prompt`, `system_prompt*`, `*.jinja2` files |

<br>

**Supported Asset Categories**

AI-SCRM supports all seven AI-SCS asset categories (AI-SCS 4.1):

| Category | Examples | Builder Methods |
|----------|----------|-----------------|
| **Models** | Base models, fine-tuned, adapters | `add_model()`, `add_fine_tuned_model()`, `add_adapter()` |
| **Data** | Training, evaluation datasets | `add_dataset()`, `add_training_data()` |
| **Embeddings** | Embedding models, vector stores | `add_embedding_model()`, `add_vector_store()` |
| **Dependencies** | Frameworks, tokenizers, libraries | `add_library()`, `add_framework()`, `add_tokenizer()` |
| **Agents** | Orchestrators, planners | `add_agent()`, `add_planner()`, `add_orchestrator()` |
| **Tools** | Plugins, MCP servers, APIs | `add_tool()`, `add_mcp_server()`, `add_external_api()` |
| **Infrastructure** | TEEs, accelerators | `add_infrastructure()`, `add_tee()`, `add_accelerator()` |

Plus behavioral artifacts: `add_prompt_template()`, `add_policy()`, `add_guardrail()`

<br>

**Smart Metadata Inference**

AI-SCRM recognizes 100+ model families and automatically fills in:

```python
# Automatically inferred from filename:
"llama-3-8b-instruct.safetensors" → supplier: Meta, type: fine-tuned, params: 8B
"mistral-7b-v0.1.gguf" → supplier: Mistral AI, architecture: mistral
"text-embedding-ada-002.onnx" → supplier: OpenAI, type: embedding
"claude-3-sonnet.bin" → supplier: Anthropic, family: Claude 3
```

<br>

**MCP Server Support**

AI-SCRM provides specific support for Model Context Protocol (MCP) servers:

```python
# MCP servers have mandatory fields per AI-SCS 5.3.5
builder.add_mcp_server(
    name="filesystem-mcp",
    version="1.0.0",
    endpoint="http://localhost:3000",      # REQUIRED
    trust_boundary="internal",              # REQUIRED: internal, external, hybrid
    capabilities=["read", "write", "list"]  # REQUIRED
)

# Runtime validation before connecting
detector = DriftDetector(abom)
event = detector.check_mcp_authorized("filesystem-mcp", endpoint="http://localhost:3000")
if not event.is_compliant():
    raise SecurityError(f"Unauthorized MCP: {event.observation.details}")
```

<br>

**Runtime Validation Scenarios**

AI-SCRM supports various validation scenarios:

* **Startup Validation**: Verify all components before system initialization
* **Continuous Monitoring**: Periodic checks for drift with configurable intervals
* **On-Demand Checks**: Validate specific components before use
* **Tool Authorization**: Check tool/MCP permissions before invocation

```python
# Startup validation
events = detector.check("./deployed-system")
if any(e.event_type == "drift" for e in events):
    raise SecurityError("System integrity compromised")

# Tool authorization before use
if detector.check_tool_authorized("web-search").is_compliant():
    result = web_search_tool.execute(query)
```

<br>

**Continuous Monitoring**

AI-SCRM monitors with three tiers:

| Tier | Default Interval | What It Checks |
|------|------------------|----------------|
| **Hash Check** | 60 seconds | File integrity of known components |
| **MCP Heartbeat** | 5 minutes | MCP server availability |
| **Full Scan** | 30 minutes | Discover new/removed components |

```python
from ai_scrm import Monitor

monitor = Monitor(
    abom_path="abom-signed.json",
    hash_check_interval=30,      # Faster checks
    mcp_heartbeat_interval=120,
    on_drift=lambda e: alert(e)  # Custom handler
)
monitor.start()
```

<br>

**Diff-Based Approval**

When drift is detected:

```bash
$ ai-scrm status

⚠️  2 changes detected:

[NEW] MCP Server: slack-notifications-mcp
      Endpoint: http://localhost:3005
      Action: ai-scrm approve slack-notifications-mcp

[CHANGED] Model: llama-3-8b.safetensors
      Hash: a1b2c3... → x7y8z9...
      Action: ai-scrm approve model:llama-3-8b
```

<br>

**SIEM/SOAR Integration**

AI-SCRM emits structured RADE (Runtime Attestation & Drift Events) for security integration:

```python
from ai_scrm import RADEEmitter, DriftDetector

# Create emitter with handlers
emitter = RADEEmitter(system_name="my-ai-assistant")
emitter.add_file_handler("./logs/rade-events.jsonl")
emitter.add_webhook_handler("https://siem.company.com/api/events")

# Emit events from validation
detector = DriftDetector(abom)
events = detector.check("./deployed-system")
emitter.emit_all(events)

# Events are SIEM-compatible JSON
# {
#   "eventType": "drift",
#   "severity": "critical",
#   "observation": {"type": "model-substitution", ...},
#   "abomBinding": {"serialNumber": "urn:uuid:..."}
# }
```

<br>

## AI-SCRM Conformance

AI-SCRM conforms with all 3 Levels of AI-SCS Control Domains:

| Domain | Purpose | Requirements | AI-SCRM Support |
|--------|---------|--------------|-----------------|
| **CD1** | Inventory & Provenance | ABOM generation, static provenance |  ✅ `Scanner`, `ABOMBuilder` |
| **CD2** | Integrity & Authenticity | Artifact signing, verification |  ✅ `Signer`, `Verifier` |
| **CD3** | Continuous Assurance | Runtime validation, automated detection |  ✅ `Monitor`, `DriftDetector`, `RADEEmitter` |

```python
# Control Domain 1: ABOM
from ai_scrm import ABOMBuilder
builder = ABOMBuilder()
builder.add_model(...)
builder.add_mcp_server(...)
abom = builder.finalize()

# Control Domain 2: Trust
from ai_scrm import Signer, Verifier
signer = Signer.generate("ed25519")
signer.sign(abom)

# Control Domain 3: Validation
from ai_scrm import DriftDetector, RADEEmitter
detector = DriftDetector(abom)
emitter = RADEEmitter()
emitter.add_file_handler("events.jsonl")
```

<br>

## Package Structure

```
ai_scrm/
├── __init__.py              # Main exports
├── abom/                    # Control Domain 1: ABOM
│   ├── models.py            # ABOM, Component, Hash, Property
│   ├── builder.py           # Fluent builder for all asset types
│   └── exceptions.py        # ABOM-specific exceptions
├── trust/                   # Control Domain 2: Trust
│   ├── signing.py           # Ed25519, RSA, ECDSA signers
│   ├── verification.py      # Signature verification
│   └── assertion.py         # Trust assertions (AI-SCS 6.3)
├── validation/              # Control Domain 3: Validation
│   ├── detector.py          # Drift detection
│   ├── events.py            # RADE events (attestation, drift, violation)
│   └── emitter.py           # SIEM/SOAR integration
├── scanner/                 # Auto-Discovery
│   ├── scanner.py           # Main scanner
│   ├── inference.py         # Model metadata inference (100+ models)
│   ├── mcp_discovery.py     # MCP server discovery
│   └── metadata.py          # YAML metadata handling
├── monitor/                 # Continuous Validation
│   └── monitor.py           # Tiered monitoring (hash/heartbeat/scan)
├── integrations/            # Framework Shortcuts
│   └── integrations.py      # guard, langchain_guard, FastAPI
└── cli/                     # Command-Line Interface
    └── __init__.py          # init, scan, status, monitor, etc.
```

<br>

## Version History

| Version | Changes |
|---------|---------|
| 1.0.1 | Minor release: Bug fixes in CLI Syntax and Logic |
| 1.0.0 | Full release: Auto-discovery, smart inference, continuous monitoring, framework integrations, Ed25519/RSA/ECDSA signing, RADE events |

<br>

## License

Apache License 2.0

<br>
<br>
