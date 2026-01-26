# AI-SCRM Implementation Guide

## Securing Your AI Infrastructure with AI Supply Chain Risk Management

**Version:** 1.0.0  
**Standard:** AI-SCS (AI Supply Chain Security) v0.1  
**License:** Apache 2.0

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Quick Start: One Command Setup](#4-quick-start-one-command-setup)
5. [Auto-Discovery & Scanning](#5-auto-discovery--scanning)
6. [Control Domain 1: ABOM Creation](#6-control-domain-1-abom-creation)
7. [Control Domain 2: Trust & Signing](#7-control-domain-2-trust--signing)
8. [Control Domain 3: Runtime Validation](#8-control-domain-3-runtime-validation)
9. [Continuous Monitoring](#9-continuous-monitoring)
10. [Framework Integrations](#10-framework-integrations)
11. [CLI Reference](#11-cli-reference)
12. [CI/CD Integration](#12-cicd-integration)
13. [Best Practices](#13-best-practices)
14. [Troubleshooting](#14-troubleshooting)
15. [Appendix: AI-SCS Compliance Checklist](#15-appendix-ai-scs-compliance-checklist)

---

## 1. Introduction

### What is AI-SCRM?

AI-SCRM (AI Supply Chain Risk Management) is a Python library that implements the AI-SCS (AI Supply Chain Security) standard. It provides tools to:

- **Auto-Discover** your AI system's components (models, MCP servers, libraries, prompts)
- **Document** components using AI Bill of Materials (ABOM)
- **Sign** and verify the integrity of AI artifacts
- **Monitor** continuously for unauthorized changes at runtime

### Why AI Supply Chain Security?

AI systems are uniquely vulnerable because they depend on:

| Asset Type | Risk Examples |
|------------|---------------|
| **Models** | Backdoored weights, malicious fine-tuning, silent replacement |
| **Datasets** | Data poisoning, training data leakage |
| **Tools/MCP** | Unauthorized tool activation, capability escalation |
| **Prompts** | Prompt injection, guardrail bypass |
| **Dependencies** | Supply chain attacks, version hijacking |

AI-SCRM addresses these risks through three **Control Domains**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI-SCS Control Domains                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐         │
│  │  Domain 1    │   │  Domain 2    │   │  Domain 3    │         │
│  │    ABOM      │──▶│   Trust     │──▶│  Validation  │         │
│  │              │   │              │   │              │         │
│  │ • Inventory  │   │ • Signing    │   │ • Detection  │         │
│  │ • Provenance │   │ • Verify     │   │ • Events     │         │
│  │ • Metadata   │   │ • Assertions │   │ • Enforce    │         │
│  └──────────────┘   └──────────────┘   └──────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### What's New in v1.0

| Feature | Description |
|---------|-------------|
| **Auto-Discovery** | Scan for models, MCP servers, libraries, prompts automatically |
| **Smart Inference** | Recognize 100+ model families and auto-fill supplier metadata |
| **Trust Boundaries** | Automatic classification of MCP servers (internal/external) |
| **Continuous Monitoring** | Tiered validation at configurable intervals |
| **Framework Integrations** | One-liner decorators for LangChain, FastAPI |
| **Clear Error Messages** | Actionable errors with fix instructions |
| **Diff-Based Approval** | Easy workflow for approving legitimate changes |

### Conformance Levels

| Level | Name | Requirements |
|-------|------|--------------|
| **Level 1** | Visibility | ABOM generation, static provenance tracking |
| **Level 2** | Integrity | Artifact signing, verification enforcement |
| **Level 3** | Continuous Assurance | Runtime validation, automated detection |

---

## 2. Prerequisites

### System Requirements

- **Python:** 3.9 or higher
- **Operating System:** Linux, macOS, or Windows
- **Memory:** Minimum 512MB RAM
- **Disk:** 50MB for installation

### Optional Dependencies

| Package | Purpose | Required For |
|---------|---------|--------------|
| `cryptography` | Signing & verification | Control Domain 2 |
| `click` | CLI interface | CLI commands |
| `rich` | Pretty terminal output | CLI commands |
| `pyyaml` | Metadata configuration | Metadata files |

### Knowledge Prerequisites

- Basic understanding of your AI system architecture
- Access to model files and configuration
- Understanding of your deployment environment

---

## 3. Installation

### Standard Installation

```bash
pip install ai-scrm
```

### Installation with All Features

```bash
pip install ai-scrm[all]
```

This includes:
- `cryptography` for signing/verification
- `click` and `rich` for CLI
- `pyyaml` for metadata configuration

### Installation for Development

```bash
git clone https://github.com/kahalewai/ai-scrm/python.git
cd ai-scrm
pip install -e ".[dev]"
```

### Verify Installation

```bash
python -c "import ai_scrm; print(f'AI-SCRM v{ai_scrm.__version__} installed successfully')"
```

Expected output:
```
AI-SCRM v1.0.0 installed successfully
```

### Verify CLI

```bash
ai-scrm --version
```

---

## 4. Quick Start: One Command Setup

### The Fastest Path (2 minutes)

```bash
# Initialize everything
ai-scrm init

# View your security status
ai-scrm status

# Start continuous monitoring
ai-scrm monitor
```

That's it! The `init` command:

1. **Scans** for models, MCP servers, libraries, and prompts
2. **Infers** suppliers for known models (Llama, Mistral, GPT, etc.)
3. **Generates** a metadata template for items needing review
4. **Creates** signing keys (Ed25519)
5. **Signs** your ABOM

### What Happens During Init

```
$ ai-scrm init

=== AI-SCRM Initialization ===

Step 1/4: Scanning for AI components...
  Found: 3 models, 47 MCP servers, 156 libraries, 5 prompts

Step 2/4: Generating metadata template...
  Generated: ./ai-scrm-metadata.yaml
  Warning: 1 item needs manual review (marked with TODO)

Step 3/4: Building ABOM...
  Components added: 211

Step 4/4: Generating keys and signing...
  Generated keys: ./keys/
  ABOM signed

  ABOM saved: ./abom-signed.json

==================================================
Initialization complete!
==================================================

Next steps:
  1. Review ./ai-scrm-metadata.yaml (fill in 1 TODO)
  2. Run: ai-scrm sign ./abom-signed.json
  3. Run: ai-scrm status
  4. Run: ai-scrm monitor --daemon
```

### Init Options

```bash
# Scan a specific directory
ai-scrm init --dir ./my-project

# Custom output paths
ai-scrm init --output ./security/abom.json --keys ./security/keys

# Skip signing (for development)
ai-scrm init --no-sign

# Custom metadata file location
ai-scrm init --metadata ./config/ai-scrm-metadata.yaml
```

### 4.1 Manual Quick Start (Alternative)

If you prefer step-by-step control:

```python
from ai_scrm import Scanner, ABOMBuilder, Signer

# 1. Scan for components
scanner = Scanner()
result = scanner.scan(model_dirs=["./models"])
scanner.print_summary(result)

# 2. Build ABOM from scan results
builder = ABOMBuilder()
for model in result.models:
    builder.add_model(
        name=model.name,
        version=model.version,
        hash_value=model.hash_value,
        format=model.format,
        supplier=model.supplier or "Unknown"
    )
for mcp in result.mcp_servers:
    builder.add_mcp_server(
        name=mcp.name,
        version=mcp.version or "1.0.0",
        endpoint=mcp.endpoint,
        trust_boundary=mcp.trust_boundary,
        capabilities=mcp.capabilities
    )
abom = builder.finalize(system_name="my-ai-assistant")

# 3. Sign
signer = Signer.generate("ed25519")
signer.save_keys("./keys")
signer.sign(abom)
abom.to_file("abom-signed.json")

# 4. Verify
from ai_scrm import Verifier, DriftDetector
verifier = Verifier(reject_unsigned=True)
verifier.verify(abom)

detector = DriftDetector(abom)
event = detector.check_tool_authorized("filesystem-mcp")
if event.is_compliant():
    print("✓ Tool authorized")

---

## 5. Auto-Discovery & Scanning

### 5.1 Understanding the Scanner

The Scanner automatically discovers AI components in your environment:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Scanner Discovery Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Directories          Config Files           Environment        │
│  ┌──────────┐         ┌──────────┐          ┌──────────┐        │
│  │ ./models │         │ mcp.json │          │ MCP_*    │        │
│  │ ~/.cache │         │ claude/  │          │ env vars │        │
│  └────┬─────┘         └────┬─────┘          └────┬─────┘        │
│       │                    │                     │              │
│       ▼                    ▼                     ▼              │
│  ┌─────────────────────────────────────────────────────┐        │
│  │                    SCANNER                          │        │
│  │  • Model files (.safetensors, .gguf, .pt)           │        │
│  │  • MCP server configs                               │        │
│  │  • Python libraries (pip, requirements.txt)         │        │
│  │  • Prompt templates                                 │        │
│  └─────────────────────────────────────────────────────┘        │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────┐        │
│  │                  SCAN RESULT                        │        │
│  │  Models: 3    MCP: 47    Libraries: 156    Prompts: 5│       │
│  └─────────────────────────────────────────────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 What Gets Discovered

| Component | Discovery Method | Auto-Inferred |
|-----------|------------------|---------------|
| **Models** | File extension scan (.safetensors, .gguf, .pt, .onnx) | Supplier, architecture, parameters, format |
| **MCP Servers** | Config file parsing, environment variables | Trust boundary, capabilities |
| **Libraries** | pip list, requirements.txt, pyproject.toml | Version |
| **Prompts** | Pattern matching (*.prompt, system_prompt*) | Prompt type |

### 5.3 Using the Scanner

#### Basic Scan

```python
from ai_scrm import Scanner

scanner = Scanner()
result = scanner.scan()

# Print summary
scanner.print_summary(result)
```

Output:
```
============================================================
  AI-SCRM Scan Results
============================================================

  Scan completed: 2024-01-20T15:30:00Z
  Directories scanned: .

  📦 Models:        3
  🔌 MCP Servers:  47
  📚 Libraries:   156
  📝 Prompts:       5

  ✓ All items have complete metadata

============================================================
```

#### Scan Specific Directories

```python
result = scanner.scan(
    model_dirs=["./models", "./weights"],
    prompt_dirs=["./prompts", "./templates"],
    scan_cwd=True,
    scan_huggingface_cache=True,
    scan_libraries=True,
    scan_mcp=True
)
```

#### CLI Scan

```bash
# Basic scan
ai-scrm scan

# Scan specific directory
ai-scrm scan --dir ./models

# Output results to JSON
ai-scrm scan --output scan-results.json
```

### 5.4 Smart Model Inference

AI-SCRM recognizes 100+ model families and automatically infers metadata:

```python
from ai_scrm.scanner import infer_model_info

# Automatic inference from filename
info = infer_model_info("llama-3-8b-instruct.safetensors")
print(f"Supplier: {info.supplier}")      # "Meta"
print(f"Architecture: {info.architecture}")  # "llama"
print(f"Family: {info.family}")          # "Llama 3"
print(f"Parameters: {info.parameters}")  # "8B"
print(f"Type: {info.model_type}")        # "fine-tuned" (detected from "instruct")
```

#### Supported Model Families

| Provider | Model Patterns Recognized |
|----------|---------------------------|
| **Meta** | llama, llama-2, llama-3, codellama |
| **Mistral AI** | mistral, mixtral, codestral, mistral-nemo |
| **OpenAI** | gpt-4, gpt-3.5, whisper, text-embedding |
| **Anthropic** | claude, claude-3-opus, claude-3-sonnet |
| **Google** | gemma, gemini, bert, t5, palm |
| **Microsoft** | phi, phi-2, phi-3, orca, e5 |
| **Cohere** | command, command-r, embed |
| **Alibaba** | qwen, qwen-2 |
| **DeepSeek** | deepseek, deepseek-coder |
| **Stability AI** | stable-diffusion, stablelm |
| **Others** | falcon, bloom, yi, vicuna, zephyr, starcoder |

#### Format Detection

```python
from ai_scrm.scanner import infer_format_from_extension, infer_quantization

# Format from extension
format = infer_format_from_extension("model.safetensors")  # "safetensors"
format = infer_format_from_extension("model.gguf")         # "gguf"

# Quantization from filename
quant = infer_quantization("model-q4_k_m.gguf")  # "GGUF-Q4_K_M"
quant = infer_quantization("model-awq.safetensors")  # "AWQ"
```

### 5.5 MCP Server Discovery

#### Discovery Sources

AI-SCRM discovers MCP servers from multiple sources:

```python
from ai_scrm.scanner import MCPDiscovery

discovery = MCPDiscovery()
servers = discovery.discover_all()

for server in servers:
    print(f"{server.name}: {server.endpoint} ({server.trust_boundary})")
```

#### Configuration Files Checked

```
MCP Configuration Sources (in order):
├── Claude Desktop
│   ├── macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
│   ├── Windows: ~/AppData/Roaming/Claude/claude_desktop_config.json
│   └── Linux: ~/.config/claude/claude_desktop_config.json
├── Project configs
│   ├── ./mcp.json
│   ├── ./mcp-servers.json
│   └── ./.mcp/config.json
└── Environment
    ├── $MCP_CONFIG_PATH
    └── $MCP_* variables
```

#### Claude Desktop Config Format

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "xxx"}
    }
  }
}
```

### 5.6 Trust Boundary Classification

MCP servers are automatically classified into trust boundaries:

```python
from ai_scrm.scanner import TrustBoundaryClassifier

classifier = TrustBoundaryClassifier(default_boundary="external")

# Built-in patterns (automatic)
classifier.classify("http://localhost:3000")     # "internal"
classifier.classify("http://127.0.0.1:8080")     # "internal"
classifier.classify("http://192.168.1.100:3000") # "internal"
classifier.classify("http://10.0.0.50:3000")     # "internal"
classifier.classify("stdio://npx server")        # "internal"
classifier.classify("https://api.example.com")   # "external"

# Add custom patterns
classifier.add_pattern("*.internal.mycompany.com", "internal")
classifier.add_pattern("*.mycompany.com", "hybrid")
```

#### Default Classification Rules

| Pattern | Trust Boundary |
|---------|----------------|
| `localhost:*` | internal |
| `127.0.0.1:*` | internal |
| `[::1]:*` | internal |
| `10.*` | internal |
| `172.16-31.*` | internal |
| `192.168.*` | internal |
| `stdio://` | internal |
| Everything else | external |

### 5.7 Metadata Configuration

For components that need manual input, create `ai-scrm-metadata.yaml`:

```yaml
# ai-scrm-metadata.yaml
# Generated by ai-scrm init - review and update TODOs

# Model metadata patterns
models:
  # Auto-discovered models with inferred metadata
  "llama-3-8b*":
    supplier: "Meta"
    type: fine-tuned
    family: "Llama 3"
  
  # Custom model needing manual input
  "custom-model*":
    supplier: "TODO"  # <-- Fill this in
    type: base

# Trust boundary patterns
trust_boundaries:
  "localhost:*": internal
  "127.0.0.1:*": internal
  "*.internal.mycompany.com": internal
  "*": external  # Default

# Agent permissions (design decision - cannot auto-discover)
agents:
  research-agent:
    permitted_tools:
      - web-search
      - file-reader
    permitted_mcp:
      - filesystem-mcp
    autonomy_level: supervised

# Datasets (cannot be auto-discovered at runtime)
datasets:
  - name: training-data-v1
    version: "2024-01"
    source: internal
    type: fine-tuning

# Default values
defaults:
  trust_boundary: external
  model_type: base
```

#### Loading and Applying Metadata

```python
from ai_scrm.scanner import MetadataEnricher

enricher = MetadataEnricher("./ai-scrm-metadata.yaml")
enricher.enrich(scan_result)

# Now scan_result.models have supplier filled in from patterns
```

### 5.8 Handling Items Needing Review

After scanning, some items may need manual input:

```python
result = scanner.scan()

# Check what needs review
for model in result.models:
    if model.needs_review:
        print(f"Model '{model.name}' needs: {', '.join(model.needs_review)}")
```

Output:
```
Model 'custom-internal-model' needs: supplier
```

#### Fixing with CLI

```bash
# View items needing review
ai-scrm status

# The metadata template shows TODOs
cat ai-scrm-metadata.yaml | grep TODO
```

### 5.9 Scan Result Structure

```python
from ai_scrm.scanner import ScanResult

result: ScanResult = scanner.scan()

# Access discovered components
result.models        # List[DiscoveredModel]
result.mcp_servers   # List[DiscoveredMCP]
result.libraries     # List[DiscoveredLibrary]
result.prompts       # List[DiscoveredPrompt]

# Summary
result.summary()     # {'models': 3, 'mcp_servers': 47, ...}

# Serialize
result.to_dict()     # Full JSON-serializable dict
```
```


---

## 6. Control Domain 1: ABOM Creation

### 6.1 Understanding ABOM Structure

An ABOM (AI Bill of Materials) is a machine-readable inventory of all components in your AI system. It follows the CycloneDX 1.6 format with AI-SCS extensions.

```
ABOM Structure
├── metadata
│   ├── system name & version
│   ├── ai-scs:profile = "ABOM"
│   └── ai-scs:version = "0.1"
├── components[]
│   ├── models (weights, adapters)
│   ├── datasets (training, evaluation)
│   ├── embeddings (models, vector stores)
│   ├── dependencies (libraries, frameworks)
│   ├── agents (orchestrators, planners)
│   ├── tools (plugins, MCP servers, APIs)
│   ├── infrastructure (TEEs, accelerators)
│   └── behavioral (prompts, policies)
├── dependencies[]
│   └── dependency relationships
└── signature (optional)
```

### 6.2 Building from Scan Results (Recommended)

The easiest way to create an ABOM is from scan results:

```python
from ai_scrm import Scanner, ABOMBuilder

# Scan
scanner = Scanner()
result = scanner.scan()

# Build ABOM from results
builder = ABOMBuilder()

for model in result.models:
    builder.add_model(
        name=model.name,
        version=model.version,
        hash_value=model.hash_value,
        format=model.format or "unknown",
        supplier=model.supplier or "Unknown",
        model_type=model.model_type,
        architecture=model.architecture,
        parameters=model.parameters
    )

for mcp in result.mcp_servers:
    builder.add_mcp_server(
        name=mcp.name,
        version=mcp.version or "1.0.0",
        endpoint=mcp.endpoint,
        trust_boundary=mcp.trust_boundary,
        capabilities=mcp.capabilities or ["unknown"]
    )

for lib in result.libraries[:50]:  # Top 50 libraries
    builder.add_library(name=lib.name, version=lib.version)

abom = builder.finalize(
    system_name="my-ai-assistant",
    system_version="1.0.0"
)
```

### 6.3 Adding Models (AI-SCS 4.1.1, 5.3.1)

#### Base Models

```python
builder.add_model(
    name="llama-3-8b",
    version="1.0.0",
    hash_value="a1b2c3d4...",       # REQUIRED: SHA-256 of model file
    format="safetensors",            # REQUIRED: safetensors, gguf, pt, etc.
    supplier="Meta",                 # REQUIRED: Source organization
    model_type="base",               # Optional: base, fine-tuned, adapter
    architecture="llama",            # Optional: Model architecture
    parameters="8B"                  # Optional: Parameter count
)
```

#### Fine-Tuned Models

```python
builder.add_fine_tuned_model(
    name="llama-3-8b-customer-support",
    version="1.0.0",
    hash_value="x1y2z3w4...",
    base_model_ref="model:llama-3-8b@1.0.0",  # REQUIRED: Reference to base
    format="safetensors",
    supplier="My Organization"
)
```

#### Adapters (LoRA, PEFT)

```python
builder.add_adapter(
    name="customer-support-lora",
    version="1.0.0",
    hash_value="p1q2r3s4...",
    base_model_ref="model:llama-3-8b@1.0.0",
    adapter_type="lora",             # lora, peft, qlora
    rank="16"                        # LoRA rank
)
```

### 6.4 Adding Datasets (AI-SCS 4.1.2, 5.3.2)

```python
# Training dataset
builder.add_dataset(
    name="customer-support-conversations",
    version="2024-01-15",
    data_type="fine-tuning",         # REQUIRED: training, fine-tuning, evaluation
    source="internal",               # REQUIRED: Source of data
    hash_value="d1e2f3g4...",        # Recommended: For immutability
    license="proprietary",           # If applicable
    record_count="50000"
)

# Evaluation dataset
builder.add_evaluation_data(
    name="support-eval-set",
    version="1.0",
    source="internal",
    record_count="1000"
)
```

### 6.5 Adding Embeddings (AI-SCS 4.1.3, 5.3.4)

```python
# Embedding model
builder.add_embedding_model(
    name="text-embedding-ada-002",
    version="2.0",
    hash_value="e1f2g3h4...",
    dimension="1536",                # Vector dimension
    supplier="OpenAI"
)

# Vector store
builder.add_vector_store(
    name="knowledge-base-index",
    version="2024-01-20",
    index_type="HNSW",               # HNSW, IVF, Flat, etc.
    update_policy="append-only",     # REQUIRED: append-only, replace, incremental
    embedding_model_ref="model:text-embedding-ada-002@2.0"
)
```

### 6.6 Adding Dependencies (AI-SCS 4.1.4, 5.3.3)

```python
# Python libraries
builder.add_library(name="transformers", version="4.36.0")
builder.add_library(name="torch", version="2.1.0")
builder.add_library(name="langchain", version="0.1.0")

# Framework
builder.add_framework(name="vllm", version="0.2.7")

# Tokenizer
builder.add_tokenizer(
    name="llama-tokenizer",
    version="1.0",
    hash_value="t1u2v3w4..."
)

# Inference engine
builder.add_inference_engine(name="triton", version="2.41.0")
```

### 6.7 Adding Agents (AI-SCS 4.1.5, 5.3.5)

```python
builder.add_agent(
    name="research-assistant",
    version="1.0.0",
    agent_type="orchestrator",       # agent, planner, orchestrator
    permitted_tools=[                # REQUIRED: List of allowed tools
        "tool:web-search@1.0",
        "tool:file-reader@1.0",
        "mcp:filesystem-mcp@1.0"
    ],
    autonomy_level="supervised"      # supervised, autonomous, hybrid
)

# Planner component
builder.add_planner(
    name="task-planner",
    version="1.0",
    permitted_tools=["tool:calculator@1.0"]
)
```

### 6.8 Adding Tools & MCP Servers (AI-SCS 4.1.6, 5.3.5)

#### Simple Tools

```python
builder.add_tool(
    name="web-search",
    version="1.0",
    tool_type="plugin",              # plugin, function-call
    capability="Search the web for current information"
)

builder.add_tool(
    name="code-executor",
    version="1.0",
    tool_type="function-call",
    capability="Execute Python code in sandbox",
    has_side_effects=True            # Important for risk assessment
)
```

#### MCP Servers (Model Context Protocol)

MCP servers have stricter requirements due to their elevated capabilities:

```python
builder.add_mcp_server(
    name="filesystem-mcp",
    version="1.0.0",
    endpoint="http://localhost:3000/mcp",    # REQUIRED
    trust_boundary="internal",                # REQUIRED: internal, external, hybrid
    capabilities=["read_file", "write_file", "list_directory"]  # REQUIRED
)

builder.add_mcp_server(
    name="database-mcp",
    version="1.0.0",
    endpoint="http://localhost:3001/mcp",
    trust_boundary="internal",
    capabilities=["query", "insert", "update"]
)
```

#### External APIs

```python
builder.add_external_api(
    name="openai-api",
    version="v1",
    endpoint="https://api.openai.com/v1",
    trust_boundary="external",
    capability="LLM inference and embeddings"
)
```

### 6.9 Adding Behavioral Artifacts (AI-SCS 5.3.6)

```python
# System prompt
builder.add_prompt_template(
    name="system-prompt-v1",
    version="1.0.0",
    prompt_type="system",            # system, agent, tool, guardrail
    hash_value="p1r2o3m4..."         # Recommended: Detect modifications
)

# Guardrail policy
builder.add_policy(
    name="content-filter",
    version="1.0.0",
    policy_type="guardrail",         # guardrail, routing, retrieval
    enforcement="block",             # block, warn, log
    hash_value="g1u2a3r4..."
)

# Routing policy
builder.add_policy(
    name="model-router",
    version="1.0.0",
    policy_type="routing",
    enforcement="enforce"
)
```

### 6.10 Adding Infrastructure (AI-SCS 4.1.7)

```python
# Execution environment
builder.add_infrastructure(
    name="aws-sagemaker",
    version="2024.1",
    infra_type="execution-environment"
)

# Trusted Execution Environment
builder.add_tee(
    name="azure-confidential-compute",
    version="1.0",
    tee_type="SGX"                   # SGX, SEV, TDX
)

# Accelerator
builder.add_accelerator(
    name="nvidia-h100",
    version="sm_90",
    accelerator_type="GPU"           # GPU, TPU, NPU
)
```

### 6.11 Adding Dependencies Between Components

```python
# Agent depends on model and tools
builder.add_dependency(
    from_ref="agent:research-assistant@1.0.0",
    to_refs=[
        "model:llama-3-8b@1.0.0",
        "tool:web-search@1.0",
        "mcp:filesystem-mcp@1.0.0"
    ]
)

# Model depends on tokenizer
builder.add_dependency(
    from_ref="model:llama-3-8b@1.0.0",
    to_refs=["lib:llama-tokenizer@1.0"]
)
```

### 6.12 Finalizing the ABOM

```python
abom = builder.finalize(
    system_name="my-ai-assistant",
    system_version="1.0.0",
    system_type="agent",             # llm, agent, pipeline, rag, hybrid
    runtime="cloud",                 # cloud, on-prem, edge, tee, hybrid
    validate=True                    # Validate against AI-SCS
)

# Check for compliance issues
issues = abom.validate_ai_scs()
if issues:
    print("AI-SCS Compliance Issues:")
    for issue in issues:
        print(f"  - {issue}")
else:
    print("✓ Fully AI-SCS compliant")

# Save ABOM
abom.to_file("abom.json")
```

### 6.13 Computing Model Hashes

To compute the SHA-256 hash of a model file:

```python
import hashlib

def compute_file_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Usage
model_hash = compute_file_hash("./models/llama-3-8b.safetensors")
print(f"Model hash: {model_hash}")
```

**Note:** The Scanner computes hashes automatically during discovery.

---

## 7. Control Domain 2: Trust & Signing

### 7.1 Understanding Trust in AI-SCS

Trust in AI-SCS is established through:

1. **Cryptographic Signatures** - Prove ABOM hasn't been tampered with
2. **Trust Assertions** - Individual statements about artifact integrity
3. **Verification** - Runtime checks before using artifacts

### 7.2 Generating Signing Keys

AI-SCRM supports three signature algorithms:

| Algorithm | Key Size | Signature Size | Recommendation |
|-----------|----------|----------------|----------------|
| Ed25519 | 32 bytes | 64 bytes | **Recommended** - Fast, secure |
| RSA-PSS | 4096 bits | 512 bytes | Wide compatibility |
| ECDSA P-256 | 256 bits | 64 bytes | Good balance |

```python
from ai_scrm import Signer

# Generate Ed25519 keys (recommended)
signer = Signer.generate("ed25519")

# Or RSA for compatibility
signer = Signer.generate("rsa")

# Or ECDSA
signer = Signer.generate("ecdsa")

# Save keys to files
signer.save_keys("./keys")
# Creates:
#   ./keys/private.pem  (keep secret!)
#   ./keys/public.pem   (distribute freely)
```

### 7.3 Signing an ABOM

```python
from ai_scrm import ABOM, Signer

# Load ABOM
abom = ABOM.from_file("abom.json")

# Load existing key or generate new
signer = Signer.from_file("./keys/private.pem", "ed25519")
# Or: signer = Signer.generate("ed25519")

# Sign the ABOM
signer.sign(abom)

# The signature is now embedded in the ABOM
print(f"Signed with: {abom.signature['algorithm']}")
print(f"Public key embedded: {abom.signature['publicKey'][:50]}...")

# Save signed ABOM
abom.to_file("abom-signed.json")
```

### 7.4 Verifying an ABOM

```python
from ai_scrm import ABOM, Verifier
from ai_scrm.trust.exceptions import VerificationError

# Load signed ABOM
abom = ABOM.from_file("abom-signed.json")

# Create verifier
verifier = Verifier(reject_unsigned=True)

try:
    # Verify signature
    verifier.verify(abom)
    print("✓ ABOM signature valid")
except VerificationError as e:
    print(f"✗ Verification failed: {e}")
    # Handle security incident
```

### 7.5 Trust Assertions

Trust Assertions are individual statements about specific artifacts:

```python
from ai_scrm.trust import TrustAssertionBuilder

# Create assertion builder
assertion_builder = TrustAssertionBuilder(
    issuer_name="My Organization Security Team",
    issuer_id="urn:ai-scs:issuer:my-org:security",
    validity_days=365
)

# Create assertion for a specific component
model = abom.get_models()[0]
assertion = assertion_builder.create_for_component(model, abom)

# Save assertion
assertion.to_file("assertions/model-assertion.json")

# Check expiration
if assertion.is_expired():
    print("WARNING: Trust assertion has expired")
```

### 7.6 Key Management Best Practices

```
Key Management Hierarchy
├── Root Signing Key (offline, HSM)
│   └── Used to sign intermediate keys
├── Intermediate Signing Keys (secure server)
│   └── Used for production signing
└── Development Keys (developer machines)
    └── Used for testing only

Key Storage:
├── Production: HSM, AWS KMS, Azure Key Vault, HashiCorp Vault
├── CI/CD: Encrypted secrets, OIDC authentication
└── Development: Local files (never commit!)
```

**Security Checklist:**
- [ ] Never commit private keys to version control
- [ ] Use environment variables or secret managers in CI/CD
- [ ] Rotate keys annually or after security incidents
- [ ] Keep root keys offline and air-gapped
- [ ] Distribute public keys through secure channels

---

## 8. Control Domain 3: Runtime Validation

### 8.1 Understanding Runtime Validation

Runtime validation detects deviations between your declared ABOM and the actual system state:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Runtime Validation Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Declared (ABOM)              Actual (Runtime)                 │
│   ┌─────────────┐              ┌─────────────┐                  │
│   │ model: abc  │    Compare   │ model: xyz  │   ⚠️ DRIFT!     │
│   │ hash: 123   │ ──────────▶ │ hash: 789    │                 │
│   └─────────────┘              └─────────────┘                  │
│                                                                 │
│   Detection ──▶ Event ──▶ Enforcement ──▶ Alert               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Initializing the Drift Detector

```python
from ai_scrm import ABOM, DriftDetector

# Load verified ABOM
abom = ABOM.from_file("abom-signed.json")

# Initialize detector
detector = DriftDetector(
    abom=abom,
    system_name="my-ai-assistant",
    environment="production"
)
```

### 8.3 Checking Model Integrity

```python
import hashlib

def get_model_hash(filepath):
    """Compute hash of loaded model file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Before loading a model, verify it
model_path = "./models/llama-3-8b.safetensors"
actual_hash = get_model_hash(model_path)

event = detector.check_component(
    bom_ref="model:llama-3-8b@1.0.0",
    actual_hash=actual_hash
)

if event.is_compliant():
    print("✓ Model integrity verified")
    # Proceed to load model
else:
    print(f"✗ SECURITY ALERT: {event.observation.details}")
    print(f"  Expected: {event.observation.expected}")
    print(f"  Actual: {event.observation.actual}")
    # DO NOT load the model - handle security incident
```

### 8.4 Checking Tool Authorization

Before allowing an agent to use a tool:

```python
def authorize_tool(tool_name: str) -> bool:
    """Check if tool is authorized before use."""
    event = detector.check_tool_authorized(tool_name)
    
    if event.is_compliant():
        return True
    else:
        print(f"BLOCKED: Unauthorized tool '{tool_name}'")
        return False

# In your agent code
if authorize_tool("web-search"):
    result = web_search_tool.execute(query)
else:
    result = "Tool not authorized"
```

### 8.5 Checking MCP Server Authorization

```python
def authorize_mcp(server_name: str, endpoint: str) -> bool:
    """Verify MCP server before connecting."""
    event = detector.check_mcp_authorized(
        server_name=server_name,
        endpoint=endpoint
    )
    
    if event.is_compliant():
        return True
    elif event.event_type == "drift":
        print(f"WARNING: MCP endpoint mismatch for '{server_name}'")
        print(f"  Declared: {event.observation.expected}")
        print(f"  Actual: {event.observation.actual}")
        return False
    else:  # violation
        print(f"BLOCKED: Undeclared MCP server '{server_name}'")
        return False

# Before connecting to MCP
if authorize_mcp("filesystem-mcp", "http://localhost:3000"):
    mcp_client.connect("http://localhost:3000")
```

### 8.6 Directory Scanning

Scan a deployment directory for drift:

```python
# Scan deployed system
events = detector.check("./deployed-system")

# Process results
compliant = 0
drift = 0
violations = 0

for event in events:
    if event.is_compliant():
        compliant += 1
    elif event.event_type == "drift":
        drift += 1
        print(f"DRIFT: {event.observation.details}")
    elif event.event_type == "violation":
        violations += 1
        print(f"VIOLATION: {event.observation.details}")

print(f"\nResults: {compliant} compliant, {drift} drift, {violations} violations")
```

### 8.7 Event Emission (SIEM Integration)

```python
from ai_scrm import RADEEmitter

# Create emitter with handlers
emitter = RADEEmitter(
    system_name="my-ai-assistant",
    environment="production",
    fail_on_critical=True  # Raise exception on critical events
)

# File handler (JSONL for log aggregation)
emitter.add_file_handler("./logs/rade-events.jsonl")

# Custom webhook handler (SIEM integration)
def send_to_siem(event):
    import requests
    requests.post(
        "https://siem.company.com/api/events",
        json=event.to_dict(),
        headers={"Authorization": "Bearer <token>"}
    )

emitter.add_handler(send_to_siem)

# Emit events from detector
events = detector.check("./deployed-system")
emitter.emit_all(events)

# Get statistics
stats = emitter.get_statistics()
print(f"Emitted: {stats['total_events']} events")
print(f"  Drift: {stats['drift_events']}")
print(f"  Violations: {stats['violation_events']}")
```

### 8.8 Policy-Based Enforcement

```python
from ai_scrm.validation import PolicyEngine, EnforcementAction

# Define enforcement actions
def block_execution(event):
    print(f"BLOCKING: {event.observation.details}")
    raise SecurityException("Execution blocked due to policy violation")

def send_alert(event):
    # Send to PagerDuty, Slack, etc.
    print(f"ALERT: {event.observation.details}")

def log_and_continue(event):
    print(f"LOGGED: {event.observation.details}")

# Create policy engine
policy = PolicyEngine()

# Critical events → Block
policy.add_rule(
    condition=lambda e: e.severity == "critical",
    action=block_execution
)

# Drift events → Alert
policy.add_rule(
    condition=lambda e: e.event_type == "drift",
    action=send_alert
)

# Other events → Log
policy.add_rule(
    condition=lambda e: True,
    action=log_and_continue
)

# Integrate with emitter
emitter.add_handler(policy.evaluate)
```

---

## 9. Continuous Monitoring

### 9.1 Understanding Continuous Monitoring

AI-SCRM provides tiered continuous validation to balance security with performance:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Monitoring Tiers                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Tier 1: Hash Check          [Every 60 seconds]                 │
│  ├── Verify file integrity of known components                  │
│  ├── Fast: Only computes hashes, compares to ABOM               │
│  └── Detects: File tampering, silent replacement                │
│                                                                 │
│  Tier 2: MCP Heartbeat       [Every 5 minutes]                  │
│  ├── Ping MCP servers to verify availability                    │
│  ├── Medium: HTTP/TCP connectivity check                        │
│  └── Detects: Server down, endpoint hijacking                   │
│                                                                 │
│  Tier 3: Full Re-scan        [Every 30 minutes]                 │
│  ├── Complete system discovery                                  │
│  ├── Slow: Full scanner run                                     │
│  └── Detects: New components, removed components                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Using the Monitor

```python
from ai_scrm import Monitor, MonitorConfig

# Configure monitoring intervals
config = MonitorConfig(
    hash_check_interval=60,       # Seconds between hash checks
    mcp_heartbeat_interval=300,   # Seconds between MCP pings
    full_scan_interval=1800,      # Seconds between full scans
    fail_on_critical=False        # Don't raise on critical events
)

# Create monitor
monitor = Monitor(
    abom_path="abom-signed.json",
    config=config
)

# Start monitoring (background thread)
monitor.start()

# ... your application runs ...

# Stop monitoring
monitor.stop()
```

### 9.3 Event Handlers

```python
def on_drift_detected(event):
    """Called when drift is detected."""
    print(f"⚠️  DRIFT: {event.observation.details}")
    # Send alert, log, etc.

def on_violation_detected(event):
    """Called when a violation occurs."""
    print(f"🚨 VIOLATION: {event.observation.details}")
    # Block, alert, etc.

monitor = Monitor(
    abom_path="abom-signed.json",
    on_drift=on_drift_detected,
    on_violation=on_violation_detected
)
```

### 9.4 Monitor Status

```python
# Get current status
status = monitor.get_status()

print(f"State: {status.state.value}")
print(f"Last hash check: {status.last_hash_check}")
print(f"Last MCP heartbeat: {status.last_mcp_heartbeat}")
print(f"Last full scan: {status.last_full_scan}")
print(f"Drift events: {status.drift_events}")
print(f"Violations: {status.violations}")
print(f"Uptime: {status.uptime_seconds}s")
```

### 9.5 Manual Checks

```python
# Run all checks immediately
events = monitor.check_now()

for event in events:
    if not event.is_compliant():
        print(f"{event.event_type}: {event.observation.details}")
```

### 9.6 CLI Monitor

```bash
# Start monitoring with defaults
ai-scrm monitor

# Custom intervals
ai-scrm monitor --hash-interval 30 --mcp-interval 120 --scan-interval 900

# Output events to file
ai-scrm monitor --output ./logs/events.jsonl

# View live status
ai-scrm status --watch
```

### 9.7 Monitor with SIEM Integration

```python
from ai_scrm import Monitor, RADEEmitter

# Create emitter with multiple handlers
emitter = RADEEmitter(system_name="my-ai-assistant")
emitter.add_file_handler("./logs/rade-events.jsonl")
emitter.add_webhook_handler("https://siem.company.com/api/events")

# Create monitor with emitter
monitor = Monitor(
    abom_path="abom-signed.json",
    emitter=emitter
)

monitor.start()
```

### 9.8 Production Monitoring Pattern

```python
import signal
import sys
from ai_scrm import Monitor, MonitorConfig, RADEEmitter

def main():
    # Configure for production
    config = MonitorConfig(
        hash_check_interval=60,
        mcp_heartbeat_interval=300,
        full_scan_interval=1800,
        fail_on_critical=False,
        model_dirs=["./models", "/opt/ai/models"]
    )
    
    # SIEM integration
    emitter = RADEEmitter(
        system_name="production-ai",
        environment="production"
    )
    emitter.add_file_handler("/var/log/ai-scrm/events.jsonl")
    emitter.add_webhook_handler(os.environ["SIEM_WEBHOOK_URL"])
    
    # Create monitor
    monitor = Monitor(
        abom_path="/etc/ai-scrm/abom-signed.json",
        config=config,
        emitter=emitter,
        on_violation=lambda e: sys.exit(1) if e.severity == "critical" else None
    )
    
    # Handle shutdown gracefully
    def shutdown(signum, frame):
        print("\nShutting down monitor...")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    
    # Start monitoring
    print("Starting AI-SCRM monitor...")
    monitor.start(daemon=False)  # Block main thread

if __name__ == "__main__":
    main()
```

---

## 10. Framework Integrations

### 10.1 Guard Decorator

The simplest way to add AI-SCRM checks to your code:

```python
from ai_scrm import guard

# Guard a tool function
@guard(tool="web-search")
def search_web(query: str):
    """Only executes if web-search is authorized in ABOM."""
    return search_api.search(query)

# Guard an MCP call
@guard(mcp="filesystem-mcp")
def read_file(path: str):
    """Only executes if filesystem-mcp is authorized."""
    return mcp_client.read(path)

# Custom ABOM path
@guard(tool="calculator", abom_path="./security/abom.json")
def calculate(expression: str):
    return eval(expression)  # Only if authorized
```

#### Guard with Custom Handler

```python
def on_blocked(event):
    """Called when guard blocks execution."""
    logger.warning(f"Blocked: {event.observation.details}")
    send_alert(event)

@guard(tool="dangerous-tool", on_violation=on_blocked, raise_on_violation=False)
def dangerous_operation():
    # Returns None instead of raising if blocked
    pass
```

### 10.2 LangChain Integration

```python
from langchain.agents import create_react_agent, AgentExecutor
from ai_scrm import langchain_guard

# Create your agent normally
llm = ChatOpenAI(model="gpt-4")
tools = [web_search, file_reader, calculator]
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

# Wrap with AI-SCRM guard
secure_executor = langchain_guard(
    executor,
    abom_path="abom-signed.json",
    on_violation=lambda e: print(f"Blocked: {e}")
)

# Use normally - tools are validated before each use
result = secure_executor.invoke({"input": "Search for AI news"})
```

#### Custom LangChain Integration

```python
from langchain.agents import AgentExecutor
from ai_scrm import DriftDetector, ABOM

class SecureAgentExecutor(AgentExecutor):
    """Agent executor with AI-SCS validation."""
    
    def __init__(self, *args, detector: DriftDetector, **kwargs):
        super().__init__(*args, **kwargs)
        self.detector = detector
    
    def _should_use_tool(self, tool_name: str) -> bool:
        """Check tool authorization before use."""
        event = self.detector.check_tool_authorized(tool_name)
        if not event.is_compliant():
            print(f"BLOCKED: {tool_name} - {event.observation.details}")
            return False
        return True
    
    def invoke(self, input, config=None, **kwargs):
        # Verify tools before execution
        for tool in self.tools:
            if not self._should_use_tool(tool.name):
                raise SecurityError(f"Unauthorized tool: {tool.name}")
        return super().invoke(input, config, **kwargs)

# Usage
abom = ABOM.from_file("abom-signed.json")
detector = DriftDetector(abom)
secure_executor = SecureAgentExecutor(
    agent=agent,
    tools=tools,
    detector=detector
)
```

### 10.3 FastAPI Integration

#### Middleware Approach

```python
from fastapi import FastAPI
from ai_scrm import FastAPIMiddleware

app = FastAPI()

# Add AI-SCRM middleware
app.add_middleware(
    FastAPIMiddleware,
    abom_path="abom-signed.json",
    mcp_path_prefix="/mcp/",  # Protect MCP endpoints
    on_violation=lambda e: logger.warning(e)
)

@app.post("/mcp/{server_name}/invoke")
async def invoke_mcp(server_name: str, request: dict):
    # Middleware validates server_name against ABOM
    return await mcp_client.invoke(server_name, request)
```

#### Dependency Injection Approach

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from ai_scrm import ABOM, Verifier, DriftDetector

app = FastAPI()

# Load ABOM on startup
@app.on_event("startup")
async def startup():
    app.state.abom = ABOM.from_file("abom-signed.json")
    verifier = Verifier(reject_unsigned=True)
    verifier.verify(app.state.abom)
    app.state.detector = DriftDetector(app.state.abom)

# Dependency for MCP authorization
async def authorize_mcp(request: Request, server_name: str):
    detector = request.app.state.detector
    event = detector.check_mcp_authorized(server_name)
    if not event.is_compliant():
        raise HTTPException(
            status_code=403,
            detail=f"Unauthorized MCP: {event.observation.details}"
        )
    return True

@app.post("/mcp/{server_name}/invoke")
async def invoke_mcp(
    server_name: str,
    request: dict,
    authorized: bool = Depends(authorize_mcp)
):
    return await mcp_client.invoke(server_name, request)
```

### 10.4 Emergency Bypass

For production incidents where you need to temporarily disable checks:

```python
from ai_scrm import emergency_bypass

# All checks disabled within this block, but FULLY LOGGED
with emergency_bypass(reason="Production incident #1234"):
    # Do emergency fix
    result = dangerous_operation()
    
# Checks are re-enabled after the block
```

#### Custom Logging

```python
def incident_logger(message: str):
    """Log to incident management system."""
    logger.critical(f"EMERGENCY BYPASS: {message}")
    pagerduty.send_event(message)

with emergency_bypass(
    reason="Incident #1234 - Customer escalation",
    log_callback=incident_logger
):
    # Emergency operations here
    pass
```

#### Check Bypass Status

```python
from ai_scrm import is_bypass_active, get_bypass_reason

if is_bypass_active():
    print(f"⚠️  Bypass active: {get_bypass_reason()}")
```

---

## 11. CLI Reference

### 11.1 Init Command

Initialize AI-SCRM for a project:

```bash
# Full initialization (scan + keys + sign)
ai-scrm init

# Options
ai-scrm init --dir ./my-project        # Scan specific directory
ai-scrm init --output ./abom.json      # Custom ABOM path
ai-scrm init --metadata ./config.yaml  # Custom metadata path
ai-scrm init --keys ./security/keys    # Custom keys directory
ai-scrm init --no-sign                 # Skip signing (dev only)
```

### 11.2 Scan Commands

```bash
# Scan current directory
ai-scrm scan

# Scan specific directories
ai-scrm scan --dir ./models --dir ./configs

# Output to JSON
ai-scrm scan --output scan-results.json
```

### 11.3 Status Command

```bash
# Show current status
ai-scrm status

# Live updating status
ai-scrm status --watch

# Custom ABOM
ai-scrm status --abom ./security/abom.json

# Update interval (seconds)
ai-scrm status --watch --interval 10
```

### 11.4 ABOM Commands

```bash
# Validate ABOM structure
ai-scrm abom validate abom.json

# Strict AI-SCS compliance
ai-scrm abom validate abom.json --strict

# Display ABOM information
ai-scrm abom info abom.json
```

### 11.5 Trust Commands

```bash
# Generate signing keys
ai-scrm trust keygen
ai-scrm trust keygen --algorithm ed25519
ai-scrm trust keygen --algorithm rsa
ai-scrm trust keygen --output ./keys

# Sign an ABOM
ai-scrm trust sign abom.json
ai-scrm trust sign abom.json --key ./keys/private.pem
ai-scrm trust sign abom.json --output abom-signed.json

# Verify signature
ai-scrm trust verify abom-signed.json
```

### 11.6 Validation Commands

```bash
# Check for drift
ai-scrm validation check --abom abom.json

# Check specific directory
ai-scrm validation check --abom abom.json --dir ./deployed

# Output events to file
ai-scrm validation check --abom abom.json --output events.jsonl
```

### 11.7 Monitor Command

```bash
# Start monitoring with defaults
ai-scrm monitor

# Custom intervals
ai-scrm monitor --hash-interval 30
ai-scrm monitor --mcp-interval 120
ai-scrm monitor --scan-interval 900

# Log events to file
ai-scrm monitor --output ./logs/events.jsonl

# Custom ABOM
ai-scrm monitor --abom ./security/abom.json
```

### 11.8 Approve/Reject Commands

```bash
# Approve a new component
ai-scrm approve mcp:new-server
ai-scrm approve mcp:new-server --trust internal
ai-scrm approve model:updated-weights

# Reject a component
ai-scrm reject mcp:suspicious-server
```

---

## 12. CI/CD Integration

### 12.1 GitHub Actions

```yaml
# .github/workflows/ai-security.yml
name: AI Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  ai-scrm-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install AI-SCRM
        run: pip install ai-scrm[all]
        
      - name: Scan for changes
        run: ai-scrm scan --output scan-results.json
        
      - name: Validate ABOM
        run: ai-scrm abom validate abom.json --strict
        
      - name: Verify Signature
        run: ai-scrm trust verify abom-signed.json
        
      - name: Check for Drift
        run: |
          ai-scrm validation check \
            --abom abom-signed.json \
            --dir ./models
            
      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: ai-scrm-scan
          path: scan-results.json
```

### 12.2 GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

ai-security:
  stage: security
  image: python:3.11
  script:
    - pip install ai-scrm[all]
    - ai-scrm scan --output scan-results.json
    - ai-scrm abom validate abom.json --strict
    - ai-scrm trust verify abom-signed.json
  artifacts:
    paths:
      - scan-results.json
  only:
    - main
    - merge_requests
```

### 12.3 Kubernetes Admission Controller

```python
# admission_webhook.py
from flask import Flask, request, jsonify
from ai_scrm import ABOM, DriftDetector

app = Flask(__name__)
abom = ABOM.from_file("/etc/ai-scrm/abom.json")
detector = DriftDetector(abom)

@app.route('/validate', methods=['POST'])
def validate_pod():
    """Kubernetes admission webhook for AI workloads."""
    review = request.json
    pod_spec = review['request']['object']['spec']
    
    # Extract model references from pod annotations
    model_hash = pod_spec.get('annotations', {}).get('ai-scrm/model-hash')
    model_ref = pod_spec.get('annotations', {}).get('ai-scrm/model-ref')
    
    if model_ref and model_hash:
        event = detector.check_component(model_ref, model_hash)
        if not event.is_compliant():
            return jsonify({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": review['request']['uid'],
                    "allowed": False,
                    "status": {
                        "message": f"Model integrity check failed: {event.observation.details}"
                    }
                }
            })
    
    return jsonify({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": review['request']['uid'],
            "allowed": True
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')
```

### 12.4 Pre-commit Hook

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ai-scrm-validate
        name: Validate AI-SCRM ABOM
        entry: ai-scrm abom validate abom.json --strict
        language: system
        pass_filenames: false
        
      - id: ai-scrm-signature
        name: Check ABOM signature
        entry: ai-scrm trust verify abom-signed.json
        language: system
        pass_filenames: false
```

---

## 13. Best Practices

### 13.1 ABOM Management

| Practice | Description |
|----------|-------------|
| **Version ABOMs** | Use semantic versioning and track in git |
| **Automate generation** | Use `ai-scrm init` or scanner in build process |
| **Include all components** | Don't skip "minor" components |
| **Update on changes** | Regenerate ABOM when any component changes |
| **Sign before deploy** | Never deploy unsigned ABOMs to production |
| **Review TODOs** | Fill in all TODO items before production |

### 13.2 Security Practices

```
Security Hierarchy
├── Production Environment
│   ├── Signed ABOMs only
│   ├── Continuous validation enabled
│   ├── Alert on any drift
│   └── Block on critical violations
├── Staging Environment
│   ├── Signed ABOMs preferred
│   ├── Periodic validation
│   └── Alert on drift
└── Development Environment
    ├── Unsigned ABOMs acceptable
    ├── Validation optional
    └── Log drift events
```

### 13.3 Monitoring Recommendations

| Environment | Hash Interval | MCP Interval | Scan Interval |
|-------------|---------------|--------------|---------------|
| Production | 60s | 5min | 30min |
| Staging | 5min | 15min | 1hr |
| Development | Manual | Manual | Manual |

### 13.4 Incident Response

When drift is detected:

1. **Immediate Actions**
   - Block affected components
   - Preserve evidence (logs, hashes)
   - Alert security team

2. **Investigation**
   - Compare expected vs actual artifacts
   - Review access logs
   - Identify scope of compromise

3. **Remediation**
   - Restore from known-good state
   - Update ABOM if legitimate change
   - Rotate signing keys if compromised

4. **Post-Incident**
   - Document findings
   - Update detection rules
   - Improve monitoring

### 13.5 Performance Considerations

```python
# Optimize hash computation for large models
def compute_hash_streaming(filepath: str, chunk_size: int = 1024*1024) -> str:
    """Compute hash with configurable chunk size for large files."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Cache validation results
from functools import lru_cache

@lru_cache(maxsize=100)
def cached_component_check(bom_ref: str, actual_hash: str):
    return detector.check_component(bom_ref, actual_hash)
```

---

## 14. Troubleshooting

### 14.1 Clear Error Messages

AI-SCRM provides actionable error messages:

```
ABOM file not found: ./abom.json

This could mean:
  • The file path is incorrect
  • You haven't created an ABOM yet

To fix:
  • Check the file path and try again
  • Run 'ai-scrm init' to create an ABOM
  • Run 'ai-scrm scan' to discover components
```

```
Signature validation failed for abom.json

The ABOM file has been modified since it was signed.
This could mean:
  • Someone tampered with the file (security incident)
  • You made legitimate changes and forgot to re-sign

To fix:
  • If changes were intentional: ai-scrm sign abom.json
  • If unexpected: Investigate first - this may be a security incident
```

### 14.2 Common Issues

#### Issue: "Missing cryptographic hash" validation error

**Cause:** Model component doesn't have a hash defined.

**Solution:**
```python
# Ensure hash is provided
builder.add_model(
    name="my-model",
    version="1.0",
    hash_value=compute_file_hash("./model.safetensors"),  # Add this
    format="safetensors",
    supplier="My Org"
)
```

Or use the Scanner which computes hashes automatically:
```bash
ai-scrm init  # Hashes are computed during scan
```

#### Issue: "ABOM not signed" verification error

**Cause:** Trying to verify an unsigned ABOM with `reject_unsigned=True`.

**Solution:**
```python
# Option 1: Sign the ABOM
signer = Signer.generate("ed25519")
signer.sign(abom)

# Option 2: Allow unsigned (development only)
verifier = Verifier(reject_unsigned=False)
```

#### Issue: "Missing ai.mcp.capabilities" validation error

**Cause:** MCP server missing required capabilities field.

**Solution:**
```python
builder.add_mcp_server(
    name="my-mcp",
    version="1.0",
    endpoint="http://localhost:3000",
    trust_boundary="internal",
    capabilities=["read", "write"]  # Add this - REQUIRED
)
```

#### Issue: Signature verification fails after ABOM modification

**Cause:** ABOM was modified after signing.

**Solution:**
```python
# Always re-sign after any modification
abom.components[0].version = "1.1.0"  # Modification
signer.sign(abom)  # Must re-sign
abom.to_file("abom-signed.json")
```

#### Issue: "Component not found" during validation

**Cause:** bom-ref doesn't match ABOM entry.

**Solution:**
```python
# Check the actual bom-ref in ABOM
for comp in abom.components:
    print(f"{comp.name}: {comp.bom_ref}")

# Use exact bom-ref in check
event = detector.check_component(
    "model:llama-3-8b@1.0.0",  # Must match exactly
    actual_hash
)
```

#### Issue: Model not discovered during scan

**Cause:** File is too small (<1MB) or wrong extension.

**Solution:**
```python
# Check file size
import os
print(os.path.getsize("model.safetensors"))  # Should be >1MB

# Supported extensions
# .safetensors, .gguf, .ggml, .pt, .pth, .bin, .onnx, .tflite, .h5
```

#### Issue: MCP server not discovered

**Cause:** Config file not in expected location.

**Solution:**
```bash
# Check if Claude Desktop config exists
ls ~/.config/claude/claude_desktop_config.json

# Or specify config path
export MCP_CONFIG_PATH=/path/to/my/mcp.json
ai-scrm scan
```

#### Issue: Smart inference didn't detect supplier

**Cause:** Model filename doesn't match known patterns.

**Solution:**
```yaml
# Add to ai-scrm-metadata.yaml
models:
  "my-custom-model*":
    supplier: "My Organization"
    type: base
```

### 14.3 Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("ai_scrm")
logger.setLevel(logging.DEBUG)

# Now operations will show detailed logs
```

```bash
# CLI verbose mode
ai-scrm --verbose scan
ai-scrm -v status
```

---

## 15. Appendix: AI-SCS Compliance Checklist

Use this checklist to verify your implementation meets AI-SCS requirements.

### Control Domain 1: ABOM (Section 5)

#### 5.3.1 Model Information
- [ ] All models have cryptographic hash (SHA-256)
- [ ] All models have format specified
- [ ] All models have supplier/source organization
- [ ] Fine-tuned models have base model reference
- [ ] Adapters have base model reference

#### 5.3.2 Data Provenance
- [ ] All datasets have type (training, fine-tuning, evaluation)
- [ ] All datasets have source specified
- [ ] Licensing constraints documented (if applicable)

#### 5.3.3 Dependencies
- [ ] All software dependencies listed
- [ ] Version constraints specified
- [ ] Transitive dependencies included

#### 5.3.4 Embeddings
- [ ] Embedding model identifier specified
- [ ] Vector store identifier specified
- [ ] Update policy defined for vector stores

#### 5.3.5 Agents/Tools
- [ ] Agent type specified
- [ ] Permitted tools listed for each agent
- [ ] MCP servers have endpoint defined
- [ ] MCP servers have trust boundary defined
- [ ] MCP servers have capabilities listed

#### 5.3.6 Behavioral Artifacts
- [ ] System prompts documented (if externally managed)
- [ ] Guardrail policies documented
- [ ] Routing configurations documented

#### 5.4 ABOM Properties
- [ ] ABOM is machine-readable (JSON)
- [ ] ABOM has serial number (URN:UUID)
- [ ] ABOM is versioned
- [ ] ABOM includes ai-scs:profile property
- [ ] ABOM includes ai-scs:version property

### Control Domain 2: Trust (Section 6)

#### 6.3 Trust Assertions
- [ ] Artifact identifier present
- [ ] Cryptographic hash present
- [ ] Signing entity identified
- [ ] Signing timestamp present
- [ ] Validity period defined
- [ ] ABOM reference included

#### 6.4 Verification
- [ ] Verification performed before artifact use
- [ ] Invalid signatures rejected
- [ ] Unsigned artifacts rejected (when required)
- [ ] Trust roots configurable

### Control Domain 3: Validation (Section 7)

#### 7.2 Detection Capabilities
- [ ] Model substitution detection
- [ ] Dependency drift detection
- [ ] Unauthorized tool detection
- [ ] Unauthorized MCP detection
- [ ] Modified prompt detection
- [ ] Provenance mismatch detection

#### 7.2.1 Enforcement
- [ ] Can prevent execution of affected components
- [ ] Can disable compromised tools
- [ ] Can block modified artifacts
- [ ] Supports fail-closed mode

#### 7.3 Event Emission
- [ ] Structured events for verification failures
- [ ] Events for ABOM deviations
- [ ] Events for trust expiration
- [ ] Events for policy violations

#### 7.4 Integration
- [ ] SIEM integration available
- [ ] SOAR integration available (optional)
- [ ] Policy engine integration (optional)

### New in v1.0: Auto-Discovery & Monitoring

#### Auto-Discovery
- [ ] Model files automatically discovered
- [ ] MCP servers discovered from config files
- [ ] Libraries discovered from pip/requirements
- [ ] Smart inference fills in known model suppliers
- [ ] Metadata template generated for manual review

#### Continuous Monitoring
- [ ] Hash checks at configurable intervals
- [ ] MCP heartbeat checks implemented
- [ ] Full re-scan at configurable intervals
- [ ] Events emitted for all drift/violations

#### Framework Integration
- [ ] Guard decorator available
- [ ] LangChain integration tested
- [ ] FastAPI middleware available
- [ ] Emergency bypass with logging

---

## Support & Resources

- **Documentation:** https://github.com/kahalewai/ai-scrm
- **GitHub Issues:** https://github.com/kahalewai/ai-scrm/issues
- **AI-SCS Standard:** https://github.com/kahalewai/ai-scs

---

*This implementation guide is provided under the Apache 2.0 license.*
