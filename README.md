# THOS – AI-Powered Threat Hunting Platform

<p align="center">

**AI-Powered • Hypothesis-Driven • Multi-SIEM • RAG • LangGraph • MCP • Fully On-Premises**

</p>

---

## Overview

**THOS (Threat Hunting Operating System)** is an enterprise-grade, AI-powered threat hunting platform designed to help SOC Analysts, Threat Hunters, and Incident Responders investigate security events using natural language.

Unlike traditional SIEM search interfaces, THOS enables analysts to perform **hypothesis-driven threat hunting** through an interactive chat interface. Behind the scenes, THOS orchestrates multiple AI agents using **LangGraph**, retrieves contextual knowledge through **Retrieval-Augmented Generation (RAG)**, integrates with multiple SIEM platforms, analyzes telemetry using local Large Language Models (LLMs), and automatically generates comprehensive threat hunting reports.

THOS is designed to operate **entirely on-premises**, ensuring sensitive security data never leaves your environment.

---

# Key Features

- 🤖 AI-powered hypothesis-based threat hunting
- 💬 Interactive chat interface for SOC Analysts
- 🧠 Local LLM inference using Ollama (offline capable)
- 🔗 LangGraph multi-agent orchestration
- 🧩 FastMCP modular tool execution
- 📚 Retrieval-Augmented Generation (RAG)
- 🗄️ ChromaDB vector knowledge base
- 🛡️ Multi-SIEM integration
- 📂 Folder-based log hunting
- 🔍 Automatic log parsing and normalization
- 📖 MITRE ATT&CK & HEARTH framework integration
- 📄 Automated Markdown hunting reports
- ⚡ FastAPI backend services
- 🖥️ Modern Gradio user interface
- 🐳 One-command Docker deployment
- 🔒 Fully on-premises architecture

---

# Architecture

<img width="50%" alt="ChatGPT Image Jul 8, 2026, 11_17_41 PM" src="https://github.com/user-attachments/assets/39ecbf05-df8d-498a-9d2a-b3b22676def5" />



---

# Core Components

| Component | Description |
|------------|-------------|
| **Gradio UI** | Interactive analyst chat interface |
| **FastAPI** | REST API backend |
| **LangGraph** | AI workflow orchestration |
| **FastMCP** | Tool execution framework |
| **Ollama** | Local Large Language Models |
| **ChromaDB** | Vector database for semantic retrieval |
| **Knowledge Base** | MITRE ATT&CK & HEARTH frameworks |
| **Parser Engine** | Multi-format log normalization |
| **SIEM Connectors** | Unified interface for multiple SIEM platforms |
| **Report Engine** | Automated Markdown report generation |
| **PostgreSQL** | Metadata and audit storage |
| **Redis** | Caching and task management |

---

# Supported SIEM Platforms

THOS provides a modular SIEM abstraction layer, allowing the same AI hunting workflow to operate across different security platforms.

| SIEM Platform | Status | Integration |
|---------------|--------|-------------|
| Folder Logs | ✅ Supported | Local Filesystem |
| Mock Data | ✅ Supported | Built-in Simulator |
| LogRhythm | ✅ Supported | Search API |
| Splunk Enterprise | ✅ Supported | REST Search API |
| Splunk Cloud | ✅ Supported | REST Search API |
| IBM QRadar | ✅ Supported | Ariel Search API |

Additional SIEM platforms can be integrated by implementing a new connector within the `services/siem` module.

---

# Supported Log Formats

THOS supports automatic parsing and normalization of multiple security log formats.

| Format | Support |
|----------|----------|
| EVTX | ✅ |
| CSV | ✅ |
| JSON | ✅ |
| JSONL | ✅ |
| NDJSON | ✅ |
| XML | ✅ |
| ECS JSON | ✅ |
| Syslog | ✅ |
| CEF | ✅ |
| LOG | ✅ |
| TXT | ✅ |
| PCAP | ✅ |
| PCAPNG | ✅ |

Default ingestion directory:

```text
data/log_sources/
```

---

# Threat Hunting Workflow

```text
Analyst Hypothesis
        │
        ▼
Select Target SIEM
        │
        ▼
Retrieve Security Events
        │
        ▼
Normalize & Parse Logs
        │
        ▼
RAG Knowledge Retrieval
        │
        ▼
LLM Threat Analysis
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Generate Threat Hunting Report
```

---

# Technology Stack

| Layer | Technology |
|--------|------------|
| Frontend | Gradio |
| Backend | FastAPI |
| AI Workflow | LangGraph |
| MCP Framework | FastMCP |
| Local LLM | Ollama |
| Default Model | Qwen3.4B |
| Vector Database | ChromaDB |
| Database | PostgreSQL |
| Cache | Redis |
| Knowledge Base | MITRE ATT&CK & HEARTH |
| Containerization | Docker Compose |
| Programming Language | Python 3.12+ |

---

# Quick Start

```bash
# Clone the repository
git clone <repository-url>

cd thos

# Configure environment
cp env.example .env

# Start all services
docker compose up -d --build
```

Open your browser:

```
http://localhost:7860
```

---

# Generated Reports

Every investigation produces a structured Markdown report containing:

- Executive Summary
- Threat Findings
- Evidence
- MITRE ATT&CK Mapping
- Indicators of Compromise (IOCs)
- Recommendations
- Analyst Notes

Reports are automatically saved to:

```text
data/reports/
```

---

# Security

THOS is built for security-conscious environments.

- Fully on-premises deployment
- Local AI inference (no cloud dependency)
- Local vector database
- Local report storage
- Suitable for regulated and air-gapped environments

---

# Roadmap

Upcoming enhancements include:

- Microsoft Sentinel Connector
- Elastic Security Connector
- Google Chronicle Connector
- Cortex XSIAM Connector
- Sigma Rule Generation
- YARA Rule Generation
- IOC Enrichment
- Threat Intelligence Integration
- SOAR Playbooks
- Scheduled Hunts
- Investigation Timeline
- Case Management
- Multi-user Collaboration
- Autonomous AI Hunting Agents

---

# Contributing

Contributions are welcome!

Whether you're adding new SIEM connectors, improving AI workflows, expanding knowledge sources, or fixing bugs, feel free to submit a pull request.

---

# License

This project is licensed under the **MIT License** (or your preferred license).

---

# Acknowledgements

THOS is built upon several outstanding open-source technologies:

- Ollama
- LangGraph
- FastMCP
- ChromaDB
- FastAPI
- Gradio
- PostgreSQL
- Redis
- Docker
- MITRE ATT&CK Framework
- HEARTH Threat Hunting Framework

---

# Disclaimer

THOS is intended for authorized security monitoring, threat hunting, incident response, and cybersecurity research. Users are responsible for ensuring compliance with all applicable laws, regulations, and organizational policies before deploying or using this software.
