# ESLA-PRO v3.1: Enterprise SOC Threat Analyzer

[![SOC Tool CI](https://github.com/nitzz2025/soc-analyzer-pro/actions/workflows/main.yml/badge.svg)](https://github.com/nitzz2025/soc-analyzer-pro/actions/workflows/main.yml)

🎯 Purpose of the Tool
ESLA-PRO is a high-performance security engine designed to automate the ingestion of server (HTTP 401) and firewall (DROP/DENY) logs. It identifies potential threat actors, enriches datasets with Geo-IP intelligence, and dispatches real-time alerts via modular webhook integrations.

🛡️ Security Mandates
- **Zero-Trust Pathing**: Strict resolution of log paths to prevent directory traversal attacks.
- **CSV Injection Shields**: Automated sanitization of forensic reports to block malicious formula execution. 
- **Non-Blocking IO**: Async operations with aggressive timeouts to ensure tool resilience during network latency.

⚙️ Installation & Setup

### Prerequisites
- Docker (recommended)
- Python 3.10 or higher (if running natively without Docker)

### 1. Repository Access
```bash
git clone https://github.com/nitzz2025/soc-analyzer-pro.git
cd soc-analyzer-pro
```

### 2. Dependency Management
(Only if running natively, Docker handles this automatically)
```bash
pip install -r soc_analyzer_pro/requirements.txt
```

### 3. Environment Configuration
Create a .env file in the root directory:
```env
IPINFO_TOKEN=your_api_token_here
```

### 4. Docker Build
Build the secure Docker container:
```bash
docker build -t soc-analyzer-pro -f soc_analyzer_pro/Dockerfile .
```

🚀 Usage

Launch the interactive monitoring dashboard using Docker:
```bash
# Create a 'logs' directory in your current working directory if you want to map local log files
# mkdir -p logs
# Place your web_activity.log or sample_firewall.log inside the 'logs' directory

docker run -it -v $(pwd)/logs:/home/socuser/app/logs --env-file .env soc-analyzer-pro
```

📜 Governance
Please review our [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CONTRIBUTING.md) before submitting pull requests. Licensed under the MIT License.