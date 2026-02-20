# Hunter v7.0 — Transaction State Recon Engine

## Overview

**Hunter** is a sophisticated reconnaissance tool designed to identify and analyze transaction logic vulnerabilities within web applications, with a specific focus on financial systems and DeFi (Decentralized Finance) platforms. It uses a multi-staged approach to map endpoints, analyze state transitions, and detect critical flaws like replay attacks or unauthorized access.

The system is designed to run within a secure, VPN-protected environment to ensure anonymity and security during reconnaissance operations.

### 🚀 Key Features

* **Intelligent Parsing:** Recursively extracts API calls (Axios/HTTP) and configuration objects directly from JavaScript files.
* **State Machine Analysis:** Maps transaction flows (e.g., Payment, Withdrawal, Swap) and detects missing idempotency or logic gaps.
* **DeFi & Crypto Detection:** Built-in patterns for identifying flash loan logic, price impact settings, and token approval vulnerabilities.
* **Active Probing:** Dynamic payload generation to verify findings and check for CORS wildcards or stack trace leaks.
* **AI-Powered Strategy:** Integrates with OpenAI (GPT-4o) to provide strategic analysis of discovered vulnerabilities.
* **VPN Integration:** Built-in support for NordVPN (via `gluetun`) to ensure all traffic is routed through a secure tunnel.
* **Web Dashboard:** Automated reporting available via a local Nginx dashboard.

## ⚠️ Status: Research & Testing

**Please Note:** This project is currently in an **active testing and development phase**.

* Features are subject to change.
* Functionality is being refined and may not be stable.
* Use in production environments is at your own risk.

## Quick Start (Docker)

The recommended way to run Hunter is using Docker Compose, which sets up the VPN gateway, the scanning engine, and the reports dashboard.

1. **Configure Environment:**
    Create a `.env` file based on `.env.example`:

    ```env
    NORD_PRIVATE_KEY=your_wireguard_private_key
    OPENAI_API_KEY=your_openai_key
    ```

2. **Add Targets:**
    Add your target domains to `targets.txt`.
3. **Start the Engine:**

    ```bash
    docker-compose -f docker-compose.prod.yml up -d
    ```

4. **View Reports:**
    Open `http://localhost:8080` to access the reports dashboard.

## Manual Execution (Python)

If you prefer to run it locally without Docker:

1. **Install dependencies:**

    ```bash
    pip install aiohttp rich
    ```

2. **Run:**

    ```bash
    python hunter.py
    ```

---
*Developed for strategic logic reconnaissance.*
