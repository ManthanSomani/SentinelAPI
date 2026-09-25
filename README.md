# 🛡️ SentinelAPI

> **Next-Gen 15-Point DAST & SAST Security Matrix**  
> Zero-Trust API Security — Automated in Seconds.

[![Deployed on Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat-square&logo=vercel)](https://sentinelapi-nine.vercel.app)
[![Backend Powered](https://img.shields.io/badge/Backend-Render-blue?style=flat-square&logo=render)](https://sentinelapi-backend-0iao.onrender.com)
[![Security Standard](https://img.shields.io/badge/Security-Zero--Trust-red?style=flat-square)]()

---

## 🚀 Overview

**SentinelAPI** is an advanced, automated security auditing platform designed to detect critical vulnerabilities—such as **BOLA (Broken Object Level Authorization)**, **PII data leaks**, and **brute-force exposure risks**—instantly across multiple target vectors. Whether analyzing raw source code ZIP repositories, live web apps, or OpenAPI/Swagger specifications, SentinelAPI runs a rigorous **15-point DAST & SAST security matrix** backed by an **AI Security Copilot**.

---

## 🛠️ Tech Stack

### **Frontend**
* **Framework / Hosting:** Hosted on **Vercel** (`https://sentinelapi-nine.vercel.app`)
* **UI Architecture:** Modern, responsive component-driven interface with real-time audit trail rendering, interactive assessment vector selection, execution log inspectors, and live AI Copilot chat widgets.

### **Backend & Core Services**
* **Hosting / Runtime:** Hosted on **Render** (`https://sentinelapi-backend-0iao.onrender.com`)
* **Languages & Core Frameworks:** Python / FastAPI / Node.js microservices architecture designed for high-throughput scanning and asynchronous request handling.
* **AI Integration:** Integrated AI Security Copilot for deep vulnerability explanation, Proof of Concept (PoC) generation, and automated secure code patching.

---

## 🔍 Assessment Vectors & How It Works

SentinelAPI allows users to select from multiple evaluation targets to run comprehensive security checks:

1. **OpenAPI / Swagger Specs:** Ingests API definitions to statically analyze endpoints for missing authentication headers, insecure HTTP methods, and exposed sensitive parameters.
2. **Live Web Apps:** Performs Dynamic Application Security Testing (DAST) by probing live endpoints to detect runtime security misconfigurations and data exposure.
3. **Source Code Repositories (ZIP):** Executes Static Application Security Testing (SAST) to scan raw source code files for hardcoded secrets, weak cryptographic algorithms, and insecure dependency patterns.

---

## 🧪 The 15-Point Security Test Matrix & Execution

The security engine evaluates targets across a rigorous **15-point test matrix**. Each test case execution provides:
* **Detailed Execution Logs:** Step-by-step trace of payloads sent, status codes returned, and behavioral patterns observed.
* **Proof of Concept (PoC):** Concrete, reproducible exploit strings or curl commands demonstrating the vulnerability.
* **AI Security Explanation:** Plain-language breakdown of *why* the vulnerability exists and its potential business/system impact.
* **Secure Code Correction:** Automated patch suggestions containing immediate refactored code snippets to remediate the flaw.
* **Interactive AI Copilot:** A context-aware chat interface enabling developers to ask targeted follow-up questions about specific test cases.

---

## ⚙️ CI/CD Integration (GitHub Actions)

Halt risky deployments automatically upon critical vulnerability or BOLA detection by integrating SentinelAPI directly into your CI/CD pipeline. 

Add the following workflow configuration to `.github/workflows/sentinel.yml`:

```yaml
name: SentinelAPI Security Gate

on: [push, pull_request]

jobs:
  sec-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Zero-Trust Scan
        run: |
          curl -X POST [https://sentinelapi-backend-0iao.onrender.com/api/scanner/run](https://sentinelapi-backend-0iao.onrender.com/api/scanner/run) \
          -H "Content-Type: application/json" \
          -d '{"target_url": "http://your-app/openapi.json"}'
