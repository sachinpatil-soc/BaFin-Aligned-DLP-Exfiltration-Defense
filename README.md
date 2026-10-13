# 🏦 BaFin-Aligned Data Leakage Prevention (DLP): Multi-Vector Egress Monitoring & Rule Tuning

## 📌 Project Overview
This project demonstrates the design, deployment, and tuning of an enterprise Data Leakage Prevention (DLP) architecture using **Microsoft Purview** and **Microsoft Sentinel**. 

Designed to align with German banking regulations (BaFin/BAIT) and strict data secrecy (*Bankgeheimnis*), this lab models the detection, blocking, and SIEM investigation of sensitive financial data egress across three critical vectors:
1. **Email (Exchange Online)**
2. **Endpoint Removable Storage (USB)**
3. **Unsanctioned Web Uploads (Cloud/Browser)**

**Core Focus:** Transitioning from raw alerts to actionable intelligence by optimizing DLP rules to reduce false positives and documenting Tier-1 SOC investigations.

---

## 🏗️ Architecture Diagram

```mermaid
graph TD
    subgraph Local_Environment [Local Environment]
        EP["💻 Windows 11 (ARM64)"]
        USB["💽 USB Drive"]
        Web["🌐 External Browser"]
    end

    subgraph Microsoft_Cloud [Microsoft Cloud Security]
        Entra["🔑 Entra ID"]
        Defender["🛡️ Defender for Endpoint"]
        Purview["🎯 Purview Portal"]
        SIT["⚙️ Custom SIT (BaFin)"]
        Policy["📜 DLP Policy"]
    end

    subgraph SOC_Operations [Security Operations]
        SIEM["🚨 Sentinel / Defender XDR"]
    end

    EP -->|"Onboards to"| Defender
    EP -->|"Joins"| Entra
    
    Purview -->|"Defines"| SIT
    SIT -->|"Triggers"| Policy
    Policy -->|"Pushes Dictionary"| Defender
    Defender -->|"Enforces Rules Locally"| EP

    EP -->|"Attempted File Transfer"| USB
    EP -->|"Attempted Clipboard Paste"| Web

    USB -.->|"Intercepts & Blocks"| Defender
    Web -.->|"Intercepts & Blocks"| Defender

    Defender -->|"Raw Alerts"| SIEM
    Purview -->|"Compliance Logs"| SIEM
