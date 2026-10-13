# 🏦 BaFin-Aligned Data Leakage Prevention (DLP): Multi-Vector Egress Monitoring & Rule Tuning

## 📌 Project Overview
This project demonstrates the design, deployment, and tuning of an enterprise Data Leakage Prevention (DLP) architecture using **Microsoft Purview** and **Microsoft Sentinel**. 

Designed to align with German banking regulations (BaFin/BAIT) and strict data secrecy (*Bankgeheimnis*), this lab models the detection, blocking, and SIEM investigation of sensitive financial data egress across three critical vectors:
1. **Email (Exchange Online)**
2. **Endpoint Removable Storage (USB)**
3. **Unsanctioned Web Uploads (Cloud/Browser)**

**Core Focus:** Transitioning from raw alerts to actionable intelligence by optimizing DLP rules to reduce false positives and documenting Tier-1 SOC investigations.

---

# BaFin-Aligned Data Leakage Prevention (DLP): Multi-Vector Egress Monitoring & Rule Tuning

## 📌 Project Overview
This project demonstrates the design, deployment, and tuning of an enterprise Data Leakage Prevention (DLP) architecture using **Microsoft Purview** and **Microsoft Sentinel**.

Designed to align with German banking regulations (BaFin/BAIT) and strict data secrecy (Bankgeheimnis), this lab models the detection, blocking, and SIEM investigation of sensitive financial data egress.

**Core Focus:** Transitioning from raw alerts to actionable intelligence by optimizing DLP rules to reduce false positives, navigating virtualized hardware abstraction, and executing Tier-1 SOC investigations via KQL.

---

## 🏗️ Architecture Diagram
```mermaid
graph TD
    %% Local Infrastructure
    subgraph "Local Environment (macOS Host)"
        subgraph "Virtualization (UTM/QEMU)"
            EP["💻 Windows 11 Endpoint (ARM64)"]
        end
        USB["💽 Removable Media (USB)"]
    end

    %% Cloud Identity & Sensor
    subgraph "Microsoft Cloud & Security"
        Entra["🔑 Microsoft Entra ID"]
        Defender["🛡️ Defender for Endpoint"]
    end

    %% Purview Compliance
    subgraph "Microsoft Purview (Data Security)"
        Purview["🎯 Purview Compliance Portal"]
        SIT["⚙️ Custom SIT: BaFin (SEC-DACH-FIN)"]
        Policy["📜 Endpoint DLP Policy"]
    end

    %% SOC & SIEM
    subgraph "Security Operations (SOC)"
        SIEM["🚨 Microsoft Sentinel / XDR (Incident Response)"]
    end

    %% Workflows
    EP -->|Onboarded via Script| Defender
    EP -->|Joined| Entra
    
    Purview -->|Defines Classification| SIT
    SIT -->|Triggers| Policy
    Policy -->|Pushes Rule Dictionary| Defender
    Defender -->|Enforces Engine Locally| EP

    EP -->|Attempted Egress| USB
    EP -->|Attempted Clipboard Paste| Web["🌐 External App / Browser"]

    USB -.->|Blocked by Endpoint DLP| Defender
    Web -.->|Blocked by Endpoint DLP| Defender

    Defender -->|Raw Alerts & Telemetry| SIEM
    Purview -->|Compliance Events| SIEM
--
