# Advanced Password Security & Enterprise Purple-Team Simulation Lab

An enterprise-style cybersecurity lab that simulates credential-based attacks and validates defensive detection, behavioral analytics, MITRE ATT&CK mapping, risk scoring, campaign correlation, and adaptive SOAR response.

---

## 📌 Project Overview

This project extends a traditional password attack detection lab into an enterprise-style **Purple-Team Security Simulation Lab**.

The system combines controlled offensive attack simulations with defensive security monitoring to demonstrate the complete security lifecycle:

**Attack Simulation → Telemetry → Detection → Risk Scoring → Alerting → MITRE ATT&CK Mapping → Automated Response → Performance Measurement**

The project is designed for cybersecurity learning and demonstrates practical concepts relevant to:

- Security Operations Center (SOC)
- Detection Engineering
- Threat Detection
- Security Automation
- Purple Teaming
- Authentication Security
- Behavioral Analytics
- MITRE ATT&CK
- SOAR

---

## 🎯 Objectives

The main objectives of this project are to:

- Simulate realistic authentication-based attack patterns in a controlled lab.
- Generate structured authentication security telemetry.
- Detect suspicious authentication behavior.
- Establish user-specific behavioral baselines.
- Calculate contextual risk scores.
- Correlate multiple events into attack campaigns.
- Map detected activity to MITRE ATT&CK techniques.
- Automatically select defensive response actions.
- Measure Mean Time to Detect (MTTD).
- Measure Mean Time to Respond (MTTR).
- Provide security monitoring and campaign-level reporting.

---

# 🏗️ System Architecture

```text
                    ┌───────────────────────┐
                    │    Campaign Manager   │
                    └───────────┬───────────┘
                                │
                       Attack Profiles
                                │
                                ▼
                    ┌───────────────────────┐
                    │    Attack Simulator   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │     Flask Auth API    │
                    └───────────┬───────────┘
                                │
                       Authentication Events
                                │
                                ▼
              ┌─────────────────────────────────┐
              │       PostgreSQL + Redis        │
              │                                 │
              │  PostgreSQL → Security Data    │
              │  Redis → Event Streaming       │
              └───────────────┬─────────────────┘
                              │
                       Redis Streams
                              │
                              ▼
                    ┌───────────────────────┐
                    │   Detection Worker    │
                    └───────────┬───────────┘
                                │
                                ▼
                 ┌────────────────────────────┐
                 │ Behavioral Detection Engine│
                 └────────────┬───────────────┘
                              │
                        Risk Scoring
                              │
                              ▼
                    ┌───────────────────────┐
                    │     Alert Engine      │
                    └───────────┬───────────┘
                                │
                       MITRE ATT&CK Mapping
                                │
                                ▼
                    ┌───────────────────────┐
                    │         SOAR          │
                    └───────────┬───────────┘
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
           CAPTCHA          STEP-UP MFA     Restriction
               │                │                │
               └────────────────┼────────────────┘
                                ▼
                    ┌───────────────────────┐
                    │ Dashboard / Reporting │
                    └───────────────────────┘
