<img width="189" height="73" alt="logn-pacific-logo" src="https://github.com/user-attachments/assets/dc939a98-dcbe-4ad2-b1d5-f59b351e4bf5" />
<div align="center">

<img src="assets/logn-pacific-logo.png" width="200" alt="LOG(N) Pacific">

<sub>Cyber Range Capstone · LOG(N) Pacific</sub>

# Live-Exposed Honeypot Lab

**Write the detections first. Then open the door and let the internet supply the breach.**

![Azure](https://img.shields.io/badge/Azure-0078d4?style=flat-square&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft_Sentinel-0072c6?style=flat-square)
![KQL](https://img.shields.io/badge/Queries-KQL-5e2750?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped_to-MITRE_ATT%26CK-c1272d?style=flat-square)
![Windows](https://img.shields.io/badge/Windows_VM-0078d6?style=flat-square&logo=windows&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-00758f?style=flat-square&logo=mysql&logoColor=white)

`Harden` → `Instrument` → `Baseline` → `Detect` → `Weaken & Expose`

</div>

---

Most home-lab detection projects fire alerts at traffic the author generated
himself. This one doesn't. A hardened Windows VM running MySQL is instrumented,
baselined while quiet, fitted with detection rules — and *then* deliberately
weakened and exposed to the public internet, so the incident that follows is
supplied by real attackers rather than a script.

The ordering is the whole point. Detections must exist before exposure, or you
have no way to prove you caught the intrusion instead of reconstructing it after
the fact. Telemetry lands in `LAW-Cyber-Range` for analysis.

### Phases

| # | Phase | What happens | Output |
|---|-------|--------------|--------|
| 1 | **Harden** | Build the Windows VM + MySQL, apply baseline hardening | Documented secure build |
| 2 | **Instrument** | Wire telemetry into `LAW-Cyber-Range` | Verified log ingestion |
| 3 | **Baseline** | Capture normal behavior while the box is quiet | Known-good activity profile |
| 4 | **Detect** | Author ATT&CK-mapped analytics rules | Detection rule set + KQL |
| 5 | **Weaken & Expose** | Reduce controls, open to the internet, wait | Live incident + investigation |

### Jump to

[Architecture](#architecture) · [Build & Hardening](#build--hardening) · [Telemetry](#telemetry) · [Baseline](#baseline) · [Detection Rules](#detection-rules) · [Incident Findings](#incident-findings)
