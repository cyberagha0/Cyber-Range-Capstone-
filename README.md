<img width="189" height="73" alt="logn-pacific-logo" src="https://github.com/user-attachments/assets/dc939a98-dcbe-4ad2-b1d5-f59b351e4bf5" />
<div align="center">

# Explainable Detection Engineering System

**Detection rules that don't just fire — they explain themselves.**

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-005c8a?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped_to-MITRE_ATT%26CK-c1272d?style=flat-square)
![Atomic Red Team](https://img.shields.io/badge/Validated_with-Atomic_Red_Team-1f6feb?style=flat-square)
![Python](https://img.shields.io/badge/Python-3776ab?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-complete-success?style=flat-square)

<sub>Capstone · B.S. Cybersecurity, Champlain College · CMIT-450</sub>

</div>

---

Most SOC analysts inherit alerts they can't interpret. A rule fires, the
dashboard turns red, and nobody can say *why* this event mattered or what
the attacker was actually trying to do.

This project builds nine custom Wazuh detection rules across a three-host
lab — Rocky Linux, Windows 10, and Kali — each mapped to a specific MITRE
ATT&CK technique, validated against live Atomic Red Team executions, and
paired with an LLM explainability layer that translates a raw alert into
plain-language analyst context.

**Techniques covered:** `T1110` Brute Force · `T1078` Valid Accounts ·
`T1059.001` PowerShell · `T1059.004` Unix Shell · `T1547.001` Registry
Run Keys · `T1087.001` Local Account Discovery

### Jump to

[Architecture](#architecture) · [Threat Model](#threat-model) · [Detection Rules](#detection-rules) · [Validation Results](#validation-results) · [Setup](#setup)
