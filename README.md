<div align="center">

<img width="189" height="73" alt="logn-pacific-logo" src="https://github.com/user-attachments/assets/dc939a98-dcbe-4ad2-b1d5-f59b351e4bf5" />

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

### Honeypot Architecture 
<img width="1083" height="709" alt="image" src="https://github.com/user-attachments/assets/708f6f78-82a7-440d-9734-30b49429a414" />

## Phase 1 — Harden

**Goal:** Deploy the VM, seal it from the internet, confirm telemetry before any control is loosened.

**1. Deploy Windows 11 VM with public IP**
Named `CORP-SDA1-HS12` to look like a real asset, not a lab.

<img width="976" height="587" alt="image" src="https://github.com/user-attachments/assets/95813954-7b00-4f3b-be60-eb04679e5e9a" />


**2. Deny all inbound traffic from the internet**
The core control of this phase and the one reversed in Phase 5.

<img width="936" height="451" alt="image" src="https://github.com/user-attachments/assets/90a06231-f7af-4076-8832-41677dae977f" />


**3. Onboard to Microsoft Defender for Endpoint**

<img width="989" height="592" alt="image" src="https://github.com/user-attachments/assets/10599074-bbf7-4c36-b073-063214bee861" />


**4. Verify telemetry in `DeviceInfo`**

```kusto
DeviceInfo
| where DeviceName startswith "corp-sda1-hs12"
| top 10 by Timestamp desc
```

<img width="978" height="687" alt="image" src="https://github.com/user-attachments/assets/6ca1214e-b4ed-4903-b58c-ac65d2a9ee8a" />

---

- [x] VM deployed, public IP assigned
- [x] All inbound internet traffic denied
- [x] MDE onboarded and returning rows in `DeviceInfo`

> Egress not yet restricted — lock down before Phase 5.

## Phase 3 — Wire Logging to Log Analytics

**Goal:** Ship MySQL's own activity log into `LAW-Cyber-Range` so database activity is queryable alongside endpoint telemetry.

Defender tells us what happens *on* the box — processes, logons, connections. It says nothing about what happens *inside* MySQL. Since the database is the lure, that gap is the whole exposure. The Azure Monitor Agent (AMA) reads the log file off disk; a Data Collection Rule (DCR) tells it which file to watch and where to send it.

**1. Confirm the VM is running**

A deallocated VM ships nothing and throws no error. Most common cause of an empty table 30 minutes later.

<!-- SCREENSHOT: VM overview blade — hostname CORP-SDA1-HS12 with Status: Running -->

**2. Confirm existing telemetry is current**

Prove the Phase 1 pipeline is healthy before adding a source, so a later failure is attributable to the DCR and not to onboarding.

```kusto
DeviceInfo
| where DeviceName startswith "CORP-"
| top 10 by Timestamp desc
```

<!-- SCREENSHOT: DeviceInfo query results with a recent Timestamp visible -->

**3. Create the custom text log DCR**

**Monitor → Data Collection Rules → Create → Custom Text Logs**

| Setting | Value |
|---------|-------|
| File pattern | `C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log` |
| Table name | `MySQLAudit_CL` |
| Record delimiter | `TimeStamp` |
| Timestamp format | `ISO 8601` |

The record delimiter matters more than it looks — MySQL writes multi-line entries, and splitting on the timestamp keeps one query event as one row instead of shredding it across several. A typo in the file pattern deploys cleanly and silently watches nothing.

<!-- SCREENSHOT: DCR data source config showing file pattern, table name, delimiter, timestamp format -->

**4. Set the destination to `LAW-Cyber-Range`**

Same workspace as the Defender telemetry, so Phase 4 detections can correlate database activity against process and logon events in a single query.

<!-- SCREENSHOT: DCR Destination tab with LAW-Cyber-Range selected -->

**5. Verify the Azure Monitor Agent installed**

Creating the DCR triggers the extension install automatically. A failed install is a silent dead end, so confirm rather than assume.

**VM → Settings → Extensions + applications → `AzureMonitorWindowsAgent`**

<!-- SCREENSHOT: Extensions blade showing AzureMonitorWindowsAgent, status Succeeded -->

**6. Generate activity and verify ingestion**

Make test connections and run queries against MySQL first — the general log has nothing to say otherwise. First ingestion into a new custom table can take up to 30 minutes.

```kusto
MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "CORP-SDA1-HS12"
```

`RawData` holds the unparsed line. Structuring it is a Phase 4 problem; the only question here is whether records arrive at all.

<!-- SCREENSHOT: MySQLAudit_CL results showing recognizable MySQL connection/query text in RawData -->

**7. Scope every query to this resource**

> ⚠️ `MySQLAudit_CL` is shared across the range and contains **every participant's** MySQL logs. Any unfiltered query returns other people's data.

```kusto
MySQLAudit_CL
| where _ResourceId endswith "CORP-SDA1-HS12"
```

This becomes non-negotiable in Phase 5 — without the filter, someone else's attacker looks like our incident.

<!-- SCREENSHOT: same query with and without the filter, showing the row count difference -->

---

- [x] Custom text log DCR created against the MySQL general log
- [x] Destination set to `LAW-Cyber-Range`
- [x] `AzureMonitorWindowsAgent` installed and healthy
- [x] `MySQLAudit_CL` returning scoped rows

> `RawData` is unparsed — field extraction happens in Phase 4 before any rule is written against it.
