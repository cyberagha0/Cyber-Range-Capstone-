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




## Phase 2 — Install & Populate MySQL

**Goal:** Stand up MySQL on the hardened VM, load it with realistic data, and turn on the logging that Phase 3 will ship to the workspace.

The database is the lure. It needs to look like something worth reaching — populated with plausible corporate data rather than an empty default install — and it needs to record every connection attempt and query, success or failure, before the box is ever exposed.

**1. Install the Visual C++ 2019 Redistributable (x64)**

A hard prerequisite for MySQL 8.0. Installing MySQL first just fails partway through.

- [Microsoft Visual C++ 2019 Redistributable (x64)](https://aka.ms/vc14/vc_redist.x64.exe) — [supported versions reference](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#latest-supported-redistributable-version)

**2. Install MySQL 8.0.45**

- [mysql-installer-community-8.0.45.0.msi](https://downloads.mysql.com/archives/get/p/25/file/mysql-installer-community-8.0.45.0.msi) — [installer archive](https://downloads.mysql.com/archives/installer/)

Choose **Developer Default** or **Full** so Workbench installs alongside the server. Accept defaults everywhere else.

Set a **strong root password** and store it in a password manager. This stays strong through Phase 4 — credential weakening is a deliberate Phase 5 change, not a shortcut taken now.

<!-- SCREENSHOT: MySQL installer setup type screen with Developer Default selected -->

**3. Connect via MySQL Workbench**

Create a new connection and confirm it opens against the local instance.

<!-- SCREENSHOT: Workbench connection established, server status green -->
<img width="341" height="200" alt="image" src="https://github.com/user-attachments/assets/849ab1fe-6b33-4064-bdab-492db735272e" />

**4. Import the sample dataset**

Download [`db_info_import.sql`](https://drive.google.com/file/d/1xwJBq_96ehR-obBPZYEgqrSwwmhGSAhW/view?usp=drive_link) to the VM, open it as an SQL script in Workbench, and execute.

> ⚠️ Workbench will appear frozen — it isn't, the insert volume is just large. If the connection drops, re-authenticate and retry. If it fails repeatedly, reduce the user count in the script from 5000 to 1000 or fewer.

**5. Enable general query logging**

This is what makes the database observable. Every connection — successful or not — and every query gets written to a file on disk.

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
```

<!-- SCREENSHOT: SHOW VARIABLES output confirming general_log = ON and the file path -->

**6. Replace `my.ini`**

Download [`my.ini`](https://drive.google.com/file/d/1_rc2H24rRgJrN0aQ9m-NLUiR7agcsY2j/view?usp=drive_link) and overwrite:

```
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
```

Two changes matter here. It pins the log destination so the path is predictable for the DCR, and it permits network logins — without that, MySQL only listens on loopback and no remote attacker could ever reach it in Phase 5.

Log path:

```
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

**7. Restart the `MySQL80` service**

`services.msc` → restart. The `SET GLOBAL` statements above are runtime-only; the `my.ini` changes need the restart to take effect and to survive reboots.

<!-- SCREENSHOT: services.msc showing MySQL80 running after restart -->

**9. Verify the log is writing**

Run a few `SELECT` queries in Workbench, then open `mysql_general.log` and confirm they appear.

```sql
SELECT * FROM lnp_corp.employees LIMIT 10;
```

<!-- SCREENSHOT: mysql_general.log open in a text editor showing the SELECT statements and connection entries -->
<img width="787" height="611" alt="image" src="https://github.com/user-attachments/assets/76a8cf0e-dde2-43ee-aa49-9b10ba6064d1" />

---

- [x] VC++ 2019 Redistributable installed
- [x] MySQL 8.0.45 installed with Workbench, strong root password
- [x] `lnp_corp` schema imported and populated
- [x] `general_log = ON`, output set to `FILE`
- [x] `my.ini` replaced, network login enabled
- [x] `MySQL80` restarted, queries confirmed in `mysql_general.log`
- [ ] *Optional:* [full server backup via Workbench export](https://dev.mysql.com/doc/workbench/en/wb-admin-export-import-management.html)

> Log path for Phase 3: `C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log`
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
