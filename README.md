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

# Phase 1 — Harden

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




# Phase 2 — Install & Populate MySQL

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



# Phase 3 — Wire Logging to Log Analytics

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

**5. Verify the Azure Monitor Agent installed**

Creating the DCR triggers the extension install automatically. A failed install is a silent dead end, so confirm rather than assume.

**VM → Settings → Extensions + applications → `AzureMonitorWindowsAgent`**

<img width="910" height="643" alt="image" src="https://github.com/user-attachments/assets/861e56db-fad9-412d-82c6-a6a32524ce81" />

**6. Generate activity and verify ingestion**

Make test connections and run queries against MySQL first — the general log has nothing to say otherwise. First ingestion into a new custom table can take up to 30 minutes.

```kusto
MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "CORP-SDA1-HS12"
```

`RawData` holds the unparsed line. Structuring it is a Phase 4 problem; the only question here is whether records arrive at all.

<!-- SCREENSHOT: MySQLAudit_CL results showing recognizable MySQL connection/query text in RawData -->
<img width="922" height="755" alt="image" src="https://github.com/user-attachments/assets/a84ec83d-01d6-4693-ab33-307bc87555da" />


**7. Scope every query to this resource**

> ⚠️ `MySQLAudit_CL` is shared across the range and contains **every participant's** MySQL logs. Any unfiltered query returns other people's data.

```kusto
MySQLAudit_CL
| where _ResourceId endswith "CORP-SDA1-HS12"
```

This becomes non-negotiable in Phase 5 — without the filter, someone else's attacker looks like our incident.

<!-- SCREENSHOT: same query with and without the filter, showing the row count difference -->
<img width="915" height="640" alt="image" src="https://github.com/user-attachments/assets/9d937ec3-c8de-4efe-a5bf-40061787c1a1" />

---

- [x] Custom text log DCR created against the MySQL general log
- [x] Destination set to `LAW-Cyber-Range`
- [x] `AzureMonitorWindowsAgent` installed and healthy
- [x] `MySQLAudit_CL` returning scoped rows

> `RawData` is unparsed — field extraction happens in Phase 4 before any rule is written against it.



# Phase 4 — Write Detections (While the Box Is Still Clean)

Detections are authored **before** the VM is exposed, then verified silent against the clean baseline. If a rule fires now, it's a false positive I can fix while nothing is at stake — so the first real alert is a real intrusion.

Shared settings for both rules: **Severity** Medium · **MITRE** Initial Access / T1078 Valid Accounts · **Run every** 5 min, **lookup** last 5 hours · **Alert when** results > 0 · **Trigger alert for each event** · Incident creation on, alerts grouped when all entities match.

---

## Rule 1 — Successful Logon to the VM

**Name:** `CyberDefense-CORP-SDA1-HS12-tural`

```kusto
// Virtual Machine Logons
let MyDevice = "CORP-SDA1-HS12"; // MDE truncates the device name
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```

Scoped to `administrator` and `guest` — the accounts a stranger would try, and the ones weakened in Phase 5.

**Entity mapping:** Account → `AccountName` · Host → `DeviceName` · IP → `RemoteIP`

> 📸 **Screenshot:** Rule logic page — query with entity mapping expanded.
<img width="997" height="821" alt="image" src="https://github.com/user-attachments/assets/d0bb99aa-d06c-4563-8bb0-044a9519e7cd" />

---

## Rule 2 — Successful Login to MySQL

**Name:** `CyberDefense-CORP-SDA1-HS12-tural-successful`

`MySQLAudit_CL` lands as one blob per row in `RawData`, so it gets parsed into columns first. The catch: MySQL writes a `Connect` line for successes *and* failures — a failure just adds an `Access denied` line with the same `ConnectionId`. So the query collects every failed ID, then discards matching `Connect` lines. What's left is a genuine success.

```kusto
// MySQL successful logins
let MyDevice = "CORP-SDA1-HS12";
let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName =~ MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName =~ MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

**Entity mapping:** Account → `Username` · Host → `DeviceName` · IP → `IpAddress`

> 📸 **Screenshot:** Raw `MySQLAudit_CL` vs. parsed output — the blob becoming real columns.
> <img width="879" height="737" alt="image" src="https://github.com/user-attachments/assets/6e78eca9-ef81-40cd-9388-a8ea3c3c48a2" />


---

## Baseline Validation

Both queries were run manually across the full baseline window before enabling the rules. Both returned **zero results** — expected, since inbound traffic is still denied and no one has logged in from a public address.

> 📸 **Screenshot:** Analytics rules list showing both rules **Enabled**, and a query returning no results.

<img width="1407" height="437" alt="image" src="https://github.com/user-attachments/assets/212c4166-85e7-4047-9abc-469bf88ba494" />


**Phase 4 complete.** Detections are live and quiet. The next alert will come from someone who isn't me.



# Phase 5 — Weaken & Expose

**Host:** `CORP-SDA1-HS12`

## Steps

1. **Administrator** (`compmgmt.msc`) — enable, confirm in Administrators group, set a weak password (top-10 `rockyou.txt`).
2. **Guest** (`compmgmt.msc`) — enable, blank password, add to Users group.
3. **Guest network logon** (`secpol.msc` → User Rights Assignment) — remove Guest from *Deny log on through RDS* and *Deny log on locally*; add Guest/Remote Desktop Users to *Allow log on through RDS*. In Security Options, set *Limit blank passwords to console logon only* → **Disabled**.
4. **RDP** — add Guest under Remote Desktop Users, then `gpupdate /force`.
5. **MySQL** — expose over the network with a weak root login:
```sql
   CREATE USER 'root'@'%' IDENTIFIED BY 'root';
   GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
   FLUSH PRIVILEGES;
```
6. **Defender** — capture an Investigation Package *before* opening the firewall (clean-state baseline).
7. **Open the network** — disable Windows Firewall; weaken NSG to allow all inbound.

## Exposure timestamp

T0: ___2026-07-30T04:31:21.9289822Z___


## Vector
RDP brute-force → pivot to local MySQL → dummy data. Chain: **Initial Access → Discovery → Collection**. Optionally expose `3306` directly as insurance.


# Phase 6 — Detect the Breach

**Host:** `CORP-SDA1-HS12` · Sentinel + Defender for Endpoint + KQL
**Exposure start:** `2026-07-30T04:31:21.9289822Z`

Kept the exposed VM online, monitored logons, confirmed my Analytics Rule fired on a real intrusion, then traced what the attacker did.

---

## 1. Monitor logons

```kql
let MyDevice = "corp-sda1-hs12";
let ServerVulnerableDateTime = todatetime("2026-07-30T04:31:21.9289822Z");
DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName startswith MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, ActionType, LogonType
| order by TimeGenerated desc
```

Brute force = wall of `LogonFailed`. Breach = one `LogonSuccess`, `RemoteInteractive`.

![Failed and successful logons]
<img width="824" height="827" alt="image" src="https://github.com/user-attachments/assets/833326d3-c2d9-4cc0-be00-c9c69d711059" />

---

## 2. Incident created by my rule

Sentinel → Incidents. Fired. Set Active, verified entities (account, host, IP) mapped correctly.

![Incident and entity mapping]

<img width="1078" height="910" alt="image" src="https://github.com/user-attachments/assets/a525191e-7b40-4cd6-973b-837009867151" />

---

## 3. Scope the attacker's activity

```kql
let MyDevice = "corp-sda1-hs12";
let BreachTime = todatetime("2026-07-30T04:31:21.9289822Z");  // narrow to the successful logon
DeviceProcessEvents      // repeat for DeviceFileEvents, DeviceNetworkEvents
| where TimeGenerated > BreachTime
| where DeviceName startswith MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

Discovery commands, dropped tooling, outbound connection attempts — the last of which my NSG rules blocked.

![Attacker activity across tables]
<img width="970" height="761" alt="image" src="https://github.com/user-attachments/assets/796f34bb-44bc-404d-a4ce-d73d82d5a63b" />


## Attack chain

| Observation | Technique |
|-------------|-----------|
| Failed RDP logons from external IP | T1110.001 — Password Guessing |
| Successful `administrator` logon | T1078.003 — Valid Accounts: Local |
| Discovery commands | T1033 / T1087.001 |
| Tooling dropped to disk | T1105 — Ingress Tool Transfer |

---

## Outcome

Real intrusion, detected by my own rule, fully reconstructed from telemetry.

**Detection gaps:** *fill in* — what the rules missed and what I'd write next.

# Phase 7 — Analyze the Breach

---

## Objective

This phase can't be a step-by-step. What happens to the box depends entirely on who finds it and what they decide to try. So the job here is to watch, pivot, and take good notes until the data is worth something.

---

Every query below is anchored to the moment the box went vulnerable, so nothing from the clean baseline period pollutes the results.

---

## Step 1 — MySQL authentication

This one separates real logins from failed ones. MySQL logs both under `Connect`, so the query first collects every connection ID that got `Access denied`, then throws those out of the results — what's left actually got in.

```kusto
let MyDevice = "corp-sda1-hs12";
let MyTimeframe = todatetime("2026-07-30T04:31:21.9289822Z"); // when the box went vulnerable
let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName =~ MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName =~ MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

Most of it is `LogonFailure` — scanners hammering `root` from rotating IPs. What matters is a `LogonSuccess`, and especially an IP that fails repeatedly and then succeeds once. That timestamp anchors everything else.

> 📸 `![MySQL auth]

<img width="1009" height="869" alt="image" src="https://github.com/user-attachments/assets/45e46394-939c-4142-8e58-cbd76cf63c09" />


---

## Step 2 — MySQL queries

Once someone's in, the query log is where intent shows up.

```kusto
let MyDevice = "corp-sda1-hs12";
let ServerVulnerableDateTime = todatetime("2026-07-30T04:31:21.9289822Z");
MySQLAudit_CL
| where TimeGenerated > ServerVulnerableDateTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName =~ MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc
```

`DROP DATABASE`, 'recover_your_data' and ` CREATE DATABASE IF NOT EXISTS RECOVER_YOUR_DATA`  someone looking actively creating, dropping and ransoming database.

> 📸 `![MySQL queries]

<img width="981" height="826" alt="image" src="https://github.com/user-attachments/assets/7676107c-dc1e-4b43-b034-d13a0f56954b" />

---

## Step 3 — Virtual machine logons

```kusto
let MyDevice = "corp-sda1-hs12"; // MDE truncates at 15 chars — mine fits, so no cutoff
let ServerVulnerableDateTime = todatetime("2026-07-30T04:31:21.9289822Z");
DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName =~ MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```

A note on `=~`. The helper query uses `==`, which is case-sensitive in KQL. MDE doesn't always store the device name in the casing you expect, and a mismatch returns nothing at all — no error, just an empty table. I learned this the hard way in Phase 6, when a detection rule ran over 4,000 times without firing for exactly this reason. Every query in this phase uses `=~` instead.

> 📸 `![VM logons]

<img width="1006" height="841" alt="image" src="https://github.com/user-attachments/assets/c5d0c16e-ed7e-466d-833f-c7af32542eeb" />

---

## Step 4 — If they reached the OS, follow them into Defender

A successful Guest or Administrator logon means the story continues in MDE:

| Table | What it answers |
|---|---|
| `DeviceProcessEvents` | What they ran |
| `DeviceFileEvents` | What they dropped or took |
| `DeviceRegistryEvents` | Whether they set up persistence |
| `DeviceNetworkEvents` | Where the box started calling out to |
| `NTANetAnalytics` | Flow-level traffic, including what the NSG blocked |

###Full investigation report — unauthorized RDP access, 2026-07-30 (click to expand)
<details>
<summary><b>📄 Full investigation report — unauthorized RDP access, 2026-07-30 (click to expand)</b></summary>

<br>

### Incident Summary

| | |
|---|---|
| **Affected host** | `corp-sda1-hs12` (10.3.0.19) |
| **Source address** | 137.74.119.18 (OVH SAS, AS16276, Roubaix, France) |
| **Connection accepted** | 2026-07-30 03:29:28 UTC |
| **Successful logon** | 2026-07-30 04:31:21 UTC |
| **Session length** | Approximately 26 minutes |
| **Classification** | Confirmed unauthorized interactive access with administrative privileges |

A Windows 11 virtual machine was deliberately weakened and exposed to the public internet with Remote Desktop enabled, so that a genuine intrusion rather than simulated traffic would supply the incident data. On 2026-07-30 an external host successfully authenticated to the local administrator account and held an interactive session for roughly 26 minutes.

Investigation across five telemetry tables established that the intruder obtained full administrative control but wrote no files to disk, installed no persistence mechanism, and never established a channel back to their own infrastructure. The only substantive action observed was launching a web browser. A secondary finding emerged during the investigation: flow level network logging was never enabled, leaving a measurable gap in the available evidence.

### Timeline

| Time (UTC) | Event | Source table |
|---|---|---|
| 03:29:28 | Inbound TCP connection accepted on port 3389 from 137.74.119.18:20024 | `DeviceNetworkEvents` |
| 04:31:21 | Successful RemoteInteractive logon as `administrator` | `DeviceLogonEvents` |
| 04:31:25 | Windows begins constructing the user profile | `DeviceFileEvents` |
| 04:31:59 | Final registry write of the session | `DeviceRegistryEvents` |
| 04:32:06 | Microsoft Edge launched | `DeviceFileEvents` |
| 04:57:20 | Last observed activity, session ends | `DeviceFileEvents` |

Roughly 62 minutes separate the accepted connection from successful authentication, consistent with credential guessing rather than use of a known password.

> **Note on timestamps.** Advanced Hunting exports in local time (EDT, UTC−4) while the portal displays UTC. All times here have been normalized to UTC. Correlating raw exports without conversion makes related events appear four hours apart.

---

### Step 1 — Establishing the anchor · `DeviceLogonEvents`

**Question:** Did any external host successfully authenticate to this machine?

```kusto
let MyDevice = "corp-sda1-hs12";
DeviceLogonEvents
| where DeviceName startswith MyDevice
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| project Timestamp, AccountName, AccountDomain, LogonType, RemoteIP,
          ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

<img src="images/01-ip-entity.png" width="420">

Several successful logons from public addresses were returned. One was selected based on `LogonType`. **RemoteInteractive** corresponds to Windows Logon Type 10, indicating an interactive Remote Desktop session rather than a service or network authentication. That distinction is what makes the event worth pursuing: somebody had a live desktop in front of them.

The source belongs to OVH SAS on AS16276. Defender assigns it an entity reputation of **Suspicious (4/100)** and reports it observed on organization devices exactly **once** in the preceding 30 days.

Two qualifications. OVH is a legitimate large scale hosting provider, and low cost virtual servers there are routine infrastructure for opportunistic scanning, so the ASN alone is not incriminating. A reputation score of 4 out of 100 is likewise low confidence and does not support attribution. The weight of this investigation rests on host behavior.

**Anchor established:** `2026-07-30T04:31:21.9289822Z`

---

### Step 2 — Did they drop or take anything? · `DeviceFileEvents`

**Question:** Was any attacker supplied file written to the host?

```kusto
let MyDevice = "corp-sda1-hs12";
let Anchor = datetime(2026-07-30T04:31:21.9289822Z);
DeviceFileEvents
| where DeviceName startswith MyDevice
| where Timestamp between (Anchor - 15m .. Anchor + 6h)
| project Timestamp, ActionType, FileName, FolderPath, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp asc
```

<img src="images/02-file-events.png" width="900">

The export returned 163 events. Only **63 ran under the `administrator` account**, spanning 04:31:25 to 04:57:20 UTC. The remaining 100 belonged to `system` and `local service` and were attributed to platform tooling:

| Observed activity | Attribution |
|---|---|
| `__PSScriptPolicyTest_*.ps1` in `C:\Windows\SystemTemp` | PowerShell's own AllSigned execution policy probe |
| `powershell.exe` with parent `SenseIR.exe` or `MsSense.exe` | Defender for Endpoint live response engine |
| `csc.exe` writing a randomly named DLL | PowerShell compiling a type in memory |
| `sdbinst.exe` writing to `C:\Windows\apppatch\MergeSdbFiles` | Scheduled shim database maintenance, two hour cadence |
| `collectguestlogs.exe` producing `VMAgentLogs.zip` | Azure VM guest agent on its own timer |
| `schtasks.exe` writing `ScheduledTasks.csv` | Defender inventorying scheduled tasks |

Two entries warrant explicit mention rather than silent exclusion. `sdbinst.exe` writing an `.sdb` file matches **T1546.011 Application Shimming**, and `schtasks.exe` writing a file matches **T1053.005 Scheduled Task**. Both are benign here, and the only evidence establishing that is the parent process and account. Verifying parentage before flagging separates a finding from a false positive.

**Within the intruder's session:** the earliest events show `explorer.exe` with parent `userinit.exe` creating `Links\Desktop.lnk`, `Links\Downloads.lnk`, and Quick Launch shortcuts. This is Windows constructing a user profile, establishing that this was the **first interactive logon the account had ever performed on the host**. The intruder was not returning to an existing foothold.

All subsequent activity, 57 events between 04:32:06 and 04:57:20, originated from `msedge.exe` writing into `CRX_INSTALL` and `msedge_chrome_Unpacker_BeginUnzipping` directories under `%LOCALAPPDATA%\Temp`. These are Microsoft Edge components unpacking on first launch, originating from Microsoft rather than the intruder.

**Finding.** Nothing was dropped. No executables, scripts, or archives in any user writable location. No activity in Downloads, Desktop, `C:\Users\Public`, or `\PerfLogs`. The single substantive action was launching a browser.

> **Scope limitation.** `DeviceFileEvents` records creations, modifications, renames, and deletions. It does not record file reads, so it cannot establish whether data was accessed. The absence of staged archives and `\\tsclient\` redirected drive paths are weak negative indicators rather than proof.

---

### Step 3 — Did they establish persistence? · `DeviceRegistryEvents`

**Question:** Was any mechanism created that would restore access after the session ended?

```kusto
let MyDevice = "corp-sda1-hs12";
let SessionStart = datetime(2026-07-30T04:31:21Z);
let SessionEnd   = datetime(2026-07-30T04:57:20Z);
let Baseline =
    DeviceRegistryEvents
    | where DeviceName startswith MyDevice
    | where Timestamp between (SessionStart - 7d .. SessionStart - 1h)
    | distinct RegistryKey;
DeviceRegistryEvents
| where DeviceName startswith MyDevice
| where Timestamp between (SessionStart .. SessionEnd + 10m)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey !in (Baseline)
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| order by Timestamp asc
```

<img src="images/03-registry-events.png" width="900">

292 events survived the baseline diff:

| Account | Events | Source |
|---|---|---|
| `system` | 245 | Profile initialization and platform services |
| `network service` | 30 | `wmiprvse.exe` writing boot configuration objects |
| `administrator` | 15 | The intruder's session |
| `local service` | 2 | Service telemetry |

229 of the system events are `services.exe` with parent `wininit.exe`, all at one timestamp, creating per user service instances under `ControlSet001\Services\*_cd89cc`. Windows instantiates a private copy of every user scoped service the first time an account logs on interactively.

That reveals a genuine limitation. **A baseline diff loses most of its filtering power against a first logon**, because a newly created profile makes every user scoped key appear new by definition. The technique remained useful but excluded far less than it normally would.

**The 15 administrator events all occur within 34 seconds of logon**, between 04:31:26 and 04:31:59. All but one are `explorer.exe` with parent `userinit.exe`, or `ie4uinit.exe`, writing wallpaper values, `TranscodedImageCount`, Internet Settings defaults, and the `Shell Folders\Startup` path. Standard profile construction.

**One entry required closer examination:**

```
04:31:59 UTC   RegistryValueSet
HKEY_CURRENT_USER\...\CurrentVersion\Run
  MicrosoftEdgeAutoLaunch_19C07ACF7D464A64B5B7148C18E2096D
  = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    --no-startup-window --win-session-start
  Process: msedge.exe   Parent: setup.exe
```

A write to a `Run` key during an active intrusion occupies precisely the location used by **T1547.001 Registry Run Keys and Startup Folder**, and it was the only event in the dataset landing in a persistence location. It was cleared on three grounds: the target is the signed Edge binary under `Program Files (x86)` rather than a Temp or AppData path, the switches are Edge's documented background launch behavior, and the writing process is Edge's own installer.

**Finding.** No persistence was established. No modifications to `Winlogon`, `Image File Execution Options`, `LSA`, or `Policies\System`. No new services. No changes to Terminal Server settings, meaning no attempt to preserve RDP access.

> **Note on filter construction.** An earlier version of this query used `has_any` against key paths and produced a false positive on `CurrentVersion\Explorer\Shell Folders`. KQL's `has_any` performs term matching and treats the backslash as a delimiter, so `CurrentVersion\Run` can match on the `CurrentVersion` token alone. The filter was rebuilt using `contains` with a leading backslash.

---

### Step 4 — Was the host calling out? · `DeviceNetworkEvents`

**Question:** Is there network layer evidence of the connection, and did the host contact the source infrastructure?

```kusto
let MyDevice = "corp-sda1-hs12";
let AttackerIP = "137.74.119.18";
DeviceNetworkEvents
| where DeviceName startswith MyDevice
| where Timestamp between (datetime(2026-07-29) .. datetime(2026-07-31))
| where RemoteIP == AttackerIP
| project Timestamp, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

<img src="images/04-network-events.png" width="900">

A single record was returned:

| Field | Value |
|---|---|
| Timestamp | 2026-07-30 03:29:28 UTC |
| ActionType | `InboundConnectionAccepted` |
| Local endpoint | 10.3.0.19:3389 |
| Remote endpoint | 137.74.119.18:20024 |
| Protocol | TCP |
| Process | `svchost.exe` running as `network service` |

This is the strongest single artifact in the investigation, because it captures the accepted connection at the network layer rather than inferring it from an authentication event, and it independently corroborates the logon.

Two conclusions follow. The connection was accepted roughly **62 minutes before** successful authentication, supporting credential guessing over use of a known password. And this is the **only** record of the address in the table, meaning **no outbound connection was ever made back to it**. No callback, no beacon, no command and control channel.

> **Interpretation limit.** `DeviceNetworkEvents` is weighted toward outbound connections and records inbound sessions to listening services inconsistently. The single inbound record is meaningful, but the absence of further inbound records is not evidence about connection volume. That question belongs to flow logs.

---

### Step 5 — Flow level traffic and blocked connections · `NTANetAnalytics`

**Question:** What did the network security group block, and can flow data corroborate the host based findings?

```kusto
NTANetAnalytics
| where SrcIp == "137.74.119.18" or DestIp == "137.74.119.18"
| project TimeGenerated, FlowStartTime, FlowEndTime, FlowType, FlowStatus,
          SrcIp, SrcPorts, DestIp, DestPort, L4Protocol,
          AllowedInFlows, DeniedInFlows, NsgRule
| order by TimeGenerated asc
```

<img src="images/05-nta-empty.png" width="900">

Zero records. The query ran without a time constraint across the available retention window, and no flow data exists for this address in either direction.

**This is a detection gap rather than a finding about the intruder.** NSG flow logs with Traffic Analytics were never configured to export into the `LAW-Cyber-Range` workspace, so no flow level record of the exposure period exists at all. An empty result from a table that was never populated says nothing about what occurred on the wire.

**Analytical impact:**

- **Denied inbound volume is unmeasured.** The scanning and brute force pressure absorbed while exposed cannot be quantified, which is precisely the metric that would demonstrate the value of the exposure exercise.
- **Byte counts are unavailable.** Session transfer volume was the last remaining proxy for whether data left the machine.
- **Threat intelligence enrichment is missing.** Traffic Analytics classifies flows matching Microsoft threat intelligence as `MaliciousFlow`.

**Remediation.** Enable NSG flow logs with Traffic Analytics against `LAW-Cyber-Range` before the next exposure period, so network layer coverage exists independently of the endpoint agent.

---

### Findings

**Confirmed.** An external host obtained interactive administrative access to `corp-sda1-hs12` over RDP and maintained a session for approximately 26 minutes.

**No files were written.** No executables, scripts, or archives attributable to the intruder appear anywhere on disk.

**No persistence was established.** No autostart entries, services, Winlogon modifications, or RDP configuration changes.

**No command and control.** The host never initiated an outbound connection to the source address.

**Telemetry gap identified.** Flow level network logging was not enabled during the exposure period.

### MITRE ATT&CK mapping

| Tactic | Technique | Supporting evidence |
|---|---|---|
| Initial Access | T1078.003 Valid Accounts: Local Accounts | Successful `administrator` logon from an external host |
| Lateral Movement | T1021.001 Remote Services: RDP | LogonType RemoteInteractive, inbound TCP 3389 accepted |
| Credential Access | T1110 Brute Force *(suspected)* | 62 minute interval between connection and authentication |
| Discovery | T1083 File and Directory Discovery *(suspected)* | Interactive session with no observable write activity |
| Persistence | Not observed | No autostart, service, or Winlogon modification |
| Command and Control | Not observed | No outbound connection to the source address |
| Exfiltration | Not determinable | No staging evidence; read activity is not logged |

### Limitations

None of these tables record file reads, so whether the intruder viewed the MySQL data, opened configuration files, or enumerated stored credentials is unknown. Browser destinations during the session were not resolved, leaving open the possibility that the host was used as a browsing proxy. With flow logging absent, session transfer volume does not exist as evidence.

The absence of persistence establishes that the intruder did not intend to return. It does not establish that nothing was taken.

### Next steps

1. Resolve Microsoft Edge network destinations for the 04:31 to 04:57 UTC window.
2. Enable NSG flow logs with Traffic Analytics against `LAW-Cyber-Range`.
3. Author a detection rule for RemoteInteractive logons from public addresses and validate it against this incident.

</details>

[step4.md](https://github.com/user-attachments/files/31383242/step4.md)

---

## Step 5 — Let it run, then shut it down

The lab asks for 24 hours minimum. I left everything reachable for **[FILL IN]** hours, until the activity started repeating and nothing new was showing up.

Before deallocating I exported the tables to CSV — the VM goes away, the logs shouldn't. Then I stopped the VM and put the deny-all inbound rule back on the NSG.

> 📸 `![Shutdown](./screenshots/phase7-06-shutdown.png)`

---

## Step 6 — Run the logs through AI

Three separate passes: MySQL authentication, MySQL queries, and Defender host logs. Same prompt each time, log type swapped in:

```text
You are a god-tier cybersecurity analyst with world-class threat hunting skills.
Please look at these logs, these are <MySQL Server Authentication / MySQL Server
Query / Microsoft Defender (MDE)> logs from my environment.
Please analyze them and paint a picture for what might be going on.
```

I treated the output as a starting point, not an answer. Anything it claimed, I went back and checked against the raw logs. Some of it held up, some of it was a reasonable guess with nothing behind it, and a couple of things were flat wrong. All three got noted — knowing where the model overreaches is part of the point.

> 📸 `![AI analysis](./screenshots/phase7-07-ai-analysis.png)`

---

## What I found

*[Fill in from the notes.]*

| | |
|---|---|
| Exposure window | *[FILL IN]* |
| Distinct source IPs | *[FILL IN]* |
| Failed logins | *[FILL IN]* |
| Successful logins | *[FILL IN]* |
| Time to first contact | *[FILL IN]* |

Short version of the attack: *[who reached the box, how they got in, what they did once they were there, and how far they got before I pulled the plug].*

---
