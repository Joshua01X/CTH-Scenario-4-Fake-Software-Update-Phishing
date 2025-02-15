# Threat Hunting: Investigating Possible Phishing Campaign Via Fake Software Update

## Introduction/Objectives
This project focuses on a comprehensive threat hunting investigation using a virtual machine hosted within Microsoft Azure. The investigation is conducted through Microsoft Defender for Endpoint (MDE), leveraging Kusto Query Language (KQL) for log analysis. The primary objective of this threat hunt is to identify and analyze potential security threats arising from devices exposed to the internet. This involves detecting malicious activity, identifying indicators of compromise (IoCs), and formulating an effective incident response strategy to mitigate risks.

## Components, Tools, and Technologies Employed
**Cloud Environment:** Microsoft Azure (VM-hosted threat-hunting lab)  
**Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)  
**Query Language:** Kusto Query Language (KQL) for log analysis  

## Scenario
A corporate employee receives an email appearing to be from IT support, instructing them to download and install a "critical software update." The email contains a hyperlink leading to a malicious website hosting a PowerShell payload. The user, believing the email to be legitimate, downloads and executes the script, resulting in further compromise. The script enables adversaries to establish persistent access, execute remote commands, and potentially exfiltrate sensitive information through a command-and-control (C2) server. The objective of this investigation is to trace the entire attack chain, identify affected assets, and mitigate the threat.

## High-Level IoC Discovery Plan
The threat hunting process follows a structured methodology to detect IoCs associated with this attack scenario. The investigation begins by identifying malicious file downloads, followed by tracking script execution on endpoints. Further queries analyze network connections to determine whether communication with external malicious entities occurred. The final phase involves correlating observed behaviors with MITRE ATT&CK techniques to understand the adversary’s tactics and techniques. Each step is reinforced by executing targeted KQL queries in MDE.

## Steps Taken

### Phase 1
A phishing email masquerading as an IT support message instructs users to install a "critical software update." Clicking the link results in the download of a PowerShell script onto the victim’s machine.

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "tphish"
| where FileName endswith "ps1"
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/f37817c0-d820-41b6-8d94-eab0964fc29f)

---

### Phase 2
After the initial download, the PowerShell script executes on the infected machine, initiating further malicious actions.

**First KQL Query Used:**
```
let VMName = "tphish";
let specificTime = datetime(2025-01-26T19:01:29.0367754Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/c4ddb801-0d7d-465c-8c76-34cd3aee720b)


**Second KQL Query Used:**
```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "phishingFakeSoftwareUpdate.ps1" or ProcessCommandLine contains "Add-Type -AssemblyName PresentationFramework"
| extend Timestamp = Timestamp, InitiatingProcessAccountName = InitiatingProcessAccountName
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/8b249ae6-cb71-48f0-8f52-dd1fb54da9af)


---

### Phase 3
The malicious script initiates outbound communication with an external command-and-control (C2) server, potentially exfiltrating sensitive credentials.

**KQL Query Used:**
```
union DeviceNetworkEvents, DeviceProcessEvents
| where Timestamp > ago(6h)
| where RemoteUrl contains "raw.githubusercontent.com" or InitiatingProcessCommandLine has "phishingFakeSoftwareUpdate.ps1"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, FileName, FolderPath, ActionType
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/f6b6120c-8413-4249-9460-f6f51b2b8e8a)


---

## Response

### Mitigation Steps
**Containment:**
- Block the malicious domain on the firewall and DNS servers.
- Disable compromised user accounts and enforce password resets.
- Isolate infected machines from the network.

**Eradication:**
- Deploy updated antivirus signatures to detect and remove the malware.
- Conduct system-wide scans using Endpoint Detection and Response (EDR) tools.

**Recovery:**
- Restore affected systems from backups.
- Re-enable user access after ensuring systems are clean.

### Post-Incident Improvements
**Proactive Monitoring:**
- Strengthen SIEM rules to detect phishing emails.
- Integrate threat intelligence feeds to block new malicious domains.
- Implement detection rules for similar attack patterns.

**User Awareness:**
- Conduct mandatory phishing training, including simulation tests.
- Distribute a phishing awareness guide via company communication channels.

## Tactics, Techniques, and Procedures (TTPs) from MITRE ATT&CK Framework
- **T1193** - Spear Phishing Link
- **T1059.001** - PowerShell Execution
- **T1071.001** - Web Protocols
- **T1210** - Exploitation of Remote Services

