# Incident Summary
Multiple SMB sessions were created from a user called `ssales` on the host `HR-PC` using the PsExec sysinternal process, although the behaviour seemed normal for every session; however, the context-multiple targets, rapid sessions through a short period of time, and unusual account usage- suggests malicious lateral movement and requires further investigation using EDR logs.
# Business Impact 
If proven malicious, this activity could indicate an attacker infiltrating our infrastructure, stealing credentials, and exposing intellectual property.
# Investigation Methodology
1. Obtained the PCAP file and looked through conversations to measure data transfer between internal hosts.
2. Identified a successful NTLM authentication between 10.0.0.130 (HR-PC) and 10.0.0.133 (SALES-PC) using the user account `ssales`.
3. Observed a Tree Connect request to the `IPC$` share on `SALES-PC`, indicating the establishment of RPC and named pipe communication channels commonly used for remote service interaction.
4. Detected multiple IOCTL (FSCTL_PIPE_TRANSCEIVE) requests, consistent with PsExec’s interaction with Windows named pipes and service control mechanisms.
5. Confirmed a successful tree connect request to the share `ADMIN$`, indicating administrative-level access to the target host, which enabled the execution of `PSEXECSVC` sysinternal process, creating session-specific key files like  `PSEXEC-HR-PC-1C6C5D14.key` used for secure communication between PsExec client and service, and pipes acting as communication channels like :
   * `PSEXECSVC`
   * `PSEXESVC-HR-PC-7980-stdin`
   * `PSEXESVC-HR-PC-7980-stdout`
   * `PSEXESVC-HR-PC-7980-stderr`
  6. Confirmed the termination of the session between `10.0.0.130` and `10.0.0.133`.
  7. Identified a failed NTLM negotiation from `10.0.0.130` to `10.0.0.131` using the user `jdoe`.
  8. Confirmed a successful NTLM negotiation from `10.0.0.130` to `10.0.0.131` under the user `IEUser`.
  9. A successful connection to both shares `IPC$` and `ADMIN$`, followed by creating multiple key files spanning over a short period of time
     * `PSEXEC-HR-PC-8FF87B23.key`
     * `PSEXEC-HR-PC-AF58F077.key`
     * `PSEXEC-HR-PC-CF174DD5.key` 
  
# IOCs (Indicators of Compromise)
| Type       | Value        | Description                                |
| :--------- | :----------- | :----------------------------------------- |
| ****IP Address**** | 10.0.0.130   | Source host initiating PsExec activity     |
| **IP Address** | 10.0.0.133   | Target host `(SALES-PC)`                     |
| ****IP Address**** | 10.0.0.131   | Secondary target host `(Marketing-PC)`                  |
| **Username**   | ssales       | Account used for remote SMB authentication on `10.0.0.133` |
| **Username**   | IEUser       | Account used for remote SMB authentication `10.0.0.131` |
| **Username**   | jdoe         | Failed authentication attempt `10.0.0.131`              |
| **File**       | PSEXESVC.exe | PsExec service binary deployed remotely    |
| **File**       | PSEXEC-*.key | Session-specific PsExec key files          |
| **SMB Share**  | IPC$         | Named pipe and RPC communication share     |
| **SMB Share**  | ADMIN$       | Administrative file share                  |
| **Named Pipe** | PSEXESVC     | PsExec service communication channel       |

# Analysis & MITRE ATT&CK Mapping
## Analysis 
Although PsExec is a legitimate tool, the context and detected behavior deviate from typical IT operations.   
The initiation of PsExec sessions from `HR-PC` to 2 different hosts, `SALES-PC` and `MARKETING-PC` combined with rapid session creation and unusual account activity, suggests potential lateral movement.  
The sequence of SMB operations from  
`multiple failed authentications with different users and then a success` &rarr; `IPC$` &rarr; `ADMIN$` &rarr; `service deployment` &rarr; `RCE`.  
leans towards being a lateral movement activity other than normal administrative remote operations.  
While each connection appears benign, the overall behavioral pattern suggests suspicious activity requiring escalation and endpoint-level validation.
## MITRE ATT&CK mapping 
Privilge Escalation (TA0004) &rarr; Valid Accounts: Local Accounts (T1078.003).  
Persistence (TA0003) &rarr; Valid Accounts: Local Accounts (T1078.003).  
Execution (TA0002) &rarr; Command and Scripting Interpreter (using PsExec).  
Lateral Movement (TA0008) &rarr; Lateral Tool Transfer(T1570).  
Lateral Movement (TA0008) &rarr; Remote Services: SMB/Windows Admin Share (T1021.002).  
Discovery(TA0007)  &rarr; Remote System Discovery (T1018)
# Verdict
Verdict: Needs further investigation through endpoint logs.  
Confidence: Medium.  
Suspicious activity consistent with PsExec-based lateral movement was identified. While the activity cannot be conclusively confirmed as malicious at this stage, the behavioral context strongly suggests unauthorized remote execution. Escalation to L2/L3 investigation is recommended.
# Recommended Next Actions
**Escalate to T2**
1. Collect EDR and Sysmon logs from 10.0.0.130, 10.0.0.133, and 10.0.0.131.
2. Verify whether `ssales` and `IEUser` accounts are authorized for administrative remote access.
3. Check for additional PsExec execution or service creation events across the network.
4. Review endpoint process trees to confirm command execution activity.
5. Reset potentially compromised accounts.
