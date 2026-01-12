# Incident Summary
This is a **suspected information-stealing incident** involving a malicious executable (`vpn.exe`) that communicated with an external server and **performed targeted data collection with attempted exfiltration** using HTTP POST requests.

# Business Impact 
This information-stealing attempt can introduce great risk when it comes to financials  in the future because the malware targeted the wallets of the cryptocurrency and the company may suffer from severe financial losses due to the credentials exfiltration
# Scope and Data Sources
* Dynamic Analysis via AnyRun
* Threat Intel enrichment using VirusTotal
* Network communication details obtained from sandbox telemetry

# Investigation Methodology
1. Reviewed dynamic execution behavior
2. Observed post-execution cleanup script, including `.dll` files
3. Analyzed network connections leading to discover the C2 server communication
4. Decoded POST requests to identify targeted data
5. Correlated observed behaviors with publicly documented information-stealing malware techniques.
# IOCs (Indicators of Compromise)
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP** | `171.22.28.221` | Suspected command-and-control endpoint IP |
| **Domain** | `http://171.22.28.221/5c06c05b7b34e8e6.php` | Suspected command-and-control endpoint URL |
| **PowerShell/CMD** | `"C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll" & exit` | Post-infection cleanup command |
| **MD5** | `12c1842c3ccafe7408c23ebf292ee3d9` | Hash of the `vpn.exe` file |
| **RC4 key** | 5329514621441247975720749009 | Encryption key obtained from the code 

# Analysis & MITRE ATT&CK Mapping
1. Upon clicking on `vpn.exe`, the following script gets executed
```
"C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll"" & exit
```
If we look closer, we can see that it takes a timeout of 5 seconds, then executes a series of deletion processes, including all the DLL files in ProgramData Directory.
2. After Further Investigations of the Network connections of the infected machine, it has been confirmed that the machine is communicating with a C2 server under the URL `http://171.22.28.221/5c06c05b7b34e8e6.php` that downloaded 7 DLL files. The downloaded DLL files appear to support the malware’s execution and network communication capabilities, consistent with information-stealing activity observed through outbound HTTP `POST` requests.

```
    sqlite3.dll
    freebl3.dll
    mozglue.dll
    msvcp140.dll
    nss3.dll
    vcruntime140.dll
    softokn3.dll
```
* **Execution TA0002** : Windows Command Shell T1059.003
* **Defense Evasion TA0005**: Indicator Removal: File Deletion T1070.004
* **Credential Access TA0006**: Unsecured Credentials: Credentials In Files T1552.001
* **Command and Control TA0011**Application Layer Protocol: Web Protocols:T1071.001
### Evidence of Targeted Data Collection
Decoded HTTP POST data revealed explicit file collection directives targeting user documents and cryptocurrency wallet-related files. The malware enumerated specific directories such as Documents, Desktop, Recent files, and AppData, searching for file patterns associated with wallet backups, recovery phrases, and application session data.
```
REC|%RECENT%\|*.txt,*.docx,*.xlsx|5|1|1|DOC|%DOCUMENTS%\|
*.txt,*.docx,*.xlsx|5|1|1|DESK|%DESKTOP%\|*.txt,*.docx,
*.xlsx|5|1|1|DESK|%DESKTOP%\|*exodus*.png,*exodus*
.pdf,*wallet*.png,*wallet*.pdf,*backup*.png,*backup*.pdf,*recover*.png,
*recover*.pdf,*metamask*.*,*UTC--*.*|1500|1|1|DOC|%DOCUMENTS%\|*exodus*.png,*exodus*.pdf,*wallet*.png,*wallet*.pdf,*backup*.png,*backup*.pdf,*recover*.png,*recover*
.pdf,*metamask*.*,*UTC--*.*|1500|1|1|REC|%RECENT%\|*exodus*.png,*exodus*.pdf,*wallet*.png,*wallet*.pdf,
*backup*.png,*backup*.pdf,*recover*.png,*recover*.pdf,*metamask*.*,*UTC--*.*|1500|1|1|NOTEPAD|%APDATA%\Notepad++|
*.xml|10|1|1|NOTEPAD|%APDATA%\backup\|*.*|10|1|1|SUBLIME|%APDATA%\Sublime Text 3\Local\Session.sublime_session\|
*.sublime_*|10|1|1|
```

This confirms intentional credential and asset targeting rather than opportunistic file theft.
# Verdict
Verdict: **Malicious** 
Confidence: High  
The activity demonstrates clear malicious behavior consistent with information-stealing malware. Attribution to a specific malware family is based on automated sandbox analysis and was not independently verified.

# Recommended Next Actions
*Escalate the incident to L2
* Suggest isolating the infected machine in a safe network
* Check using EDR whether another agent downloaded the `.exe` file or not
* Communicate with the Network Security dept to block the ip address ``171.22.28.221``
* Recommend a credential change and review that is stored on the infected machine
