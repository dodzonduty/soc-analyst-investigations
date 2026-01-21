# Incident Summary 
An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged activity exhibits behavior consistent with the Amadey Trojan Stealer. After further investigations, the activity is confirmed to be malicious, and there's a C2 communication that enabled downloading dynamic link libraries (.DLL) files to facilitate the persistence and credential harvesting mechanisms. 
# Business Impact 
Amadey is a Trojan bot that steals the credentials found on the infected machine. That means it disguises itself as legitimate software but with  malicious intent. This incident can lead to credential exposure, unauthorized access to intellectual properties, and, if left untreated, disrupt vital services.
#  Investigation Methodology
1. Viewed the process tree using a memory forensics tool to identify any rogue or masquerading processes.
2. Identified a process that utilizes a legit process name, but with a small typo.
3. Obtained the full path of the rogue process.
4. Analyzed network connections to identify external communications, confirmed C2 communication, and obtained C2 IP address.
5. Performed memory map dump with the process ID and filtered for GET requests, confirming the download of .DLL files.
6. Confirmed the successful installation of one of the DLL files and got its current path.
7. Filtered the memory dump for POST requests, confirming the exfiltration of a file, which may indicate credentials exposure.
8. Ran a file Scan to investigate additional persistence mechanisms used by the malware and confirmed the existence of the malware in `C:\Windows\System32\Tasks\lssass.exe`.

# IOCs
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP address** | `41.75.84.12` | C2 Server IP address |
| **Process name** | `lssass.exe` | **Important note**: in a real soc investigation this should be md5 or sha256 hash|
| **DLL file** | `clip64.dll` | malicious dll file downloaded by the malware|
| **DLL file** | `cred64.dll` | malicious dll file downloaded by the malware|
| **Observed Malicious Process Name** | `5315ff7b-4ad3-466a-8c77-17d0423ef5c3`| Exfiltrated file name |
# Analysis & MITRE ATT&CK Mapping
## Analysis
I loaded the `.vmem` using `volatility3` to uncover the process tree to navigate through processes to find any malicious or impersonating processes. Then, I identified a masquerading process that tries to impersonate lsass.exe -which is a critical Windows system process handling user authentication, security policy enforcement, and login management- called `lssass.exe` and has a process id of `2748`  
`2748	2524	lssass.exe	0xfa800300a750	7	254	1	True	2023-08-09 21:33:04.000000 	N/A
/* 3064	2748	rundll32.exe	0xfa8003042b30	1	64	1	True	2023-08-09 21:33:56.000000 	N/A`.  
To get a grasp of what's happening, the command line prompts has ben further investigated, and the path of the lssass.exe file has been identified. Note that the path is most likely an indication of malicious activity because it resides in `AppData\Local\Temp\`, which a lot of malware use as a go-to storing path    
`C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe`.  
Upon further investigations of the command line prompts and since the rogue process has a child rundll32.exe, there was a strong probability that there are malicious DLL files involved, and a command prompt utilizing a dll file that resides in the AppData folder and not signed by a trusted authority  
`3064	rundll32.exe	"C:\Windows\System32\rundll32.exe" C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`.   
To see whether the malware has external communications or not, the network communications of the infected machine have been investigated. Upon this investigation, it has been confirmed that the rogue process`lssass.exe` has communicated with the IP address `41.75.84.12`  
`0x1e94dcf0	TCPv4	192.168.195.136	49168	41.75.84.12	80	CLOSED	2748	lssass.exe	N/A`.  
Acting upon the C2 communication, A memory map dump has been generated for the process `2748`, and using `strings` utility in conjunction with grep, with an idea of filtering for `GET` requests in mind, it has been confirmed that there are 2 DLL files downloaded   
`GET /rock/Plugins/cred64.dll HTTP/1.1 
GET /rock/Plugins/clip64.dll HTTP/1.1`.  
To confirm or deny any exfiltration attempts, the same grep idea was used but with `POST` requests, and it has been confirmed that a successful exfiltration has occurred
`POST /5315ff7b-4ad3-466a-8c77-17d0423ef5c3/ HTTP/1.1`.  
To check for persistence techniques, filescan inspection has been made with grep for `lssass.exe` and it has been confirmed that `lssass.exe` resids in the `Tasks/` folder in windows which establishes persistence through a scheduled task; **trigger conditions were not recovered from memory**.
`C:\Windows\System32\Tasks\lssass.exe`
## MITRE ATT&CK Mapping 
Defense Evasion TA0005 --> Masquerading: Match Legitimate Resource Name or Location (T1036.005)  
Defense Evasion TA0005 --> System Binary Proxy Execution: Rundll32(T1218.011)  
Command and Control TA0011 --> Application Layer Protocol: Web Protocols (T1071.001)  
Persistence TA0003 --> Scheduled Task(T1053.005)  
# Verdict
Verdict: Malicious.  
Confidence: High.
This activity shows how malware can impersonate known processes like `lsass.exe`, utilize legit system processes like `rundll32.exe` using the Binary Proxy Execution technique, and ensure persistence via a scheduled task stored in C:\Windows\System32\Tasks
# Recommended Next Actions
**Escalate to T2**
Suggest the following actions: 
1. Isolate the infected machine and make sure that other machines in the same subnet are not communicating with the same IP address.
2. Kill the process `lssass.exe` and its descendants.
3. Delete the malicious DLL files.
4. Remove `lssass.exe` from Schdeuled Tasks folder.
5. Force the user to change passwords due to potential credential exfiltration
6. Hunt for the same scheduled task name or C2 IP across the environment.
