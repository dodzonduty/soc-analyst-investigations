# Incident Summary 
LLMNR and NetBIOS-NS protocols are used when DNS protocols fail to resolve the IP addresses to hostnames. In this incident, we encountered a potential LLMNR and NetBIOS poisoning attack, where a rogue machine impersonated an infrastructure server and successfully induced NTLM authentication and leveraged the credentials via NTLM relay
# Business Impact 
This Incident introduces credential exposure, which could lead to lateral movement, hence unauthorized access to private intellectual property and data exfiltration, and potentially, service disruption if further exploited 
#  Investigation Methodology
- Inspected the conversation to know which IPs spoke the most
- Checked the LLMNR packets and NetBIOS-NS packets, looking for suspicious behaviour, and found 2 IP addresses in a race condition to claim a nameserver
- Upon requesting a misspelled host, one of the 2 IPs instantly responded and authenticated with the machine showing malicious behavior
- Furhter Investigations has shown the rogue IP authenticating through SMBv2 with a machine using the stolen NTLM hash 
# IOCs 
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP** | `192.168.232.215` | rogue IP acting as DNS infrastructure |
| **IP** | `192.168.232.168` | Compromised User credentials IP|
| **IP** | `192.168.232.176` | Compromised User credentials IP|
| **namequery** | Fileshaare | query made by `192.168.232.168` that enabled the the attacker to authenticate |
| **namequery** | prinetr | query made by `192.168.232.168` that enabled the the attacker to authenticate |
| **Hostname** | Janesmith | hostname of the attacker |
# Analysis & MITRE ATT&CK Mapping
## Analysis
1- First, I took a look at the conversations to get a grasp of how many IPv4s we're working with and identify which IPs have talked the most. \
2- Then, I noticed 2 IPs, which are `192.168.232.148` and `192.168.232.215` is involved in many LLMNR and NetBIOS-NS responses, so I investigated even further using `llmnr` and `NBNS` filters. \
3- I found that the 2 IP addresses are in a **Race Condition** to claim the nameserver cybercactus, which is the domain name. \
4- I noticed a query from `192.168.232.168` asking for the ip address of the host `fileshaare`, which is misspelled, so the IP address `192.168.232.215` responded, confirming a malicious behavior. \
5- A query from `192.168.232.176` with the hostname `prinetr` has been answered by the rogue IP address. \
6- Upon further investigation, it has been proven that `192.168.232.215` used NTLM relay technique to authenticate to an SMBv2 Server with a hostname `Accounting` and the malicious account is `janesmith`. \
## MITRE ATT&CK Mapping 
Credential Access(TA0006) : Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay T1557.001
Collection(TA0009) : Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay T1557.001
# Verdict
Verdict: Malicious \
Confidence: High
This Activity demonstrates an LLMNR and NetBios-NS poisoning attack, followed by a successful SMBv2 session created
# Recommended Next Actions
**Escalation to T2**
* Suggesting to isolate the following IPs
  * 192.168.232.215 -> Rogue IP
  * 192.168.232.168 -> Infected machine
  * 192.168.232.176 -> Infected Machine
* Suggesting changing passwords for the NTLM because the hash has been compromised
* Disable LLMNR and NetBios-NS using group policy and only use DNS for name server resolution 
