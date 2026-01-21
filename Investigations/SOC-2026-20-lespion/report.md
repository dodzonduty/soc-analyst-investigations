# Incident Summary 
An investigation was launched into a compromised network that resulted in a total system outage. Preliminary findings identified a single user account, EMarseille99, as the source of the unauthorized activity. The investigation points to an insider threat facilitated by poor credential management and unsecured source code.
# Business Impact 
Availability: The client’s network was brought offline, causing a total cessation of business operations.
Confidentiality: credentials and an API key were exposed in a public GitHub repository.
#  Investigation Methodology
1. Reviewed the GitHub account EMarseille99 and identified repositories not originating from forks.
2. Performed static code analysis on the original repository to identify hardcoded secrets.
3. Confirmed the presence of exposed credentials and an API key within source code.
4. Assessed repository contents for indicators of misuse, such as cryptomining tooling references.
5. Evaluated the exposure risk and potential abuse scenarios related to the leaked credentials.
# Indicators of Exposure (IOEs)
| Type | Value | Description |
| :--- | :--- | :--- |
| **API Key** | `aJFRaLHjMXvYZgLPwiJkroYLGRkNBW` | leaked API key|
| **Username** | `EMarseille99` | embedded credentials|
| **Decoded Password** | `PicassoBaguette99` | embedded credentials after decoding from base64|
# Analysis & MITRE ATT&CK Mapping
## Analysis
I investigated the GitHub account provided; all the repos are forked, except one called [Project-Build---Custom-Login-Page](https://github.com/EMarseille99/Project-Build---Custom-Login-Page).  
Upon code review of the login page, there was a leaked API key and exposed credentials.
It has also been noted that the user uses a cryptocurrency mining tool called XMRIG.  
Using the Gmail found in the GitHub account, an Instagram account has been linked to the insider.
Attribution to a specific individual or malicious intent could not be conclusively established.
## MITRE ATT&CK Mapping 
Reconnaissance (T1593.003): Search Open Websites/Domains (GitHub).
Credential Access (T1552.001): Unsecured Credentials: Credentials in Files.
Defense Evasion (T1027): Obfuscated Files or Information (Base64 encoding).
# Verdict
Assessment: Credential Exposure Incident
Attribution Confidence: Low.  
Risk Level: Medium.  
The incident represents a security hygiene failure involving exposed secrets in source code. While no direct evidence of malicious exploitation was identified, the exposure presents a tangible risk and warrants remediation.
# Recommended Next Actions
**Escalate to L2**
Suggesting the following for  DevSecOps and threat intel teams:
1. Immediate Credential Rotation: Reset the password for EMarseille99 and all accounts associated with the exposed API key.
2. Revoke API Access: Invalidate the exposed API key (aJFR...) and issue a new one.
3. Implement Secret Scanning: Integrate tools like git-secrets or TruffleHog into the CI/CD pipeline to prevent future hardcoding of credentials.
4. HR/Legal Review: Provide these findings to the legal department for further action regarding the insider's breach of policy.
