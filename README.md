# BSVD - Baysec Vulnerability Database

## 📊 Database Statistics

- **Total Vulnerabilities**: 1
- **Last Updated**: 4/24/2025
- **Generated**: 6/22/2025

### Severity Breakdown
- 🟠 **High**: 1

## Vulnerabilities

### 1. BSVD-2025-001 - CVE-PENDING - DLL Sideloading/Hijacking in Double Commander

🟠 **HIGH** | Type: **VULNERABILITY**

**Identifiers:** CVE: `CVE-PENDING` | CVSS: `7.8`

**Description:**
Double Commander (v1.1.23 and prior) attempts to load certain DLLs (e.g., libheif.dll, librsvg.2-2.dll) from locations not securely bundled with the application. An attacker with write access to any directory in the system PATH may insert a malicious DLL to achieve arbitrary code execution. If the application is launched with administrative privileges, this can result in full system compromise. This vulnerability aligns with MITRE ATT&CK technique T1574.002: Hijack Execution Flow: DLL Side-Loading and can be leveraged by adversaries post-exploitation to maintain persistence or escalate privileges.

**Technical Details:**
- **CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Base Score**: 7.8
- **Exploitability Score**: 1.8
- **Impact Score**: 5.9
- **Affected Vendors**: Double Commander Team
- **Affected Products**: Double Commander v1.1.23 and earlier
- **CWE IDs**: CWE-427
- **MITRE ATT&CK**: T1574.002

**Discovered by:**
- **Krystian Bajno** (BAYSEC) - krystian.bajno@baysec.eu

**Fix Information:**
- **Fix Available**: Yes
- **Fixed in Version**: 1.1.24
- **Vendor Response**: Positive - Issue confirmed and fixed in version 1.1.24

**Proof of Concept:**
A benign DLL executing calc.exe was placed in a user-writable PATH directory. Upon launching doublecmd.exe, the DLL was loaded and the payload executed, demonstrating successful DLL hijacking. Behavior consistent with MITRE ATT&CK T1574.002. Visual proof-of-concept documentation (dll-sideloading.png, calc.png) available upon request.

**Disclosure Timeline:**
- **4/10/2025**: Initial Discovery - Vulnerability discovered and reported privately to Double Commander developers (alexx2000@mail.ru, rich2014.git@outlook.com, denis.bisson@denisbisson.org)
- **4/21/2025**: Vendor Response - Alexander Koblov confirmed fix deployed in Double Commander 1.1.24
- **4/22/2025**: CVE Request to MITRE - CVE ID requested from MITRE via cve-request@mitre.org
- **4/22/2025**: CERT.PL Notification - Parallel notification sent to CERT Polska
- **4/23/2025**: MITRE Acknowledgment - MITRE confirmed CVE request received 
- **4/24/2025**: CERT.PL Response - CERT.PL confirmed MITRE should handle as primary CNA per CVE assignment rules

**References:**
- [Reference 1](https://doublecmd.sourceforge.io)
- [Reference 2](https://github.com/doublecmd/doublecmd)
- [Reference 3](https://cve.mitre.org/cve/request_id.html)
- [Reference 4](https://news.baycode.eu/0x04-lateral-movement/#0x09-persistence-through-dll-hijacking-and-proxying)

**Tags:** `dll-sideloading`, `dll-hijacking`, `privilege-escalation`, `persistence`, `local-exploit`, `file-manager`

**Published**: 4/22/2025 | **Updated**: 4/24/2025

[📄 View full entry](./entries/BSVD-2025-001.json)


