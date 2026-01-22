# Detection Lab Journey

My cybersecurity homelab documenting my path to Detection Engineer.

## Lab Setup (January 2026)
- **Hypervisor:** Proxmox on Dell R720
- **SIEM:** Wazuh v4.14.2
- **Target Systems:**
  - Windows 11 with Sysmon (Custom Configuration from SwiftOnSecurity)
  - Debian Linux
- **Attack Simulation:** Atomic Red Team
- **AD Environment:** GOAD-Light (Game of Active Directory)
  - **Domain:** `sevenkingdoms.local`
  - **Child Domain:** `north.sevenkingdoms.local`

## Infrastructure

| Hostname | Role | OS | IP | Status | Agent Name |
|----------|------|----|----|--------|------------|
| **Wazuh-Server** | SIEM / Manager | Amazon Linux 2023 | `10.10.0.154` | 🟢 Active | `wazuh-server` |
| **Win11-Target** | Workstation Target | Windows 11 | `10.10.0.156` | 🟢 Active | `win11-agent` |
| **Debian-Target** | Attack Box / Target | Debian 12 | `DHCP` | 🟢 Active | `debian-agent` |
| **DC01** | Forest Root DC (KingsLanding) | Windows Server 2019 | `10.10.0.61` | 🟢 Active | `DC01-KingsLanding` |
| **DC02** | Child Domain DC (Winterfell) | Windows Server 2019 | `10.10.0.56` | 🟢 Active | `DC02-Winterfell` |
| **SRV02** | Member Server (CastelBlack) | Windows Server 2019 | `10.10.0.64` | 🟢 Active | `SRV02-CastelBlack` |

## Detection Rules

| Rule ID | Name | MITRE ATT&CK | Status |
|---------|------|--------------|--------|
| 100001 | Mimikatz Detection (filename) | T1003 | ✅ Tested |
| 100002 | Mimikatz Detection (cmdline) | T1003 | ✅ Tested |
| 100003 | Encoded PowerShell Commands | T1059.001 | ✅ Tested |
| 100004 | PowerShell Download Cradle | T1059.001 | ⬜ Untested |
| 100005 | Local Account Creation | T1136.001 | ✅ Tested |
| 100006 | Scheduled Task Creation | T1053.005 | ✅ Tested |
| 100007 | Disable Windows Defender | T1562.001 | ⬜ Untested |
| 100008 | Stop Security Services | T1562.001 | ⬜ Untested |
| 100009 | Kerberoasting Detection (RC4) | T1558.003 | ✅ Tested |

## Progress
- [x] Deploy Wazuh SIEM
- [x] Configure Windows 11 + Sysmon
- [x] Configure Debian Linux agent
- [x] Write custom detection rules
- [x] Install Atomic Red Team
- [x] Test detections with attack simulations
- [x] Deploy Active Directory lab (GOAD)
- [ ] Integrate Shuffle SOAR

## Progress Log

### Day 3: Active Directory & Kerberoasting
* **Infrastructure:** Deployed GOAD-Light AD Lab (DC01, DC02, SRV02) on Proxmox.
* **Configuration:**
    * Corrected Audit Policy on DC02 to log `Kerberos Service Ticket Operations`.
    * Troubleshot and fixed Wazuh Agent naming conventions.
* **Attack Simulation:** Executed Kerberoasting against `sql_svc` using Impacket `GetUserSPNs.py`.
* **Detection Engineering:**
    * Identified Event ID 4769 with Ticket Encryption `0x17` (RC4).
    * Created custom Wazuh rule (ID 100009) to alert on this activity.
    * **Result:** Validated detection in Wazuh Dashboard.