# Detection Lab Journey

My cybersecurity homelab documenting my path to Detection Engineer.

## Lab Setup (January 2026)
- **Hypervisor:** Proxmox on Dell R720
- **SIEM:** Wazuh v4.14.2
- **Target Systems:**
  - Windows 11 with Sysmon (Custom Configuration from SwiftOnSecurity)
  - Debian Linux
- **Attack Simulation:** Atomic Red Team

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

## Progress
- [x] Deploy Wazuh SIEM
- [x] Configure Windows 11 + Sysmon
- [x] Configure Debian Linux agent
- [x] Write custom detection rules
- [x] Install Atomic Red Team
- [x] Test detections with attack simulations
- [ ] Deploy Active Directory lab (GOAD)
- [ ] Integrate Shuffle SOAR