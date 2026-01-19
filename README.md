# Detection Lab Journey

My cybersecurity homelab documenting my path to Detection Engineer.

## Lab Setup (January 2026)
- **Hypervisor:** Proxmox on Dell R720
- **SIEM:** Wazuh v4.14.2
- **Target Systems:** 
  - Windows 11 with Sysmon (Custom Configuration from SwiftOnSecurity)
  - Debian Linux

## Detection Rules

| Rule ID | Name | MITRE ATT&CK | Status |
|---------|------|--------------|--------|
| 100001 | Mimikatz Detection (filename) | T1003 | ✅ Tested |
| 100002 | Mimikatz Detection (cmdline) | T1003 | ✅ Tested |

## Progress
- [x] Deploy Wazuh SIEM
- [x] Configure Windows 11 + Sysmon
- [x] Configure Debian Linux agent
- [x] Write first custom detection rule
- [ ] Deploy Active Directory lab (GOAD)
- [ ] Integrate Shuffle SOAR