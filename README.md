# Suricata Network Intrusion Detection Lab

Lab 2 of the Intrusion Detection course (SUP'COM, M2 Operational Cybersecurity, 2026/2027): installing Suricata, testing built-in Emerging Threats signatures, and writing and validating custom detection rules.

## Environment

| Item | Value |
|---|---|
| Hypervisor | VirtualBox |
| Sensor OS | Kali Linux 2025.4 (the lab is written for Ubuntu 22.04) |
| Suricata | 8.0.7, installed from apt |
| Ruleset | Emerging Threats Open via `suricata-update` (69,251 rules) |
| Monitored interface | `eth0` |
| Tools | Wireshark, tcpreplay, hping3, curl |

## Custom rules

All rules are in [`custom.rules`](custom.rules).

| SID | Detects | Tested with | Result |
|---|---|---|---|
| 1000001 | Incoming ICMP echo reply | `ping 8.8.8.8` | Alert |
| 1000002 | Possible ICMP flood (more than 20 echo requests per second from one source) | `ping -i 0.01 -c 50 8.8.8.8` | Alert (fired twice, see report) |
| 1000003 | PDF file transfer (`%PDF-` magic number) | `with_pdf.pcap` replayed with tcpreplay | Alert |
| 1000007 | PDF with embedded JavaScript (`file.data`, `/JavaScript`) | Benign JavaScript PDF served over HTTP | Alert |
| 1000011 | EXE transfer (MZ header plus DOS stub string) | PE test sample over HTTP | Alert |
| 1000009 | Visa card number in clear text over SMTP (PCRE on `smtp.body`) | `email_cc2.pcap` | Alert on 2 of the 3 numbers in the email (the Mastercard-style number is not matched, as expected) |
| 1000010 | Suspicious PayPal domain in a DNS query | `phishingattack.pcap` | Alert |

## Built-in signatures tested

- SID 2100498: root-level compromise (`uid=0(root)` in a response)
- SID 2008983: malware User-Agent (BlackSun), including a test showing that the position-anchored match is easy to evade
- SID 2400000 range: Spamhaus DROP, with the `threshold` keyword limiting alert volume during a spoofed SYN flood

## Running the rules

1. Copy `custom.rules` to `/var/lib/suricata/rules/`.
2. Add it under `rule-files` in `/etc/suricata/suricata.yaml`, and set the interface in the `af-packet` section.
3. Test the configuration: `sudo suricata -c /etc/suricata/suricata.yaml -T -v`
4. Run Suricata: `sudo suricata -c /etc/suricata/suricata.yaml -v -i eth0`
5. Watch alerts: `tail -f /var/log/suricata/fast.log`
6. Replay a capture: `sudo tcpreplay -i eth0 <file>.pcap`

## Limitations (discussed in the report)

Signature-based detection is limited by encryption, evasion (fragmentation, encoding, header changes), false positives and threshold tuning. The report covers these for each rule and suggests complementing Suricata with anomaly detection, file extraction and SIEM correlation.

## Report

The full write-up with screenshots is in [`report/`](report/).
