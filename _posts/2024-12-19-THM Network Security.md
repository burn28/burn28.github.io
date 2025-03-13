---
title: "THM Network Security"
date: 2024-12-19 00:00:00 +0800
categories: [Try Hack Me]
tags: [THM]
---

# Passive Recon


> whois
> nslookup
> dig
> shodan
> dnsdumpster

- `whois tryhackme.com` >> Lookup WHOIS record
- `nslookup -type=A tryhackme.com` >> Lookup DNS A records
- `nslookup -type=MX tryhackme.com 1.1.1.1` >> Lookup DNS MX records at DNS server
- `nslookup -type=TXT tryhackme.com` >> Lookup DNS TXT records
- `dig tryhackme.com A` >> Lookup DNS A records
- `dig @1.1.1.1 tryhackme.com MX` >> Lookup DNS MX records at DNS server
- `dig tryhackme.com TXT` >> Lookup DNS TXT records

# Active Recon

>[!abstract] Notes

> ping
> traceroute (linux/mac), tracert (windows)
> telnet
> netcat/nc

- telnet
`telnet IP PORT`
`GET / HTTP1.1`
`host: telnet`  > enter 2 times to send it

- nc 
`nc -lvnp PORT`

## Nmap Live Host Discovery

>[!info] Subnetwork

> Network segment_ is a group of computers connected using a shared medium (switch/AP).
> 
> A _subnetwork_ is usually the equivalent of one or more network segments connected together and configured to use the same router.
> 
> The network segment refers to a physical connection, while a subnetwork refers to a logical connection

> IP subnet /16 = 255.255.0.0, around 65K hosts.
> IP subnet /24 = 255.255.255.0, arounf 250 hosts.

![Image](https://github.com/user-attachments/assets/a95b675b-7073-42e4-b5e5-a0b99966f010)

>[!bug] Nmap Host Discovery using ARP

1. When a _privileged_ user tries to scan targets on a local network (Ethernet), Nmap uses _ARP requests_. A privileged user is `root` or a user who belongs to `sudoers` and can run `sudo`.
2. When a _privileged_ user tries to scan targets outside the local network, Nmap uses ICMP echo requests, TCP ACK (Acknowledge) to port 80, TCP SYN (Synchronize) to port 443, and ICMP timestamp request.
3. When an _unprivileged_ user tries to scan targets outside the local network, Nmap resorts to a TCP 3-way handshake by sending SYN packets to ports 80 and 443.

- `nmap -PR -sn IP/24` >> ARP scan without port-scanning
- `arp-scan --localnet` / `arp-scan -l` >> ARP scan on all local IP

> `-sn` >> without port-scanning/to check live hosts

>[!bug] Nmap Host Discovery using ICMP

- `-PE` >> ICMP Echo
- `-PP` >> ICMP Timestamp
- `-PM` >> ICMP Address Mask

>[!bug] Nmap Host Discovery Using TCP and UDP

> Send a SYN packet, open port reply with SYN/ACK. Closed port reply with RST.

- `-PS` >>TCP SYN ping (default port 80)
- `-PA` >> TCP ACK ping (live return RST)
- `-PU` >> UDP ping (close UDP return error indicate the host is up)

>[!warning] Masscan uses a similar approach but MORE AGGRESSIVE

![Image](https://github.com/user-attachments/assets/bb16b8c5-7c46-4543-9945-a13ab7d412e0)