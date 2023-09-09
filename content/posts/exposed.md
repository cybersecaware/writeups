---
title: "THM | Expose | Easy"
date: 2023-09-06T21:10:39+01:00
draft: false
cover:
    image: "img/expose/Expose.png"
    alt: "Expose"
    caption: "Expose"
tags: ["THM","Easy","SQL Injection","PHP Shell","SQLMap"]
categories: ["SQL Injection","Bad Passwords","Linux"]
weight: 1
---

### This post is a walkthrough of the Try Hack Me room [Expose](https://tryhackme.com/room/expose){style="text-align: center;"}

---

## Intro{style="text-align: center;"}
---
This challenge is an initial test to evaluate your capabilities in red teaming skills. 
You will find all the necessary tools to complete the challenge, like Nmap, sqlmap, wordlists, PHP shell, and many more in the AttackBox.

Exposing unnecessary services in a machine can be dangerous. Can you capture the flags and pwn the machine?

---

### NMAP Scan

```sh
 sudo nmap -sVC -T4 -p- -vv -oA nmap/all-tcp-ports 10.10.191.114
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-05 19:41 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:41
Completed NSE at 19:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:41
Completed NSE at 19:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:41
Completed NSE at 19:41, 0.00s elapsed
Initiating Ping Scan at 19:41
Scanning 10.10.191.114 [4 ports]
Completed Ping Scan at 19:41, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:41
Completed Parallel DNS resolution of 1 host. at 19:41, 0.01s elapsed
Initiating SYN Stealth Scan at 19:41
Scanning 10.10.191.114 [65535 ports]
Discovered open port 21/tcp on 10.10.191.114
Discovered open port 22/tcp on 10.10.191.114
Discovered open port 53/tcp on 10.10.191.114
Discovered open port 1883/tcp on 10.10.191.114
Discovered open port 1337/tcp on 10.10.191.114
Completed SYN Stealth Scan at 19:41, 12.23s elapsed (65535 total ports)
Initiating Service scan at 19:41
Scanning 5 services on 10.10.191.114
Completed Service scan at 19:41, 11.11s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.191.114.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:41
NSE: [ftp-bounce 10.10.191.114:21] PORT response: 500 Illegal PORT command.
Completed NSE at 19:42, 10.16s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.09s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.01s elapsed
Nmap scan report for 10.10.191.114
Host is up, received reset ttl 63 (0.051s latency).
Scanned at 2023-09-05 19:41:30 IST for 34s
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE                 REASON         VERSION
21/tcp   open  ftp                     syn-ack ttl 63 vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.0.200
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh                     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bc:ad:ba:9e:00:c2:bb:94:46:71:6d:eb:9c:6c:8b:de (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDW3b7bXXFhyAEJBjKekBQTRTlKLsL11XjqxcEdYnJZPA9MKD/M2rl8eTW4cBV+p8ktcZulk2BYUWfJpVMxkjLtUBZ5mvI9K89v0Uv01On5dVZitRBJMDMRCLRrlcMvbN5Nr/wizTL970/kxlpL6ya26lkHnXeoclrWj5F5LLZFo/510ZNE1TW9Cwb5+IrzhcdykB7iab3gPWi0Vr3WjelifDCyiOoItMgptg9gILJEoetkZfkR5Zs4ICqYgYoRc32BynnGGTp3mtbOO279RJ3U2y2NTcXtMG4GJl2yEmJAnsoq2y6mosXivbbwAvBZTZbMjXQqBtfkonJr2A/7ieXpwpcqU6eFVs17MjMeJJAE/vegRxj7nDBBobTqF4U/HrNu8nR9pYrrj92XsCu/iv+WxesKJrVIDAdiQDDY9ma6g+1BVThkCZb/Mwe8Z49zgCPcuVef/mpCpE2r0g5UiqXey+agJXsY+oNkDmkDBdd2r5KSh4b48lE3l1bRqjjt490=
|   256 3c:0c:11:2f:96:05:ad:08:c6:dd:6e:20:08:b6:71:25 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNe4/l3KTGE7PJc7QH6ImgyMbg82kppYvZJByUaE2opJQ/XV93WScr6SzhcXqG/WrXvHfz4LtHzCxeujJTPyMys=
|   256 66:4c:8e:11:31:8c:fb:3a:e1:69:38:ae:d5:d1:5f:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF2LEEUfDOIGeJBrF3AEOuhqYEnTj+n4/FcYGlAMV92f
53/tcp   open  domain                  syn-ack ttl 63 ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
1337/tcp open  http                    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: EXPOSED
|_http-server-header: Apache/2.4.41 (Ubuntu)
1883/tcp open  mosquitto version 1.6.9 syn-ack ttl 63
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     $SYS/broker/load/publish/received/5min: 0.00
|     $SYS/broker/load/publish/dropped/1min: 0.00
|     $SYS/broker/messages/stored: 53
|     $SYS/broker/load/bytes/sent/15min: 136.90
|     $SYS/broker/heap/maximum: 54584
|     $SYS/broker/publish/messages/dropped: 0
|     $SYS/broker/load/bytes/received/1min: 63.04
|     $SYS/broker/load/connections/5min: 0.39
|     $SYS/broker/bytes/sent: 2066
|     $SYS/broker/load/publish/received/1min: 0.00
|     $SYS/broker/store/messages/count: 53
|     $SYS/broker/clients/connected: 1
|     $SYS/broker/publish/bytes/received: 0
|     $SYS/broker/load/publish/sent/5min: 10.21
|     $SYS/broker/load/publish/dropped/15min: 0.00
|     $SYS/broker/bytes/received: 69
|     $SYS/broker/load/connections/15min: 0.13
|     $SYS/broker/load/sockets/5min: 0.39
|     $SYS/broker/clients/inactive: 0
|     $SYS/broker/clients/disconnected: 0
|     $SYS/broker/load/publish/dropped/5min: 0.00
|     $SYS/broker/load/bytes/sent/5min: 405.72
|     $SYS/broker/load/publish/sent/15min: 3.45
|     $SYS/broker/clients/expired: 0
|     $SYS/broker/shared_subscriptions/count: 0
|     $SYS/broker/clients/maximum: 1
|     $SYS/broker/load/messages/sent/1min: 50.25
|     $SYS/broker/version: mosquitto version 1.6.9
|     $SYS/broker/load/bytes/sent/1min: 1887.68
|     $SYS/broker/uptime: 44 seconds
|     $SYS/broker/load/messages/sent/5min: 10.80
|     $SYS/broker/subscriptions/count: 2
|     $SYS/broker/store/messages/bytes: 191
|     $SYS/broker/retained messages/count: 53
|     $SYS/broker/load/bytes/received/5min: 13.55
|     $SYS/broker/load/publish/sent/1min: 47.51
|     $SYS/broker/heap/current: 54184
|     $SYS/broker/clients/active: 1
|     $SYS/broker/load/sockets/15min: 0.13
|     $SYS/broker/clients/total: 1
|     $SYS/broker/publish/messages/sent: 52
|     $SYS/broker/load/publish/received/15min: 0.00
|     $SYS/broker/load/messages/sent/15min: 3.64
|     $SYS/broker/publish/messages/received: 0
|     $SYS/broker/publish/bytes/sent: 177
|     $SYS/broker/load/bytes/received/15min: 4.57
|     $SYS/broker/messages/sent: 55
|     $SYS/broker/load/messages/received/1min: 2.74
|     $SYS/broker/messages/received: 3
|     $SYS/broker/load/sockets/1min: 1.67
|     $SYS/broker/load/messages/received/5min: 0.59
|     $SYS/broker/load/messages/received/15min: 0.20
|_    $SYS/broker/load/connections/1min: 1.83
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.42 seconds
```
### Ports Of Interest

Port 21 - FTP (vsftpd 2.0.8 or later)
Port 22 - SSH
Port 80 - Http
Port 1883: mosquito

Starting port 21 we will check for anonymous access.

![Anonymous FTP](/img/expose/ftp_login.png#center "Anonymouse Access Allowed")

Anonymous access is allowed but we do not have permissions to upload anything nor is there anything of interest in the folder.

![No Permissons](/img/expose/ftp_perms.png#center "No Upload Permissions")

### Port 1883 - Rabbit Hole

I could find anything to exploit and deemed this as a rabbit hole and continued on.

![Rabbit Hole](/img/expose/rabbit_hole.png#center "Nothing To Exploit")

### Port 1337 - Feroxbuster

After running a directory fuzzer Feroxbuster with wordlist '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt' we see alot of phpmyadmin but amongst this large output we can spot 'admin_101'.  This can be seen near the bottom of the scanned output.

```sh
feroxbuster -u http://exposed:1337 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

![Feroxbuster](/img/expose/ferox_admin101.png#center "Feroxbuster Findings")

Browsing to http://expose:1337/admin_101, we are presented with a login page. In the username field we have a user pre-populated, so all we need now is the password.

![Admin 101 Login](/img/expose/admin101_login.png#center "Admin Login Page")

Trying default passwords such password, P@sw0rd123, etc didn't work, so  we can try SQL Injections.

Entering hacker@root.thm' and a random password gives us this.

![Undefined Error](/img/expose/login_error.png#center "Undefined Error")

This could indeed be an SQL error, so we will fire up Burpsuite and intercept the request for SQLMap.

Save this to a file called login.req and we will use this with SQLMap.

```html
POST /admin_101/includes/user_login.php HTTP/1.1
Host: exposed:1337
Content-Length: 37
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://exposed:1337
Referer: http://exposed:1337/admin_101/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=5de2kh614i7e3345m3f3sbofln
Connection: close

email=hacker%40root.thm&password=pass
```

![Login Request](/img/expose/login_req.png#center "Save Login Request For SQLMAP")

### SQLMap

```sh
sqlmap -r login.req --dump
Y
Y
```
Let 'sqlmap' do it's thing and eventually you will see the credentials for the user hacker@root.thm.  Take note of the password, so we can use it to login.

![Creds Found](/img/expose/hacker_passwd.png#center "Hacker Password Found")

These credentials work and we get redirected to `chat.php` where there is nothing we can manipulate.

![Chat Page](/img/expose/chat.png#center "Chat Page after Login")

Looking back at SQLMap I saw it was asking "recognized possible password hashes in column 'password do you want to crack them', say yes to this and we discover another webpage link and a password.

Webpage:  http://exposed:1337/file1010111/index.php and also /upload-cv00101011/index.php but this is "ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z"

![More Credentials](/img/expose/easy_pwd.png#center "More Creds Found")

Browse to http://exposed:1337/file1010111/index.php 

![Submit Password](/img/expose/file_enterpwd.png#center "Submit New Creds Found")

After submitting the new credentials we found we now have the following message.

![Fuzzing Message](/img/expose/fuzz_msg.png#center "New Mesage")

Viewing the source page gives us the following hint:

![Source Code](/img/expose/page_source.png#center "View Page Source Code")

The hint mentions file and get, which means using a Get request and a file parameter we should possibly have a Local File Inclusion vulnerability.

`?file=index.php` This is a query string. It's used to pass data to the server as key-value pairs. In this case, it's specifying that the parameter file has the value index.php

Knowing this now we modify our request in Burpsuite to the following to read a file we know exists that is `index.php`

Enter this into your browser: `http://exposed:1337/file1010111/index.php?file=index.php` and hit enter.  The page looks strange now and not the same as before and shows there is a LFI vulnerability here.

![LFI](/img/expose/lfi.png#center "LFI Confirmed")

Let's try read the `/etc/passwd` file...This too works!

![Reading Passwd](/img/expose/passwd_lfi.png#center "Contents of passwd Through LFI")

To view the results in a better format just switch view the page source code.

![Better View](/img/expose/passwd_lfi_source.png#center "Viewed Better in Source Code")

There happens to be a username in the `/etc/passwd` file that has a starting letter 'Z' which is what we are looking for. Remember the message we saw in `sqlmap`, 'ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z'

Browsing to http://exposed:1337/file1010111/index.php now this same message is displayed on the page. Now we know the username is 'zeamhish' and we have the password that we told `sqlmap` to crack. Enter the password to continue.

![Upload Page](/img/expose/upload_page.png#center "Upload Page")

If you click 'Browse' for a file to upload you can see in the bottom right the file is set for .png, so we will upload a png first to see how the page behaves. Using a png file displays a file uploaded succesfully message. 

![Upload With PNG](/img/expose/upload_success.png#center "Upload Success Message")

Okay, but where did it upload to? Viewing the source code once more reveals the answer.

![Upload Source Code](/img/expose/upload_hint.png#center "Source Code Hint")

The uploads end up in the folder `upload_thm_1001`. Confirming this by browsing to this url: `http://exposed:1337/upload-cv00101011/upload_thm_1001/`

And our file is there. Now we need to bypass the png,jpg file restriction.

Source code for this check reveals either jpg or png files will be accepted. To see what the code looks like we can view the source code for the file upload page to see it.

![Upload Source Code](/img/expose/upload_code.png#center "Upload Source Code Routine")

### Bypass File Upload

Use `php-reverse-shell.php` reverse shell code and rename it to `rshell.php.png`. Upload this and intercept with Burpsuite.

![Burp Upload Intercept](/img/expose/burp_upload.png#center "Upload Burp Intercept")

In the request you will see `filename="rshell.php.png"`, remove the png from the end and forward the request to bypass the upload restriction.  Browse to url: `http://exposed:1337/upload-cv00101011/upload_thm_1001/` to verify our `rshell.php` was uploaded.

![Shell Uploaded](/img/expose/confirm_shell_upload.png#center "Shell Successfully Uploaded")

### Getting Our Foothold

Start your reverse shell (pwncat-cs)

![Pwncat-CS](/img/expose/pwncat.png#center "Pwncat-CS Listening")

Click the uploaded `rshell.php` file to get a reverse shell on our attacker pc.

We land in the root of the box.  Change directory to /home/zeamkish and list the folder contents.

I tried to read the flag.txt but got permission denied, but we have read permissions on `ssh_creds.txt`

![Shell Working Dir](/img/expose/shell_cwd.png#center "Current Working Dir After Shell Connection.")

View the `ssh_creds.txt` to get the ssh credentials for user Zeamkish. Now we should SSH in as Zeamkish to proceed to have a more stable shell.

### Manual Enumeration

Checking sudo -l has nothing set, check for SUID binaries.

```sh
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```
We find two that stand out nano, and find.

![SUID Binaries](/img/expose/suid_bins.png#center "SUID Binaries Found")

Both nano and find will allow us to acheive root access but nano will allow for give ourselves full root access.  I will show both methods here.

###  Root with Nano

Since the suid bit is set on nano we can directly edit the sudoers file and give our use Zeamkish full root permissions to everything.  Run `/usr/bin/nano /etc/sudoers` and add the following line:  `zeamkish ALL=(ALL:ALL) ALL`, you can put this below the root user the same as below.

![Edit Sudoers](/img/expose/sudoers.png#center "Edited Sudoers File")

Now all you have to do is run `sudo bash` and enter Zeamkish's password and you now are root. Grab the root.txt flag and submit to complete the room.

![Root Flag](/img/expose/root_flag.png#center "Root Flag")

### Root with Find

Method taken from GTFO bins

```sh
zeamkish@ip-10-10-30-76:~$ /usr/bin/find . -exec /bin/sh -p \; -quit
# id
uid=1001(zeamkish) gid=1001(zeamkish) euid=0(root) groups=1001(zeamkish)

# cat /root/flag.txt
FLAG
```

### _EUID Explained By Chat GPT_

The `euid` stands for effective user ID. It is one of the user IDs associated with a process in Unix-like operating systems. 

Here's a breakdown:

- **Real User ID (`uid`)**: This is the actual user who launched the process.

- **Effective User ID (`euid`)**: This is used to determine the permissions the process has while running. It can be temporarily changed, which can be useful for processes that need to perform certain tasks with elevated privileges without granting those privileges permanently.

- **Saved Set User ID (`suid`)**: This is used to preserve the original effective user ID when it's temporarily changed.

So, what does this mean practically?

If a process has an `euid` of 0 (which is typically reserved for the superuser or root), it means that process can perform operations that are typically restricted to the superuser, such as:

1. **Modify System Files**: This includes system configuration files, logs, and other critical parts of the operating system.

2. **Manage System Services**: It can start, stop, and restart system services.

3. **Access Protected Resources**: It can access files and directories that are otherwise restricted to regular users.

4. **Change User IDs**: It can change its own `uid` and `euid` to any other user.

However, even if a process temporarily sets its `euid` to 0, it doesn't grant all privileges that a normal root user has. For example, it can't:

1. **Bypass Security Mechanisms**: Processes with `euid` 0 are still subject to access control mechanisms and other security policies.

2. **Modify Kernel Data**: Some operations, like directly modifying kernel memory, are typically restricted to the kernel itself.

3. **Modify Other Users' Files**: It can't modify files owned by other users unless those files have been explicitly configured to allow it.

4. **Bypass System Logs**: Audit logs and other monitoring mechanisms still track the actions of a process with `euid` 0.

**In summary, while a process with an `euid` of 0 has elevated privileges, it is still subject to various security measures and doesn't have all the rights and powers of the true superuser.**

---





