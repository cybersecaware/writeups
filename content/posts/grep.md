---
title: "THM | Grep | Easy"
date: 2023-08-20T14:51:52+01:00
draft: false
cover:
    image: "img/grep/grep.png"
    alt: "Grep"
    caption: "Grep"
tags: ["THM","Easy","Linux","File Upload Bypass","MagicBytes"]
categories: ["OSINT","API","Git"]
weight: 1
---

### This post is a walkthrough of the Try Hack Me room [Grep](https://tryhackme.com/room/greprtp){style="text-align: center;"}

---

## Intro{style="text-align: center;"}
---

Welcome to the OSINT challenge, part of TryHackMe’s Red Teaming Path. In this task, you will be an ethical hacker aiming to exploit a newly developed web application.

SuperSecure Corp, a fast-paced startup, is currently creating a blogging platform inviting security professionals to assess its security. The challenge involves using OSINT techniques to gather information from publicly accessible sources and exploit potential vulnerabilities in the web application. Your goal is to identify and exploit vulnerabilities in the application using a combination of recon and OSINT skills. As you progress, you’ll look for weak points in the app, find sensitive data, and attempt to gain unauthorized access. You will leverage the skills and knowledge acquired through the Red Team Pathway to devise and execute your attack strategies.

---

### Nmap Recon

```sh
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 20:20 IST
Nmap scan report for grep.thm (10.10.72.75)
Host is up (0.0093s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0d:48:28:0f:2f:8e:b2:d9:03:7e:1e:b9:11:91:46:59 (RSA)
|   256 73:fd:4c:34:0f:90:40:e7:e7:63:39:3a:14:cf:1e:63 (ECDSA)
|_  256 eb:68:63:1c:8c:58:21:a9:3a:66:07:fc:36:c6:06:4e (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp   open  ssl/http Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=grep.thm/organizationName=SearchME/stateOrProvinceName=Some-State/countryName=US
| Not valid before: 2023-06-14T13:03:09
|_Not valid after:  2024-06-13T13:03:09
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Welcome
|_Requested resource was /public/html/
51337/tcp open  http     Apache httpd 2.4.41
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: ip-10-10-72-75.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.28 seconds
```

### Ports of Interest

* Port 80 (Http)
* Port 443 (Https)
* Port 51337 (Https)

The nmap output shows us an SSL certificate has been applied to port 443 (https) and the  common name is `grep.thm`. Add this to your `/etc/hosts`.  This will be important if virtual hosts are configured and just entering the IP address would not show us a web page.

### Port 80

Port 80 Default is just the default Apache2 Home Page which has no secrets in the web page source code nor any robots.txt.  This would be flagged as Information Disclosure is an actual webapp pentest. Take note and carry on.

### Port 443

Port 443 brings us to a main page with a title 'Welcome to SearchME'. Below this there it says **"This website is under development".** In the upper right side of page you will see links for Login & Register.

![Welcome Page](/img/grep/port_443.png "Welcome Page For SearchME")

It may not be apparent right away but the message on the page is a hint, if you think about it most developers will use GitHub for web-based version control, collaboration, and code management, allowing individuals and teams to work together on software development projects. The search me is telling us to do some "OSINT", which is also mentioned in the room intro. We don't have enough recon done to search through GitHub yet.

### Register

Register an account and capture with Burpsuite.

![Register](/img/grep/register_details.png "Register an account")

On clicking register a message is displayed saying 'Invalid or expired API Key', okay another road block. 

![Invalid API Key](/img/grep/invalid_api.png "Invalid APi Key Message")

Taking a look into the source code you can see a hard coded api key that looks like a hash of some kind.

![Register JS Source](/img/grep/reg_source.png "Stored API Key")

Running this through `hashid` it outputs the most likely hashes first to we can start with the top results.

![Hash ID](/img/grep/hash_id.png "Most Likely MD5")

### Cracking the MD5 API KEY

I used `hashcat` to crack the hash with the 'rockyou.txt' password list.

![Hashcat MD5 Crack](/img/grep/crack_md5.png "Cracked MD5 Hash")

Cracking this has does nothing for us as we already know the API key is invalid, but it is good to know in case we find a valid API key. Note you can submit the md5 hash to https://crackstation.net/ and it will show you the password too.

![Crackstation](/img/grep/cs_pwd.png "Crackstation Hash Submission")

In the previous source code the path /api can be seen and we should do some directory enumeration here to see if it yields anything juicy. I chose to use Feroxbuster for this task. I scanned `https://grep.thm/` and `https://grep.thm/api/`

### Directory Enumeration

```sh
feroxbuster -k -u https://grep.thm/api/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -r -x txt,php,bak,api,html
```
**First Scan**
![First Scan](/img/grep/uploads_url.png "URLS Found")

**Second Scan** 
![Dir Enum on API](/img/grep/ferox_api.png "Directory Enumeration")

Looking through the output of Feroxbuster we can see the site folder structure and this should be enough to help us search GitHub with.  Keywords to use would be `searchme` and `searchmecms`. Interesting files folders to look at would be the `register.php` and `uploads.php`. The `uploads.php` is most likely an upload form that we can't access yet and the uploads folder is where we can expect our uploaded files to reside.

Confirming the above assumption.

![Uploads Message](/img/grep/upload_php.png "Cannot Access Uploads Yet")

Captured with BurpSuite

![Upload Burp Capture](/img/grep/upload_php_burp.png "Uploads Capture With BurpSuite")

Viewing https://grep.thm/api/uploads/ where our uploaded files would be shown.

![Uploads Folder](/img/grep/upload_folder.png "Uploads Folder Empty")

Currently the folder is empty.  This should be flagged as 'Directory Traversal' in a report too.

### OSINT

Searching GitHub with `searchcms` found the following: https://github.com/supersecuredeveloper/searchmecms

![Search GitHub](/img/grep/searchcms_git.png "Searching GitHub")

Looking at the date which only May 29 it is a good bet this is what we are looking for. Digging into the repo we can see a big clue that this is indeed what we are looking for!
There is an API folder and when clicking into this folder there is a git commit comment saying "Fix: remove key".

![GitHub API Folder](/img/grep/git_folders.png "GitHub API Folder")

![Git Comment](/img/grep/key_removed.png "Git Comment")

View the `register.php` and compare it to our site code.  The code has the same invalid message and also the same API name.

![Register PHP](/img/grep/register_git.png "Source Is Similar")

### Finding the correct API Key

The last commit removed the key, so we will need to view previous commit and get the API key. Go back and view the commit history.

![Git Commit](/img/grep/git_commit.png "Viewing Previous Git Commit")

As we can see the API Key is present in a previous commit and we can take note of this. Not required but we can submit the MD5 to Crackstation to see if it is in the database and it is. At least this confirms the GitHub code is the same as the grep.thm site.

![Valid API](/img/grep/api_cracked.png "Found in Crackstation's Database")

### Valid Registration

Now we have a the API key we can register once more and capture the request with Burp, then insert our GitHub APi key to see if it works, and it does.

![Register With New API Key](/img/grep/valid_api_reg.png "Inject Found API Key")

**Successful Registration Message**

![Registration Successful](/img/grep/reg_success.png "Successful Registration Message")

Login now as with the registered user account and you will be presented with a dashboard containing our first flag and a couple of test posts by a user admin. This let's us know there is an admin account we need to elevate to.

![Logged in Dashboard](/img/grep/login.png "Logged in Dashboard")

Now we are logged in we should return to the uploads page now to see if it is available to us. We use https://grep.thm/public/html/upload.php and sure enough we can access an upload page. 

![Upload Page](/img/grep/upload_page.png "Upload Page")

Since we found the GitHub repo the source code for the 'upload.php' is available to us to view to see what validations are implemented.

![Upload Source Code](/img/grep/upload_source.png "GitHub Upload Source Code")

Test uploading a `php-reverse-shell.php` file to see the file check error message.

![Upload Error](/img/grep/upload_error.png "Upload Error Message")

**Screenshot from BurpSuite**

![Burp Upload Error](/img/grep/upload_error_burp.png "Burp Upload Error")

**Confirming file upload with valid png image.**

![Upload Test File](/img/grep/upload_test_file.png "Uploading a Valid Image File")

The test image 'Hacked.png' file get uploaded to the uploads folder as we suspected earlier.

![Valid Image Upload](/img/grep/valid_success.png "Uploading a Valid Image File")

### Bypassing File Validation

From the source we know the file's magic bytes are checked, so what we need to de is inject valid magic bytes for any of the files that are allowed to be uploaded. Luckily the source code let's us know what types and provides the magic byte headers for us. Using `php-reverse-shell.php` as the reverse shell we want to upload, open it in a text editor and on the top line just type 4 A's `AAAA`, which is for bytes that we will overwrite with the magic bytes of png image.

Run the `file` command the following on the `php-reverse-shell.php` before modifying and the output will be `php-reverse-shell.php: ASCII text`

![Before Modification](/img/grep/before_magic.png "Before MagicBytes Modification")

Now open `php-reverse-shell.php` with `hexeditor` and overwrite the four 41 bytes(A's) that we added with the magicbytes `89 50 4E 47` for the png file format.

![After Magic Byte](/img/grep/after_magic.png "Injected Magic Bytes")

Now upload the modified php shell code to see if it now bypasses the file check validation routine.  It does and the file is located in the uploads folder along with the test 'hacked.png' image.

![Upload Shell](/img/grep/shell_upload.png "Shell Upload Bypassed")

**PHP Shell Script in the uploads folder.**

![Confirmed Upload](/img/grep/shell_upload_confirmed.png "PHP Shell File Uploaded to the Uploads Folder")

### Foothold

Start your reverse listener and then click the `php-reverse-shell.php` file to establish the reverse shell to your attack box.

![PWNCAT Listener](/img/grep/pwncat.png "Pwncat-CS Listener Connected")

The reverse shell was established and now we do some manual enumeration on the box. We land in `/` so change your directory to `/var/www/`.  

![WWW Folder Contents](/img/grep/www_folder.png "Contents of WWW Folder")

What should stand out immediately is the 'Backups' folder, so cd into this and list the contents. Inside is a file called 'users.sql', which on inspection reveals the hashed password for admin and also the email address for the admin user.

![SQL Users Content](/img/grep/sql_users.png "Snippet of the 'users.sql' file")

**Identifying the Hash**

Use `hashid` to identify the hash found.

![ID Hash](/img/grep/id_hash.png "Identify the Admin Hash")

The hash is bcrypt and I gave cracking it a go with hashcat but it was going to take nearly a day with my GPU, so I looked back at the nmap scan and noticed we didn't look into the port 51337(https) yet.  This may reveal another path?

### Port 51337

Browsing to https://grep.thm:51337 didn't reveal much and I was a bit stuck here but then thought to check the SSL certificate information and low and behold we find the hostname 'leakchecker.grep.thm'.  Add this to our `/etc/hosts` and browse to `https://redacted.grep.thm:51337`.

![SSL Cert Info](/img/grep/cert_info.png "Hostname Found in SSL Cert")

This page says 'Email Leak Checker'.  This must be looking up leaked credentials form somewhere and letting the user know if their credentials are found in the database.  The only email we have besides the fake one we entered that looks valid is the admin users email.  Enter the admin email address and click submit and you will be shown the credentials for the admin account.  You can test the credentials by logging in with the admin account.  That's it... no privesc to root required. You have all answers to the questions asked for the room now.

**Room Completed!** 🏆🏆

---
















