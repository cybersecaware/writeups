---
title: "THM | Crylo | Medium"
date: 2023-08-13T22:50:40+01:00
draft: false
cover:
    image: "img/crylo/Crylo.png"
    alt: "Crylo"
    caption: "Crylo"
tags: ["THM","Medium","Linux","SQL Injection","RCE","Password Encryption","Password Decryption","AES Encryption","Crypto_JS"]
categories: ["SQL","AES","Crypto_JS"]
weight: 1
---

### This post is a walkthrough of the Try Hack Me room [Crylo](https://tryhackme.com/room/crylo4a){style="text-align: center;"}

---

## Intro{style="text-align: center;"}
---

Welcome to Crylo.

Crylo is an engaging room on TryHackMe that focuses on teaching two interesting topics: SQL Injection and bypassing Two-Factor Authentication (2FA) through exploiting the Crypto JS library. Through these concepts, participants learn how to overcome security challenges. In the Crylo room, you'll explore techniques to go beyond just local connections and achieve command injection on a web application. This allows you to gain access to the server. Once you have access, you can uncover the sudo user's password by utilizing the same AES encryption system that the server is employing. This room offers a hands-on and practical learning experience in the realm of cybersecurity.

---

### NMAP Recon Scan

```sh
 sudo nmap -sVC -T4 -oA nmap/tcp-ports 10.10.44.143
 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 13:01 IST
Nmap scan report for 10.10.44.143
Host is up (0.0083s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:7e:08:42:ea:bf:be:1a:1b:78:b0:f7:99:3c:ca:1d (RSA)
|   256 f8:f3:90:83:b1:bc:87:e8:93:a0:ff:d5:bc:1f:d7:e1 (ECDSA)
|_  256 b6:77:4d:a6:6d:73:79:15:ea:39:0c:f6:1b:b4:0b:6c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Spicyo
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds
```

### Ports of Interest

Port 22(OpenSSH)
Port 80(Http on NGINX/1.18.0)

We can ignore port 22 for now as we do not have any credentials to use. Continue by browsing to port 80 where we are presented with a website for Spicyco.

![Main Webpage](/img/crylo/webpage.png "Main Webpage")

Notice there is a Login button on the top right that we will need to dig deeper into! First we should run a directory enumeration scan. I used Gobuster to complete this scan.

### Gobuster Directory Enumeration

```sh
gobuster dir -u http://10.10.44.143 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
![Directory Enumeration](/img/crylo/gobuster.png "Directories Found")

The login page we saw before shows up and also we can see a debug directory that might be worth looking.

![Debug Forbidden](/img/crylo/for_debug.png "Forbidden Access to Debug Dir")

Okay nothing of interest here for now as we don't have any credentials for the site yet.
Let's take a look at the Login page now and try some default credentials or SQL Injection.

![Login Page](/img/crylo/login.png "Login Page")

You should try some default username password combinations to see if we get lucky, but unfortunately this would be too easy. 

![Invalid Login](/img/crylo/invalid_login.png "Username or Password is invalid")

Moving onto some SQL Injection I tried inputting the username `admin' or 1=1--` while viewing the web developers console in chrome and saw a 500 (internal server error), which leads me to believe there is a possible injection point here.

![SQL Injection](/img/crylo/sql_inject.png "Possible Injection Point!")

Use Burpsuite to capture the login request then save this to a file called `login.req`. This will be used with SQLMap next.

### SQL Injection

I ran the following arguments with SQLMap. The argument `--batch` will tell SQLMap to auto select answers and not wait for us to answer.

```sh
sqlmap -r login.req --risk=3 --level=3 --dump --batch
```
SQLMap Identifies the following.

```text
Server: Ubuntu
Web Application: Nginx 1.18.0 as seen from our nmap scan earlier.
Database Back-end: MySQL: 5.0.12
Database: Food
```
![SQL Tables](/img/crylo/sql_tables.png "Interesting Tables Identified")

SQLMap dumped the `accounts_pintokens` which reveals two user to us user admin and anof.

![Users Identified](/img/crylo/sql_users.png "Identified Two Users")

Not sure what to do with the pintokens?

In the list of tables above there is a table called `auth_user` which most likely will have a password column in it. Assuming it does proceed to try dump the password/s.

```sh
sqlmap -r login.req --dump -D food -T auth_user -C password
```
### Admin Hash

Sure enough there is a password column and SQLMap managed to dump it for us. The password is hashed and will need to be cracked to be of any use. Hashcat is our best bet at cracking this hash and we can look up the the hash name and hash-mode on hashcat's examples page https://hashcat.net/wiki/doku.php?id=example_hashes.

![Hash ID](/img/crylo/hash_id.png "Hash ID and Mode")

The mode we need to use is `10000` to crack the hash.  

![Password Cracking](/img/crylo/hashcat.png "Cracking the HASH")

Hashcat was able to crack the password and now we have logon credentials for the admin user. Proceed to login through the login page.  The password is correct but now we are being asked for a pin code i.e. a second form of authentication.

![Pin Required](/img/crylo/pin.png "A Pin is Required")

Using the web developer tools console in Chrome we can see a true or false check for the pin code. 

![Pin Set](/img/crylo/pin_set.png "Pin Set Check")

Taking a closer look in the `validation.js` script we can better understand what is happening.

![Pin Check](/img/crylo/validation.png "Closer Look at Pin Check")

If the `jsonResponse.pin_set` is true we get redirected to /2fa and asked for the pin.

If the `jsonResponse.pin_set` is false we are redirected to the /set-pin page.  If we can redirect to here we can set a pin for the admin.

On line 23 of the `validation.js` script is the first if statement, set a breakpoint here using the browsers developers tools.

![Break Point](/img/crylo/breakpoint.png "Set Breakpoint")

Using the console enter the following to set the pin_set to false.

```json
jsonResponse = {
    "pin_set": "false",
    "email": "admin@admin.com",
    "success": "true"
}
```

![Set Pin Check False](/img/crylo/pin_false.png "Change the Pin Set Check to False")

Once this has been set resume the script and you should now be prompted to set a pin number.  Keeping it simple we can just enter `1234`

![Set Pin Number](/img/crylo/set_pin.png "Set You Pin")

Now login once more and enter the pin you just set to be granted admin login access to the site.

![Hello Admin](/img/crylo/hello_admin.png "Logged in as Admin")

We are logged in now as the admin user... Now that we are admin we can try return the the debug page that was forbidden earlier.

![Debug Revisted](/img/crylo/local_only.png "Local Access Only Message")

### Forbidden (Bypass Debug Local Access)

Still forbidden and only available to local users.  We can use Burpsuite to spoof our IP address as localhost.

Original Get Request before editing.

![Original Get Request](/img/crylo/org_req.png "Original Get Request")

To bypass this restriction we can use the `X-Forwarder-For` header and add this to our get request.

___The "X-Forwarded-For" (XFF) header is not a part of the HTML request itself but is commonly used in HTTP requests as an HTTP header. 
It is used to indicate the original IP address of a client, especially when the request passes through one or more proxy servers or load balancers. 
This header provides information about the client's IP address, allowing servers further down the chain to know the actual source of the request.___

![Modified Get Request](/img/crylo/mod_req.png "Modified Get Request")

After sending the request we mange to bypass the local user check and are presented with an open port check page which is most likely vulnerable to code injection.

Let's find out, but first just enter a port to see what it does.

![Enter a Port Number](/img/crylo/port_check.png "Enter a Port Number")

We need to use Burpsuite again, so we can inject the `X-Forwarder-For` header for this to continue to work.

![Page Response](/img/crylo/port_resp.png "Page Response in BurpSuite")

### OS Command Injection

Append more commands after the port number to see if it is executed on the target.  I used `ls -las` as an example to see if I could list the current working directory.

![Inject Command](/img/crylo/os_cmd_inject.png "Command Injection")

BurpSuite does show the contents of the current working directory albeit a little hard to read.  This is enough for us to be able to try getting a reverse shell now.

### Exploitation (Establishing a Foothold)

Now we know we can execute commands on the target it's time to get our foothold.

Start pwncat-cs and listen for the bash reverse shell sent with BurpSuite.

Start Listener.
![Start Pwncat-CS](/img/crylo/pwncat_listen.png "PWNCAT-CS Waiting")

Session Established
![Session Established ](/img/crylo/pwncat_est.png "Session Established")

### Enumeration On Target

List the current working directory contents.

![List CWD Contents](/img/crylo/list_cwd.png "List Current Working Dir Contents")

Check what other users are available on the target.
![Check Users](/img/crylo/other_users.png "Check User Accounts on The Target")

Three users found root, anof and crylo the current user we are now.

The first flag can be found in Crylo's home folder. Submit to THM.

![First Flag](/img/crylo/user_flag.png "User Flag Located")

One of the room questions asked who is a member of the sudo group, so let's take a look.

List members of the sudo group

Both these commands provide the same information and are handy to know.

```sh
cat /etc/group | grep '^sudo:'
sudo:x:27:anof

getent group sudo
sudo:x:27:anof
```
![Sudo Member](/img/crylo/sudo_grp_member.png "Sudo Member")

The user Anof is a member of the sudo group and is our answer to the question.

To get root we are given a hint 'Exploit the web app to gain access to the machine and submit the flags.'

List the contents of the accounts folder.

![Accounts Folder](/img/crylo/accounts.png "Accounts Folder Contents")

Looking inside the `enc.py` file we can see the password encryption that was used to encrypt the passwords for the users.

I downloaded it locally to modify and test it.

Looking inside the python3 `enc.py` script you can see the AES encryption algorithm.

![AES Algorithm](/img/crylo/enc.png "AES Algorithm")

Run the python3 script with `python3 enc.py` and you will get the following output.

![Run Enc Script](/img/crylo/enc_output.png "Output From 'enc.py'")

Let's try reverse the AES encryption.  Save the following to 'byte_decode.py'  This just cleans up the hex representation for us, so we can enter the hex values into Cyberchef.

```python3
import binascii

byte_string1 = b'\xc9;\xd4b\xce\xc15\x19;\x00Z^Nw\xafp\x10\xce/r\x0c\xf1\x1c&\x1c\x12a\xd9&b"\xc3'
hex_representation1 = binascii.hexlify(byte_string1).decode('utf-8')

byte_string2 = b'!6\x0b\xc7Xg@\xcc\xe3KY\xcfN\x9b\x81\x91'
hex_representation2 = binascii.hexlify(byte_string2).decode('utf-8')

byte_string3 = b'\x9f\xc9P\xff\xb3Z\x94\x84\x8a\xeb1\xa2/\xba\x8d\xa5'
hex_representation3 = binascii.hexlify(byte_string3).decode('utf-8')

print("KEY: " + hex_representation1)
print("IV: " + hex_representation2)
print("ENC: " + hex_representation3)
```

Run with `python3 byte_decode.py` to clean up the hex representation.

```sh
KEY: c93bd462cec135193b005a5e4e77af7010ce2f720cf11c261c1261d9266222c3
IV: 21360bc7586740cce34b59cf4e9b8191
ENC: 9fc950ffb35a94848aeb31a22fba8da5
```
Now using Cyberchef enter the cleaned hex output in `enc` above. If this is correct we should be able to see the original data input 'toor' in the ouput text box, and we do!

![Cyberchef AES Decrypt](/img/crylo/cyberchef.png "Decrypt AES")

We successfully reversed the AES encryption in Cyberchef, so we can try decrypt Anof's base64 encoded data we found in the database earlier. But first we want to get the hex bytes of the base64 data using Cyberchef.

![Hex Bytes For B64](/img/crylo/hex_bytes.png "Get Hex Bytes of B64 Data")

### Decrypt Password For ANOF

```python3
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

key = b'\xc9;\xd4b\xce\xc15\x19;\x00Z^Nw\xafp\x10\xce/r\x0c\xf1\x1c&\x1c\x12a\xd9&b"\xc3'
iv = b'!6\x0b\xc7Xg@\xcc\xe3KY\xcfN\x9b\x81\x91'

cipher1 = AES.new(key, AES.MODE_CBC, iv)
pwd = unpad(cipher1.decrypt(b'\x54\x7e\x87\x8f\x8f\x9e\x42\x7e\x6e\x60\x65\x40\xc7\x2f\x07\xb7\xba\x64\x54\xef\x68\x78\xf5\x29\x10\xb0\xdd\x89\x71\x6a\xd5\x5d'),16)
password_text = "Password for user ANOF: " + pwd.decode('utf-8')
trophy = '\U0001F44D'
print('\n' + trophy + ' ' + password_text + '\n')
```

Run our python3 `dec.py` to get the password for user Anof.

![Decrypt Password](/img/crylo/anof_pwd.png "Decrypted Password for Anof")

Cool! 🏆 Now we have the password for user Anof and proceed to get root access and  complete the room.

### Privilege Escalate

Switch user to anof now because we already know Anof is a member of the sudo group. All we have to do is just run `sudo bash` to get a root shell.

Grab the root flag and submit.

![Priv Esc](/img/crylo/priv_esc.png "We are root!")

Room Completed! 🏆🏆

---


