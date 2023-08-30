---
title: "THM | Lesson Learned | Easy"
date: 2023-08-29T19:03:46+01:00
draft: false
cover:
    image: "img/lesson-learned/lesson-learned.png"
    alt: "Lesson Learned"
    caption: "Lesson Learned"
tags: ["THM","Easy","SQL Injection","Hydra"]
categories: ["OWASP Authentication","SQL Injection","Bad Practice","Brute Force"]
weight: 1
---

### This post is a walkthrough of the Try Hack Me room [Grep](https://tryhackme.com/room/lessonlearned){style="text-align: center;"}

---

## Intro{style="text-align: center;"}
---
This is a relatively easy machine that tries to teach you a lesson, but perhaps you've already learned the lesson? Let's find out.
Treat this box as if it were a real target and not a CTF.
Get past the login screen and you will find the flag. There are no rabbit holes, no hidden files, just a login page and a flag. Good luck!

Tib3rius has since streamed the walkthrough of this room and can be found here: https://www.twitch.tv/videos/1911007226

---

Since the author of the room is telling us there is just a login page and a flag, there will be no recon required for this room. There will just be a webpage with a login to bypass.

### Bypassing The Login Page.

As usual we should always start with som manual guess work and try default credentials such as `admin:admin`, `admin:password` etc...

![Login Box](/img/lesson-learned/login.png#center "Login Page")

Trying incorrect credentials will give a message telling us "Invalid username and password" were provided.  This message can be used to validate actual usernames and should be considered a vulnerability according to OWASPs Top 10 Failures. Ref: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/.  By brute forcing username we should be able to find valid usernames. Before trying to brute force usernames we can also try some SQL Injection Techniques. Using the following resource https://book.hacktricks.xyz/pentesting-web/sql-injection. 

### What is SQL Injection

![SQL Injection](/img/lesson-learned/sql_info.png#center "SQL Info From HackTricks")

Trying one of the most common SQL Injections techniques such as `admin' OR 1=1-- -` we get message telling us what we have done wrong and a note telling us there must be a better way.

![SQL OR](/img/lesson-learned/sql_or.png#center "SQL Injection OR")

The SQL query would look like the image below.  The modified query will delete everything in the flags table, which is obviously a bad thing if this were a production environment or live engagement.

![Explained](/img/lesson-learned/explain_sql.png#center "Explaining the Query")

An unintended method to bypass the login would be to use the UNION command i.e. `'UNION SELECT 1 -- -`.  This also works because when it comes to the delete command in the image above the union command is invalid and not executed. This will bypass the login and you will get the flag but we will carry on as intended.

### Oops!

![OPPs](/img/lesson-learned/opps.png#center "OPPs Message")

### Lesson Learned

After injecting the `OR 1=1` we need to restart the box because we can no longer access the login page.

I actually remember the author of this room Tib3rius posting on twitter about this before, so searching Tib3rius's posts I managed to find it. https://twitter.com/0xTib3rius/status/1624819441044185088?ref_src=twsrc%5Etfw

![Twitter Post ](/img/lesson-learned/twitter.png#center "Tib3rius Twitter Post")


### Brute Force Username

Using hydra and the wordlist `xato-net-10-million-usernames.txt` we can brute force a valid username.

```sh
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -p asdf 10.10.248.178 http-post-form "/:username=^USER^&password=^PASS^:Invalid username and password." -f
```
![Hydra Brut Force](/img/lesson-learned/valid_name.png#center "Brute Force with Hydra")
Now we have a valid username we can try boolean method `martin' AND '1'='1'-- -`

![Boolean Method](/img/lesson-learned/valid_sql.png#center "Boolean SQL Injection Method")

We could also just comment out everything after the username with `martin'-- -` and this would also bypass login.

The SQL query would look like this.

```text
SELECT * FROM users WHERE username= 'martin''-- -' AND password = <hashed_password_input>
```
The password check `AND password = <hashed_password_input>` would be bypassed. This works because we were able to brute force a valid username.

![Comment Bypass](/img/lesson-learned/martin_bypass.png#center "Comment Out The Password")

### Flag Found

After entering the boolean SQL injection which would look like this in SQL `SELECT * FROM articles WHERE author = 'martin' AND '1'='1'-- -` we are able to bypass the login page and retrieve our flag.

![Login Bypassed](/img/lesson-learned/flag.png#center "Bypassed Login")

---

### Final Note

You can safely use `'OR 1=1-- -` all you want in a CTF environment but not in a real environment such as a bug bounty or a live production environment.

---


